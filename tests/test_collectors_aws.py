"""AWS collector against a fake boto3 session: dict-driven clients, no network, no Stubber."""
import copy
from datetime import datetime, timedelta, timezone

import boto3
import pytest
from botocore.exceptions import ClientError

from attest.audit import AuditLog
from attest.collectors import aws
from attest.collectors.registry import COLLECTORS, CollectContext, run_source
from attest.config import Config, SourceConfig, parse_config
from attest.evidence import EvidenceStore
from attest.sources import source_for_kind

NOW = datetime.now(timezone.utc)


def days_ago(n):
    return NOW - timedelta(days=n)


def denied(operation, code="AccessDeniedException"):
    return ClientError({"Error": {"Code": code, "Message": "not authorized"}}, operation)


def rule(name, status="COMPLIANT"):
    return {"ConfigRuleName": name, "Compliance": {"ComplianceType": status}}


class FakeClient:
    """Any method → look it up in the spec: a dict is returned, a callable gets the kwargs, an exception is raised."""

    def __init__(self, service, spec, calls):
        self.service, self.spec, self.calls = service, spec, calls

    def __getattr__(self, method):
        if method.startswith("_"):
            raise AttributeError(method)

        def call(**kwargs):
            self.calls.append((self.service, method, kwargs))
            if method not in self.spec:
                raise AssertionError(f"unexpected {self.service}.{method}({kwargs})")
            spec = self.spec[method]
            if isinstance(spec, Exception):
                raise spec
            return spec(kwargs) if callable(spec) else spec
        return call


class FakeSession:
    def __init__(self, services):
        self.services, self.calls = services, []

    def client(self, name, **kwargs):
        if name not in self.services:
            raise AssertionError(f"unexpected client {name!r}")
        return FakeClient(name, self.services[name], self.calls)

    def calls_to(self, service, method):
        return [kw for s, m, kw in self.calls if s == service and m == method]


def healthy():
    """Every service answering the way a well-run account would."""
    return copy.deepcopy({
        "config": {"describe_compliance_by_config_rule": {"ComplianceByConfigRules": [
            rule("encrypted-volumes"), rule("rds-storage-encrypted"), rule("cmk-backing-key-rotation-enabled"),
            rule("restricted-ssh"), rule("s3-bucket-public-read-prohibited"), rule("alb-waf-enabled"),
            rule("multi-region-cloudtrail-enabled"), rule("cloud-trail-log-file-validation-enabled"),
            rule("iam-password-policy"), rule("root-account-mfa-enabled"),      # 2 unmapped
        ]}},
        "iam": {
            "get_account_summary": {"SummaryMap": {"AccountAccessKeysPresent": 0, "AccountMFAEnabled": 1}},
            "list_users": {"Users": [{"UserName": "alice", "CreateDate": days_ago(400)}], "IsTruncated": False},
            "list_access_keys": {"AccessKeyMetadata": [{"AccessKeyId": "AKIAALICE0001", "Status": "Active", "CreateDate": days_ago(10)}]},
            "get_access_key_last_used": {"AccessKeyLastUsed": {}},
        },
        "accessanalyzer": {
            "list_analyzers": {"analyzers": [{"arn": "arn:aws:access-analyzer:us-east-1:1:analyzer/acct", "name": "acct", "status": "ACTIVE"}]},
            "list_findings": {"findings": []},
        },
        "cloudtrail": {
            "describe_trails": {"trailList": [{"Name": "org-trail", "TrailARN": "arn:aws:cloudtrail:us-east-1:1:trail/org-trail",
                                               "IsMultiRegionTrail": True, "LogFileValidationEnabled": True}]},
            "get_trail_status": {"IsLogging": True},
        },
        "guardduty": {"list_detectors": {"DetectorIds": ["det-1"]}, "list_findings": {"FindingIds": []}},
        "securityhub": {
            "get_enabled_standards": {"StandardsSubscriptions": [
                {"StandardsArn": "arn:aws:securityhub:us-east-1::standards/aws-foundational-security-best-practices/v/1.0.0"},
                {"StandardsArn": "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0"},
            ]},
            "get_findings": {"Findings": []},
        },
    })


@pytest.fixture
def ctx(tmp_path):
    store = EvidenceStore(tmp_path / "evidence.jsonl")
    audit = AuditLog(tmp_path / "audit.jsonl")
    src = SourceConfig(id="aws-prod", type="aws", params={"region": "us-east-1", "account_label": "prod"})
    return CollectContext(store=store, audit=audit, source=src, config=Config())


def run(ctx, services):
    session = FakeSession(services)
    result = aws.collect(ctx, session=session)
    by_kind = {}
    for record in ctx.store.all():
        by_kind.setdefault(record.kind, []).append(record)
    return result, {k: v[-1] for k, v in by_kind.items()}, session


# -- the whole account -----------------------------------------------------------------

def test_healthy_account_every_kind_passes(ctx):
    result, records, session = run(ctx, healthy())
    assert result.records == 14
    assert result.summary == "aws prod: 14 records; 2 config rules unmapped"
    assert set(records) == set(aws.KINDS)
    assert all(r.payload["result"] == "pass" for r in ctx.store.all())
    # each record lands on the catalog source that owns the kind, with attest's derived control ids
    for record in ctx.store.all():
        assert record.source == source_for_kind(record.kind).id
        assert record.payload["region"] == "us-east-1" and record.payload["account"] == "prod"
        assert record.payload["collected_by"] == "aws-prod" and isinstance(record.payload["raw"], dict)
    assert records["storage.encrypted"].source == "aws-config" and records["storage.encrypted"].control_ids == ["CTL-CRYPTO-01"]
    assert records["iam.key-age"].source == "aws-iam" and records["iam.key-age"].control_ids == ["CTL-ACCESS-03"]
    assert records["cloudtrail.enabled"].source == "cloudtrail" and records["guardduty.findings"].source == "guardduty"
    assert records["storage.encrypted"].payload["summary"] == "2 rules compliant (encrypted-volumes, rds-storage-encrypted); 0 non-compliant"
    assert records["iam.key-age"].classification == "internal" and records["iam.access-analyzer"].classification == "internal"
    assert records["securityhub.score"].payload["summary"] == "0 failed findings across 2 standards"
    assert records["securityhub.score"].payload["raw"]["standards"] == ["aws-foundational-security-best-practices/v/1.0.0", "cis-aws-foundations-benchmark/v/1.2.0"]
    assert not session.calls_to("sts", "assume_role")
    # the Config-rule view and the trail view of cloudtrail.enabled were both written (the catalog owner of the
    # kind is 'cloudtrail', so both carry that source); the direct trail check is newest and wins in the engine
    both = ctx.store.query(kind="cloudtrail.enabled")
    assert [r.source for r in both] == ["cloudtrail", "cloudtrail"]
    assert "rules" in both[0].payload["raw"] and "trails" in both[1].payload["raw"]


def test_region_is_required_and_label_defaults_to_region(ctx):
    ctx.source.params = {}
    with pytest.raises(ValueError, match="needs params.region"):
        aws.collect(ctx, session=FakeSession(healthy()))
    ctx.source.params = {"region": "eu-west-1"}
    result, records, _ = run(ctx, healthy())
    assert result.summary.startswith("aws eu-west-1: 14 records")
    assert "account" not in records["iam.root-usage"].payload


# -- AWS Config ------------------------------------------------------------------------

def test_config_rules_fail_paginate_and_ignore_not_applicable(ctx):
    services = healthy()
    pages = {
        None: {"ComplianceByConfigRules": [rule("securityhub-encrypted-volumes-a1b2c3", "NON_COMPLIANT"), rule("rds-storage-encrypted"),
                                            rule("s3-default-encryption-kms", "NOT_APPLICABLE")], "NextToken": "p2"},
        "p2": {"ComplianceByConfigRules": [rule("cmk-backing-key-rotation-enabled", "INSUFFICIENT_DATA"),
                                           rule("restricted-ssh"), rule("restricted-common-ports"), rule("custom-tagging-rule")]},
    }
    services["config"]["describe_compliance_by_config_rule"] = lambda kw: pages[kw.get("NextToken")]
    result, records, session = run(ctx, services)
    assert result.summary.endswith("1 config rules unmapped")
    assert [kw.get("NextToken") for kw in session.calls_to("config", "describe_compliance_by_config_rule")] == [None, "p2"]
    enc = records["storage.encrypted"].payload
    assert enc["result"] == "fail"
    assert enc["summary"] == "1 rule compliant (rds-storage-encrypted); 1 non-compliant (securityhub-encrypted-volumes-a1b2c3)"
    assert enc["raw"]["rules"] == {"securityhub-encrypted-volumes-a1b2c3": "NON_COMPLIANT", "rds-storage-encrypted": "COMPLIANT"}
    kms = records["kms.key.rotation"].payload
    assert kms["result"] == "fail" and "1 insufficient data (cmk-backing-key-rotation-enabled)" in kms["summary"]
    assert records["sg.no-open-ingress"].payload["result"] == "pass"
    # no mapped rule at all → nothing emitted from Config for these (CloudTrail still emits its two)
    for kind in ("waf.enabled", "s3.public-access-blocked"):
        assert kind not in records
    assert [r.source for r in ctx.store.query(kind="cloudtrail.enabled")] == ["cloudtrail"]


def test_kind_for_rule_matches_prefixed_names_only_within_the_map():
    assert aws.kind_for_rule("securityhub-restricted-ssh-9f8e7d") == "sg.no-open-ingress"
    assert aws.kind_for_rule("multi-region-cloudtrail-enabled") == "cloudtrail.enabled"
    assert aws.kind_for_rule("iam-password-policy") is None
    for kind in aws.CONFIG_RULE_KINDS:
        assert source_for_kind(kind) is not None


# -- IAM -------------------------------------------------------------------------------

def test_root_usage_and_key_age_fail_with_offenders_listed(ctx):
    services = healthy()
    services["iam"]["get_account_summary"] = {"SummaryMap": {"AccountAccessKeysPresent": 1, "AccountMFAEnabled": 0}}
    user_pages = {
        None: {"Users": [{"UserName": "alice"}, {"UserName": "bob"}], "IsTruncated": True, "Marker": "m2"},
        "m2": {"Users": [{"UserName": "carol"}], "IsTruncated": False},
    }
    services["iam"]["list_users"] = lambda kw: user_pages[kw.get("Marker")]
    keys = {
        "alice": [{"AccessKeyId": "AKIAALICE0001", "Status": "Active", "CreateDate": days_ago(120)}],
        "bob": [{"AccessKeyId": "AKIABOB000002", "Status": "Inactive", "CreateDate": days_ago(400)}],   # inactive: ignored
        "carol": [{"AccessKeyId": "AKIACAROL0003", "Status": "Active", "CreateDate": days_ago(30).isoformat()}],
    }
    services["iam"]["list_access_keys"] = lambda kw: {"AccessKeyMetadata": keys[kw["UserName"]]}
    services["iam"]["get_access_key_last_used"] = {"AccessKeyLastUsed": {"LastUsedDate": days_ago(3), "ServiceName": "s3"}}
    _, records, session = run(ctx, services)
    root = records["iam.root-usage"].payload
    assert root["result"] == "fail"
    assert root["summary"] == "MFA not enabled on the root account; 1 access key present on the root account"
    age = records["iam.key-age"].payload
    assert age["result"] == "fail"
    assert age["summary"] == "1 active access key older than 90 days (alice (120 days))"
    assert age["offending_users"] == [{"user": "alice", "access_key": "…0001", "age_days": 120,
                                       "last_used": days_ago(3).strftime("%Y-%m-%dT%H:%M:%SZ"), "last_used_service": "s3"}]
    assert age["raw"] == {"users": 3, "active_keys": 2, "stale_keys": 1, "max_age_days": 90}
    assert [kw["UserName"] for kw in session.calls_to("iam", "list_access_keys")] == ["alice", "bob", "carol"]
    assert session.calls_to("iam", "get_access_key_last_used") == [{"AccessKeyId": "AKIAALICE0001"}]


def test_key_age_threshold_is_a_param(ctx):
    services = healthy()   # alice's key is 10 days old
    ctx.source.params["max_key_age_days"] = 7
    _, records, _ = run(ctx, services)
    assert records["iam.key-age"].payload["result"] == "fail" and "older than 7 days" in records["iam.key-age"].payload["summary"]


# -- Access Analyzer -------------------------------------------------------------------

def test_access_analyzer_missing_disabled_or_with_findings(ctx):
    services = healthy()
    services["accessanalyzer"]["list_analyzers"] = {"analyzers": []}
    _, records, _ = run(ctx, services)
    assert records["iam.access-analyzer"].payload == {**records["iam.access-analyzer"].payload, "result": "fail",
                                                      "summary": "no analyzer enabled in us-east-1"}

    services["accessanalyzer"]["list_analyzers"] = {"analyzers": [{"arn": "arn:x", "name": "old", "status": "DISABLED"}]}
    _, records, _ = run(ctx, services)
    assert records["iam.access-analyzer"].payload["result"] == "fail"

    services = healthy()
    services["accessanalyzer"]["list_findings"] = {"findings": [{"id": "f1"}, {"id": "f2"}]}
    _, records, session = run(ctx, services)
    finding = records["iam.access-analyzer"].payload
    assert finding["result"] == "fail" and finding["summary"] == "2 active findings on 1 analyzer (acct)"
    assert finding["raw"] == {"analyzers": 1, "active_findings": 2, "per_analyzer": {"acct": 2}}
    assert session.calls_to("accessanalyzer", "list_findings") == [
        {"analyzerArn": "arn:aws:access-analyzer:us-east-1:1:analyzer/acct", "filter": {"status": {"eq": ["ACTIVE"]}}}]


# -- CloudTrail ------------------------------------------------------------------------

def test_cloudtrail_needs_a_logging_multi_region_trail_with_validation(ctx):
    services = healthy()
    services["cloudtrail"]["describe_trails"] = {"trailList": [{"Name": "regional", "TrailARN": "arn:r", "IsMultiRegionTrail": False}]}
    _, records, session = run(ctx, services)
    assert records["cloudtrail.enabled"].payload["summary"] == "CloudTrail: none of 1 trail is multi-region and logging"
    assert records["cloudtrail.enabled"].payload["result"] == "fail" and records["log.integrity"].payload["result"] == "fail"
    assert not session.calls_to("cloudtrail", "get_trail_status")   # single-region trails are not even asked

    services["cloudtrail"]["describe_trails"] = {"trailList": [{"Name": "org", "TrailARN": "arn:o", "IsMultiRegionTrail": True, "LogFileValidationEnabled": False}]}
    services["cloudtrail"]["get_trail_status"] = {"IsLogging": False}
    _, records, _ = run(ctx, services)
    assert records["cloudtrail.enabled"].payload["result"] == "fail"

    services["cloudtrail"]["get_trail_status"] = {"IsLogging": True}
    _, records, session = run(ctx, services)
    assert records["cloudtrail.enabled"].payload == {**records["cloudtrail.enabled"].payload, "result": "pass",
                                                     "summary": "CloudTrail: 1 multi-region trail logging (org)"}
    assert records["log.integrity"].payload["result"] == "fail"
    assert records["log.integrity"].payload["summary"] == "CloudTrail: log-file validation disabled (org)"
    assert session.calls_to("cloudtrail", "get_trail_status") == [{"Name": "arn:o"}]


# -- GuardDuty + Security Hub ----------------------------------------------------------

def test_guardduty_not_enabled_or_with_high_severity_findings(ctx):
    services = healthy()
    services["guardduty"]["list_detectors"] = {"DetectorIds": []}
    _, records, _ = run(ctx, services)
    assert records["guardduty.findings"].payload["result"] == "fail"
    assert records["guardduty.findings"].payload["summary"] == "GuardDuty not enabled in this region"

    services = healthy()
    services["guardduty"]["list_findings"] = {"FindingIds": ["a", "b", "c"]}
    _, records, session = run(ctx, services)
    assert records["guardduty.findings"].payload["result"] == "fail"
    assert records["guardduty.findings"].payload["summary"] == "GuardDuty: 3 unarchived findings with severity >= 7"
    assert session.calls_to("guardduty", "list_findings") == [{"DetectorId": "det-1", "FindingCriteria": {
        "Criterion": {"severity": {"Gte": 7}, "service.archived": {"Eq": ["false"]}}}}]


def test_securityhub_skipped_when_not_enabled_and_fails_on_failed_findings(ctx, monkeypatch):
    services = healthy()
    services["securityhub"]["get_enabled_standards"] = {"StandardsSubscriptions": []}
    result, records, _ = run(ctx, services)
    assert "securityhub.score" not in records and result.records == 13

    services["securityhub"]["get_enabled_standards"] = denied("GetEnabledStandards", code="InvalidAccessException")
    result, records, _ = run(ctx, services)
    assert "securityhub.score" not in records and result.records == 13

    services = healthy()
    monkeypatch.setattr(aws, "SECURITYHUB_MAX_PAGES", 2)
    pages = {None: {"Findings": [{"Id": "1"}, {"Id": "2"}], "NextToken": "n2"}, "n2": {"Findings": [{"Id": "3"}], "NextToken": "n3"}}
    services["securityhub"]["get_findings"] = lambda kw: pages[kw.get("NextToken")]
    _, records, session = run(ctx, services)
    score = records["securityhub.score"].payload
    assert score["result"] == "fail" and score["summary"] == "3+ failed findings across 2 standards"
    assert score["raw"]["failed"] == 3 and score["raw"]["truncated"] is True
    first = session.calls_to("securityhub", "get_findings")[0]
    assert first["MaxResults"] == 100 and first["Filters"] == {
        "ComplianceStatus": [{"Value": "FAILED", "Comparison": "EQUALS"}],
        "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
        "WorkflowStatus": [{"Value": "NEW", "Comparison": "EQUALS"}]}


# -- credentials and errors ------------------------------------------------------------

def test_access_denied_becomes_a_permission_error_naming_the_api(ctx):
    services = healthy()
    services["iam"]["list_users"] = denied("ListUsers", code="AccessDenied")
    with pytest.raises(PermissionError) as exc:
        aws.collect(ctx, session=FakeSession(services))
    message = str(exc.value)
    assert "iam:ListUsers denied (AccessDenied)" in message and "iam:GetAccountSummary, iam:ListUsers" in message
    # Config and GetAccountSummary had already written their records; nothing after the refusal ran
    kinds = {r.kind for r in ctx.store.all()}
    assert "iam.root-usage" in kinds and "storage.encrypted" in kinds
    assert not kinds & {"iam.key-age", "iam.access-analyzer", "guardduty.findings", "securityhub.score"}

    services["iam"]["list_users"] = denied("ListUsers", code="Throttling")
    with pytest.raises(ClientError):
        aws.collect(ctx, session=FakeSession(services))


def test_role_arn_assumes_the_role_from_the_ambient_session(ctx, monkeypatch):
    services = healthy()
    services["sts"] = {"assume_role": {"Credentials": {"AccessKeyId": "ASIA1", "SecretAccessKey": "s", "SessionToken": "t"}}}
    ambient, assumed = FakeSession(services), FakeSession(healthy())
    created = []

    def fake_session(**kwargs):
        created.append(kwargs)
        return assumed
    monkeypatch.setattr(boto3, "Session", fake_session)
    ctx.source.params["role_arn"] = "arn:aws:iam::123456789012:role/attest-readonly"
    result = aws.collect(ctx, session=ambient)
    assert result.records == 14
    assert ambient.calls == [("sts", "assume_role", {"RoleArn": "arn:aws:iam::123456789012:role/attest-readonly", "RoleSessionName": "attest"})]
    assert created == [{"aws_access_key_id": "ASIA1", "aws_secret_access_key": "s", "aws_session_token": "t", "region_name": "us-east-1"}]
    assert len(assumed.calls) > 10   # everything else went through the assumed-role session


def test_assume_role_denied_names_sts(ctx):
    services = healthy()
    services["sts"] = {"assume_role": denied("AssumeRole", code="AccessDenied")}
    ctx.source.params["role_arn"] = "arn:aws:iam::1:role/x"
    with pytest.raises(PermissionError, match="sts:AssumeRole"):
        aws.collect(ctx, session=FakeSession(services))


def test_registry_runs_the_collector_by_type(tmp_path, monkeypatch):
    config = parse_config('[sources.cloud]\ntype = "aws"\n[sources.cloud.params]\nregion = "us-east-1"\n', path=tmp_path / "attest.toml")
    monkeypatch.setattr(aws, "_ambient_session", lambda region: FakeSession(healthy()))
    store, audit = EvidenceStore(tmp_path / "e.jsonl"), AuditLog(tmp_path / "a.jsonl")
    assert "aws" in COLLECTORS
    out = run_source(config, "cloud", store, audit)
    assert out["status"] == "ok" and out["records"] == 14 and out["summary"].startswith("aws us-east-1: 14 records")
    assert audit.all()[-1].actor == "collector:aws"


def test_describe_lists_params_and_catalog_kinds():
    info = aws.describe()
    assert info["type"] == aws.TYPE == "aws"
    assert set(info["params"]) == {"region", "role_arn", "account_label", "max_key_age_days"}
    assert info["kinds"] == list(aws.KINDS) and all(source_for_kind(k) is not None for k in info["kinds"])
    assert set(info["actions"]) == {"sts", "config", "iam", "accessanalyzer", "cloudtrail", "guardduty", "securityhub"}

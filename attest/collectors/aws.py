"""AWS collector: Config, IAM, Access Analyzer, CloudTrail, GuardDuty and Security Hub → evidence.

One ``collect()`` walks six read-only APIs in the configured region and appends one record per
evidence kind it can prove or disprove. Every client comes from ``session.client(name)`` — nothing
else — so tests inject a fake session and never touch the network. An ``AccessDenied`` from any
API becomes a ``PermissionError`` that names the call and the read-only actions the role is missing.

Kinds emitted (all in ``attest/sources.py``):

* ``aws-config``  storage.encrypted, kms.key.rotation, sg.no-open-ingress, s3.public-access-blocked,
                  waf.enabled, cloudtrail.enabled, log.integrity — from Config-rule compliance
* ``aws-iam``     iam.root-usage, iam.key-age, iam.access-analyzer
* ``cloudtrail``  cloudtrail.enabled, log.integrity — re-checked from the trails themselves
* ``guardduty``   guardduty.findings, securityhub.score
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from attest.collectors.base import emit

if TYPE_CHECKING:  # the registry imports collectors, so the runtime import lives inside collect()
    from attest.collectors.registry import CollectContext, CollectResult

TYPE = "aws"
SESSION_NAME = "attest"
KEY_MAX_AGE_DAYS = 90
GUARDDUTY_MIN_SEVERITY = 7
SECURITYHUB_PAGE = 100
SECURITYHUB_MAX_PAGES = 10      # 1,000 failed findings is enough to know the answer

# AWS Config managed-rule identifiers → the evidence kind they prove. Rules deployed by Security Hub
# or a conformance pack carry a prefix/suffix (securityhub-encrypted-volumes-a1b2c3), so a rule is
# recognised when the identifier appears anywhere in its name.
CONFIG_RULE_KINDS: dict[str, tuple[str, ...]] = {
    "storage.encrypted": ("s3-bucket-server-side-encryption-enabled", "encrypted-volumes",
                          "rds-storage-encrypted", "s3-default-encryption-kms"),
    "kms.key.rotation": ("cmk-backing-key-rotation-enabled",),
    "sg.no-open-ingress": ("restricted-ssh", "restricted-common-ports", "vpc-default-security-group-closed"),
    "s3.public-access-blocked": ("s3-account-level-public-access-blocks-periodic", "s3-bucket-public-read-prohibited"),
    "waf.enabled": ("alb-waf-enabled", "api-gw-associated-with-waf"),
    "cloudtrail.enabled": ("cloudtrail-enabled", "multi-region-cloudtrail-enabled"),
    "log.integrity": ("cloud-trail-log-file-validation-enabled",),
}

# What the read-only role must allow, per service — quoted in PermissionError messages and the docs.
POLICY_ACTIONS: dict[str, str] = {
    "sts": "sts:AssumeRole on params.role_arn",
    "config": "config:DescribeComplianceByConfigRule",
    "iam": "iam:GetAccountSummary, iam:ListUsers, iam:ListAccessKeys, iam:GetAccessKeyLastUsed",
    "accessanalyzer": "access-analyzer:ListAnalyzers, access-analyzer:ListFindings",
    "cloudtrail": "cloudtrail:DescribeTrails, cloudtrail:GetTrailStatus",
    "guardduty": "guardduty:ListDetectors, guardduty:ListFindings",
    "securityhub": "securityhub:GetEnabledStandards, securityhub:GetFindings",
}

KINDS = ("storage.encrypted", "kms.key.rotation", "sg.no-open-ingress", "s3.public-access-blocked", "waf.enabled",
         "cloudtrail.enabled", "log.integrity", "iam.root-usage", "iam.key-age", "iam.access-analyzer",
         "guardduty.findings", "securityhub.score")

_DENIED_MARKERS = ("accessdenied", "unauthorized", "forbidden", "authorizationerror")
_NOT_ENABLED = ("InvalidAccessException", "ResourceNotFoundException")


# -- small helpers -----------------------------------------------------------------

def _error_code(exc: BaseException) -> str:
    """The AWS error code of a botocore ClientError (duck-typed: no botocore import needed here)."""
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        return str((response.get("Error") or {}).get("Code") or "")
    return ""


def _camel(method: str) -> str:
    return "".join(part.capitalize() for part in method.split("_"))


def _call(client, service: str, method: str, **kwargs) -> dict:
    """Invoke one API. AccessDenied → PermissionError naming the call and the actions to grant."""
    try:
        return getattr(client, method)(**kwargs)
    except Exception as exc:  # noqa: BLE001 - only a ClientError carries .response; anything else re-raises
        code = _error_code(exc)
        if code and any(marker in code.lower() for marker in _DENIED_MARKERS):
            raise PermissionError(
                f"AWS {service}:{_camel(method)} denied ({code}): the collector's role needs a read-only "
                f"policy allowing {POLICY_ACTIONS.get(service, service + ':*')}"
            ) from exc
        raise


def _paginate(client, service: str, method: str, items_key: str, *, token_in: str = "NextToken",
              token_out: str = "NextToken", max_pages: int | None = None, **kwargs) -> tuple[list, bool]:
    """Follow NextToken/nextToken pages; returns (items, truncated_by_max_pages)."""
    items: list = []
    token, pages = None, 0
    while True:
        args = dict(kwargs)
        if token:
            args[token_in] = token
        page = _call(client, service, method, **args)
        items.extend(page.get(items_key) or [])
        token = page.get(token_out)
        pages += 1
        if not token:
            return items, False
        if max_pages is not None and pages >= max_pages:
            return items, True


def _dt(value: Any) -> datetime:
    """boto3 hands back aware datetimes; fakes may hand back naive ones or ISO strings."""
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, str) and value:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    return datetime.now(timezone.utc)


def _iso(value: Any) -> str | None:
    if value is None:
        return None
    return _dt(value).strftime("%Y-%m-%dT%H:%M:%SZ")


def _n(count: int, noun: str) -> str:
    return f"{count} {noun}{'' if count == 1 else 's'}"


def _names(names: list[str], limit: int = 3) -> str:
    if not names:
        return ""
    shown = ", ".join(names[:limit]) + (", …" if len(names) > limit else "")
    return f" ({shown})"


def _mask(key_id: str) -> str:
    return f"…{key_id[-4:]}" if key_id else ""


def _standard_name(subscription: dict) -> str:
    arn = subscription.get("StandardsArn") or ""
    tail = arn.rsplit(":", 1)[-1]
    for prefix in ("standards/", "ruleset/"):
        if tail.startswith(prefix):
            return tail[len(prefix):]
    return tail or "?"


class _Emitter:
    """emit() with the per-run extras (region, account) filled in and a record counter."""

    def __init__(self, ctx, common: dict):
        self.ctx, self.common, self.count = ctx, common, 0

    def __call__(self, kind: str, summary: str, result: str, classification: str = "publishable", **extra):
        emit(self.ctx, kind=kind, summary=summary, result=result, classification=classification, **self.common, **extra)
        self.count += 1


# -- sessions ----------------------------------------------------------------------

def _ambient_session(region: str):
    try:
        import boto3
    except ImportError as exc:  # pragma: no cover - boto3 is an optional extra
        raise RuntimeError("the aws collector needs boto3: pip install 'attest[aws]'") from exc
    return boto3.Session(region_name=region)


def _assumed_session(base, role_arn: str, region: str):
    """sts:AssumeRole from the ambient credentials into the read-only collector role."""
    import boto3
    creds = _call(base.client("sts"), "sts", "assume_role", RoleArn=role_arn, RoleSessionName=SESSION_NAME)["Credentials"]
    return boto3.Session(aws_access_key_id=creds["AccessKeyId"], aws_secret_access_key=creds["SecretAccessKey"],
                         aws_session_token=creds["SessionToken"], region_name=region)


# -- AWS Config --------------------------------------------------------------------

def kind_for_rule(rule_name: str) -> str | None:
    lower = (rule_name or "").lower()
    for kind, identifiers in CONFIG_RULE_KINDS.items():
        if any(identifier in lower for identifier in identifiers):
            return kind
    return None


def _collect_config(session, out: _Emitter) -> int:
    """One record per kind with at least one mapped rule; returns the number of unmapped rules."""
    client = session.client("config")
    rules, _ = _paginate(client, "config", "describe_compliance_by_config_rule", "ComplianceByConfigRules")
    by_kind: dict[str, dict[str, str]] = {}
    unmapped = 0
    for rule in rules:
        name = rule.get("ConfigRuleName") or ""
        kind = kind_for_rule(name)
        if kind is None:
            unmapped += 1
            continue
        status = (rule.get("Compliance") or {}).get("ComplianceType") or "INSUFFICIENT_DATA"
        if status == "NOT_APPLICABLE":
            continue  # no resources of that type in the region: proves nothing either way
        by_kind.setdefault(kind, {})[name] = status
    for kind in CONFIG_RULE_KINDS:
        statuses = by_kind.get(kind)
        if not statuses:
            continue
        ok = sorted(n for n, s in statuses.items() if s == "COMPLIANT")
        bad = sorted(n for n, s in statuses.items() if s == "NON_COMPLIANT")
        pending = sorted(n for n, s in statuses.items() if s not in ("COMPLIANT", "NON_COMPLIANT"))
        summary = f"{_n(len(ok), 'rule')} compliant{_names(ok)}; {len(bad)} non-compliant{_names(bad)}"
        if pending:
            summary += f"; {len(pending)} insufficient data{_names(pending)}"
        out(kind, summary, "fail" if bad or not ok else "pass",
            raw={"compliant": len(ok), "non_compliant": len(bad), "insufficient_data": len(pending), "rules": statuses})
    return unmapped


# -- IAM ---------------------------------------------------------------------------

def _iam_users(iam) -> list[dict]:
    users: list[dict] = []
    marker = None
    while True:
        page = _call(iam, "iam", "list_users", **({"Marker": marker} if marker else {}))
        users.extend(page.get("Users") or [])
        marker = page.get("Marker")
        if not page.get("IsTruncated") or not marker:
            return users


def _collect_iam(session, out: _Emitter, max_age_days: int) -> None:
    iam = session.client("iam")
    summary_map = _call(iam, "iam", "get_account_summary").get("SummaryMap") or {}
    root_keys = int(summary_map.get("AccountAccessKeysPresent", 0) or 0)
    root_mfa = int(summary_map.get("AccountMFAEnabled", 0) or 0)
    problems = []
    if root_mfa == 0:
        problems.append("MFA not enabled on the root account")
    if root_keys > 0:
        problems.append(f"{_n(root_keys, 'access key')} present on the root account")
    out("iam.root-usage", "; ".join(problems) if problems else "root account: MFA enabled, no access keys",
        "fail" if problems else "pass", raw={"AccountMFAEnabled": root_mfa, "AccountAccessKeysPresent": root_keys})

    users = _iam_users(iam)
    now = datetime.now(timezone.utc)
    active_keys, stale = 0, []
    for user in users:
        name = user.get("UserName") or ""
        for key in _call(iam, "iam", "list_access_keys", UserName=name).get("AccessKeyMetadata") or []:
            if key.get("Status") != "Active":
                continue
            active_keys += 1
            age = (now - _dt(key.get("CreateDate"))).days
            if age <= max_age_days:
                continue
            last = _call(iam, "iam", "get_access_key_last_used", AccessKeyId=key["AccessKeyId"]).get("AccessKeyLastUsed") or {}
            stale.append({"user": name, "access_key": _mask(key["AccessKeyId"]), "age_days": age,
                          "last_used": _iso(last.get("LastUsedDate")), "last_used_service": last.get("ServiceName")})
    stale.sort(key=lambda s: -s["age_days"])
    if stale:
        who = [f"{s['user']} ({s['age_days']} days)" for s in stale]
        summary = f"{_n(len(stale), 'active access key')} older than {max_age_days} days{_names(who)}"
    else:
        summary = f"0 of {_n(active_keys, 'active access key')} older than {max_age_days} days"
    out("iam.key-age", summary, "fail" if stale else "pass", classification="internal",
        raw={"users": len(users), "active_keys": active_keys, "stale_keys": len(stale), "max_age_days": max_age_days},
        offending_users=stale)


# -- IAM Access Analyzer -----------------------------------------------------------

def _collect_access_analyzer(session, out: _Emitter, region: str) -> None:
    client = session.client("accessanalyzer")
    analyzers, _ = _paginate(client, "accessanalyzer", "list_analyzers", "analyzers", token_in="nextToken", token_out="nextToken")
    active = [a for a in analyzers if (a.get("status") or "ACTIVE") == "ACTIVE"]
    if not active:
        out("iam.access-analyzer", f"no analyzer enabled in {region}", "fail", classification="internal",
            raw={"analyzers": len(analyzers), "active_findings": 0})
        return
    per_analyzer: dict[str, int] = {}
    for analyzer in active:
        findings, _ = _paginate(client, "accessanalyzer", "list_findings", "findings", token_in="nextToken", token_out="nextToken",
                                analyzerArn=analyzer["arn"], filter={"status": {"eq": ["ACTIVE"]}})
        per_analyzer[analyzer.get("name") or analyzer["arn"]] = len(findings)
    total = sum(per_analyzer.values())
    out("iam.access-analyzer", f"{_n(total, 'active finding')} on {_n(len(active), 'analyzer')}{_names(list(per_analyzer))}",
        "fail" if total else "pass", classification="internal",
        raw={"analyzers": len(active), "active_findings": total, "per_analyzer": per_analyzer})


# -- CloudTrail --------------------------------------------------------------------

def _collect_cloudtrail(session, out: _Emitter) -> None:
    client = session.client("cloudtrail")
    trails = _call(client, "cloudtrail", "describe_trails").get("trailList") or []
    logging = []
    for trail in trails:
        if not trail.get("IsMultiRegionTrail"):
            continue
        status = _call(client, "cloudtrail", "get_trail_status", Name=trail.get("TrailARN") or trail.get("Name"))
        if status.get("IsLogging"):
            logging.append(trail)
    raw = {"trails": len(trails), "multi_region_logging": len(logging)}
    if not logging:
        why = "no trails" if not trails else f"none of {_n(len(trails), 'trail')} is multi-region and logging"
        out("cloudtrail.enabled", f"CloudTrail: {why}", "fail", raw=raw)
        out("log.integrity", f"CloudTrail: no multi-region logging trail to validate ({why})", "fail", raw=raw)
        return
    names = [t.get("Name") or t.get("TrailARN") for t in logging]
    out("cloudtrail.enabled", f"CloudTrail: {_n(len(logging), 'multi-region trail')} logging{_names(names)}", "pass", raw=raw)
    validated = [t.get("Name") or t.get("TrailARN") for t in logging if t.get("LogFileValidationEnabled")]
    raw = {**raw, "validated": len(validated)}
    if validated:
        out("log.integrity", f"CloudTrail: log-file validation enabled{_names(validated)}", "pass", raw=raw)
    else:
        out("log.integrity", f"CloudTrail: log-file validation disabled{_names(names)}", "fail", raw=raw)


# -- GuardDuty + Security Hub ------------------------------------------------------

def _collect_guardduty(session, out: _Emitter) -> None:
    client = session.client("guardduty")
    detectors, _ = _paginate(client, "guardduty", "list_detectors", "DetectorIds")
    if not detectors:
        out("guardduty.findings", "GuardDuty not enabled in this region", "fail", raw={"detectors": 0, "findings": 0})
        return
    criteria = {"Criterion": {"severity": {"Gte": GUARDDUTY_MIN_SEVERITY}, "service.archived": {"Eq": ["false"]}}}
    total = 0
    for detector in detectors:
        ids, _ = _paginate(client, "guardduty", "list_findings", "FindingIds", DetectorId=detector, FindingCriteria=criteria)
        total += len(ids)
    out("guardduty.findings", f"GuardDuty: {_n(total, 'unarchived finding')} with severity >= {GUARDDUTY_MIN_SEVERITY}",
        "fail" if total else "pass", raw={"detectors": len(detectors), "findings": total, "min_severity": GUARDDUTY_MIN_SEVERITY})


def _collect_securityhub(session, out: _Emitter) -> None:
    client = session.client("securityhub")
    try:
        standards, _ = _paginate(client, "securityhub", "get_enabled_standards", "StandardsSubscriptions")
    except Exception as exc:  # noqa: BLE001 - PermissionError has no code and re-raises below
        if _error_code(exc) in _NOT_ENABLED:
            return  # Security Hub is not enabled here: nothing to score
        raise
    if not standards:
        return
    filters = {"ComplianceStatus": [{"Value": "FAILED", "Comparison": "EQUALS"}],
               "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
               "WorkflowStatus": [{"Value": "NEW", "Comparison": "EQUALS"}]}
    findings, truncated = _paginate(client, "securityhub", "get_findings", "Findings", max_pages=SECURITYHUB_MAX_PAGES,
                                    Filters=filters, MaxResults=SECURITYHUB_PAGE)
    failed = len(findings)
    count = f"{failed}+" if truncated else str(failed)
    out("securityhub.score", f"{count} failed findings across {_n(len(standards), 'standard')}", "fail" if failed else "pass",
        raw={"failed": failed, "truncated": truncated, "standards": [_standard_name(s) for s in standards]})


# -- entry points ------------------------------------------------------------------

def collect(ctx: CollectContext, session=None) -> CollectResult:
    """type = "aws": read six AWS services in params.region and append one record per provable kind."""
    from attest.collectors.registry import CollectResult

    params = ctx.source.params
    region = params.get("region")
    if not region:
        raise ValueError(f"source '{ctx.source.id}' ({TYPE}) needs params.region")
    role_arn = params.get("role_arn") or None
    account_label = params.get("account_label") or None
    max_age_days = int(params.get("max_key_age_days", KEY_MAX_AGE_DAYS))

    session = session or _ambient_session(region)
    if role_arn:
        session = _assumed_session(session, role_arn, region)

    common = {"region": region}
    if account_label:
        common["account"] = account_label
    out = _Emitter(ctx, common)
    unmapped = _collect_config(session, out)
    _collect_iam(session, out, max_age_days)
    _collect_access_analyzer(session, out, region)
    _collect_cloudtrail(session, out)
    _collect_guardduty(session, out)
    _collect_securityhub(session, out)
    return CollectResult(records=out.count,
                         summary=f"aws {account_label or region}: {out.count} records; {unmapped} config rules unmapped")


def describe() -> dict:
    return {
        "type": TYPE,
        "params": {
            "region": "AWS region to read (required)",
            "role_arn": "optional: sts:AssumeRole into this read-only role from the ambient credentials (session name 'attest')",
            "account_label": "optional: name used in summaries instead of the region",
            "max_key_age_days": f"optional: IAM access keys older than this fail iam.key-age (default {KEY_MAX_AGE_DAYS})",
        },
        "credentials": "ambient boto3 credentials (environment, profile or instance role); never a key in the config file",
        "kinds": list(KINDS),
        "config_rules": {kind: list(rules) for kind, rules in CONFIG_RULE_KINDS.items()},
        "actions": dict(POLICY_ACTIONS),
    }

"""Representative seed data. One evidence gap (missing BAAs) fails three frameworks."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from attest.audit import AuditLog
from attest.evidence import EvidenceStore

# (control_id, kind, source, classification, age_hours, summary, result)
SEED = [
    ("CTL-ACCESS-01", "iam.least-privilege", "aws-iam", "publishable", 2, "0 IAM principals with wildcard actions; SCP denies root usage", "pass"),
    ("CTL-ACCESS-01", "sso.enforced", "okta", "publishable", 2, "SSO + MFA enforced for 100% of workforce accounts", "pass"),
    ("CTL-PRIV-01", "access-review.quarterly", "access-review", "publishable", 41 * 24, "Q2 privileged access review signed by 14 resource owners", "pass"),
    ("CTL-CRYPTO-01", "kms.key.rotation", "aws-config", "publishable", 2, "AES-256 under customer-scoped KMS keys; annual rotation enforced by policy", "pass"),
    ("CTL-CRYPTO-01", "storage.encrypted", "aws-config", "publishable", 2, "All S3, EBS and RDS resources report encryption enabled", "pass"),
    ("CTL-CRYPTO-02", "tls.policy", "cloudtrail", "publishable", 3, "TLS 1.2+ enforced at all load balancers; TLS 1.0/1.1 rejected", "pass"),
    ("CTL-LOG-01", "cloudtrail.enabled", "cloudtrail", "publishable", 1, "Org-wide CloudTrail on, multi-region, to a locked bucket", "pass"),
    ("CTL-LOG-01", "log.integrity", "cloudtrail", "publishable", 1, "Log file validation enabled; digest chain verified", "pass"),
    ("CTL-CHANGE-01", "pr.review-required", "github", "publishable", 9 * 24, "Branch protection: 1 approving review required on all default branches", "pass"),
    ("CTL-CHANGE-01", "ci.policy-gate", "ci-cd", "publishable", 9 * 24, "OPA, tfsec and Checkov gates block merges on policy failure", "pass"),
    ("CTL-VENDOR-01", "baa.executed", "vendor-registry", "internal", 24, "2 of 11 subprocessors processing ePHI lack an executed BAA", "fail"),
    ("CTL-RISK-01", "risk.assessment", "grc", "internal", 12 * 24, "Annual risk analysis completed and approved by CISO", "pass"),
    ("CTL-MON-01", "siem.alerting", "siem", "publishable", 1, "Detection rules active; anomaly alerts routed to on-call", "pass"),
    ("CTL-NET-01", "sg.no-open-ingress", "aws-config", "publishable", 6, "No security group allows 0.0.0.0/0 on admin ports", "pass"),
    ("CTL-NET-01", "waf.enabled", "aws-config", "publishable", 6, "WAF attached to every public-facing ALB", "pass"),
    # Restricted: exists in the store, must never be citable in a customer-facing answer.
    ("CTL-CRYPTO-01", "finding.open", "finding-tracker", "restricted", 9, "Open finding F-231: staging KMS key without rotation, remediation due 2026-09-30", "fail"),
    # ── the wider source catalog (attest/sources.py): one fresh, passing record per kind ──
    ("CTL-ACCESS-01", "idp.mfa-enrollment", "okta", "publishable", 2, "MFA enrolled on 214/214 workforce accounts; 0 SMS-only factors", "pass"),
    ("CTL-ACCESS-03", "iam.access-analyzer", "aws-iam", "internal", 3, "Access Analyzer: 0 external findings; 4 unused roles flagged for removal (all < 90 days)", "pass"),
    ("CTL-ACCESS-03", "iam.key-age", "aws-iam", "publishable", 3, "0 access keys older than 90 days; root account: no keys, MFA enforced, last used 2026-02-11", "pass"),
    (None, "iam.root-usage", "aws-iam", "publishable", 3, "Root account not used in the last 180 days; CloudTrail alarm armed", "pass"),
    ("CTL-CHANGE-02", "github.secret-scanning", "github", "publishable", 2, "Secret scanning + push protection on all 31 repos; 0 open alerts, 2 resolved this quarter", "pass"),
    (None, "github.merge-log", "github", "publishable", 2, "1,204 merges in 90 days; 100% via reviewed PR; 0 admin bypasses", "pass"),
    (None, "ci.build-history", "ci-cd", "publishable", 2, "Last 500 production builds: SAST, dependency and IaC scans ran on 100%", "pass"),
    (None, "ci.deploy-record", "ci-cd", "publishable", 2, "38 production deploys this month, each linked to an approved change ticket", "pass"),
    ("CTL-VULN-01", "vuln.findings-sla", "snyk", "publishable", 4, "Open criticals: 0; highs: 3, oldest 6 days against a 14-day SLA; mediums within 30-day SLA", "pass"),
    ("CTL-VULN-01", "inspector.findings", "aws-inspector", "publishable", 4, "Inspector: 0 critical, 2 high on hosts (patch window 2026-09-11); images rebuilt weekly", "pass"),
    (None, "s3.public-access-blocked", "aws-config", "publishable", 2, "Account-level S3 Block Public Access on; 0 public buckets", "pass"),
    ("CTL-DETECT-01", "guardduty.findings", "guardduty", "publishable", 1, "GuardDuty enabled in all regions; 0 high findings open, 3 medium triaged within 24h", "pass"),
    (None, "securityhub.score", "guardduty", "publishable", 1, "Security Hub CIS 1.4 score 96%; 2 failed checks with accepted risk", "pass"),
    ("CTL-ENDPOINT-01", "mdm.disk-encryption", "mdm", "publishable", 2, "FileVault / BitLocker on 212/212 managed devices", "pass"),
    ("CTL-ENDPOINT-01", "mdm.edr-installed", "mdm", "publishable", 2, "EDR agent healthy on 212/212 devices; 0 devices unseen > 7 days", "pass"),
    ("CTL-ENDPOINT-01", "mdm.patch-level", "mdm", "publishable", 2, "OS patch compliance 97.6%; 5 devices past the 14-day window, quarantined", "pass"),
    ("CTL-PEOPLE-01", "training.completion", "training", "publishable", 48, "Annual security awareness training: 214/214 complete; new-hire module within 30 days: 100%", "pass"),
    ("CTL-PEOPLE-01", "training.phishing", "training", "publishable", 48, "Q3 phishing simulation: 3.1% click rate, 0 credential submissions, 41% reported", "pass"),
    ("CTL-PEOPLE-02", "hr.background-check", "hr", "internal", 72, "Background checks complete for 100% of hires in the period (14 of 14)", "pass"),
    ("CTL-PEOPLE-02", "hr.policy-ack", "hr", "publishable", 72, "Acceptable-use and security policies acknowledged by 214/214 employees", "pass"),
    ("CTL-OPS-01", "incident.sla", "ticketing", "publishable", 5, "12 security incidents in 90 days; 100% triaged within 1h, 100% closed within SLA", "pass"),
    (None, "change.approval", "ticketing", "publishable", 5, "All 38 production changes this month carry an approval by someone other than the author", "pass"),
    ("CTL-SECRETS-01", "secrets.rotation", "secrets", "publishable", 6, "Vault: 100% of database and API credentials rotated within 90 days; 0 static secrets in CI", "pass"),
    ("CTL-BACKUP-01", "backup.snapshot", "backup", "publishable", 8, "Nightly snapshots succeeded 30/30 days; cross-region copy verified", "pass"),
    ("CTL-BACKUP-01", "backup.restore-test", "backup", "publishable", 5 * 24, "Restore test 2026-09-02: full production restore in 41 min against a 60 min RTO", "pass"),
    ("CTL-AVAIL-01", "uptime.availability", "uptime", "publishable", 1, "Availability last 30 days: 99.97% against a 99.9% commitment", "pass"),
    ("CTL-VENDOR-01", "vendor.soc2-report", "vendor-registry", "internal", 24, "SOC 2 Type II reports on file for 9 of 11 subprocessors; 2 bridge letters pending", "pass"),
    ("CTL-VENDOR-01", "vendor.dpa", "vendor-registry", "internal", 24, "DPAs executed with 11 of 11 subprocessors", "pass"),
    ("CTL-VENDOR-01", "vendor.review-date", "vendor-registry", "internal", 24, "Annual vendor reviews: 11 of 11 within the last 12 months", "pass"),
]

# The two structured inputs to the HRIS × IdP join. Terminated employees were
# deprovisioned within a day of leaving, so the seeded join passes.
EMPLOYEES = [
    {"id": "E-1001", "name": "Priya Natarajan", "email": "priya.natarajan@attest.internal", "hired": "2022-03-14", "terminated": None},
    {"id": "E-1002", "name": "Marcus Lindqvist", "email": "marcus.lindqvist@attest.internal", "hired": "2021-08-02", "terminated": None},
    {"id": "E-1003", "name": "Aisha Bello", "email": "aisha.bello@attest.internal", "hired": "2023-01-09", "terminated": None},
    {"id": "E-1004", "name": "Tomás Ferreira", "email": "tomas.ferreira@attest.internal", "hired": "2020-11-16", "terminated": "2026-07-31"},
    {"id": "E-1005", "name": "Hannah Weiss", "email": "hannah.weiss@attest.internal", "hired": "2024-05-20", "terminated": None},
    {"id": "E-1006", "name": "Kenji Watanabe", "email": "kenji.watanabe@attest.internal", "hired": "2019-02-25", "terminated": "2026-08-15"},
]
IDP_USERS = [
    {"email": "priya.natarajan@attest.internal", "status": "active", "deprovisioned_at": None},
    {"email": "marcus.lindqvist@attest.internal", "status": "active", "deprovisioned_at": None},
    {"email": "aisha.bello@attest.internal", "status": "active", "deprovisioned_at": None},
    {"email": "tomas.ferreira@attest.internal", "status": "deprovisioned", "deprovisioned_at": "2026-07-31T17:12:00Z"},
    {"email": "hannah.weiss@attest.internal", "status": "active", "deprovisioned_at": None},
    {"email": "kenji.watanabe@attest.internal", "status": "deprovisioned", "deprovisioned_at": "2026-08-15T09:40:00Z"},
]


def seed(data_dir: Path, now: datetime | None = None) -> tuple[EvidenceStore, AuditLog]:
    now = now or datetime.now(timezone.utc)
    data_dir.mkdir(parents=True, exist_ok=True)
    store = EvidenceStore(data_dir / "evidence.jsonl")
    audit = AuditLog(data_dir / "audit.jsonl")
    for control_id, kind, source, classification, age_h, summary, result in SEED:
        collected = (now - timedelta(hours=age_h)).strftime("%Y-%m-%dT%H:%M:%SZ")
        store.append(
            source=source,
            kind=kind,
            control_ids=[control_id] if control_id else [],
            classification=classification,
            payload={"summary": summary, "result": result},
            collected_at=collected,
        )
    stamp = (now - timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
    terminated = sum(1 for e in EMPLOYEES if e["terminated"])
    store.append(source="hris", kind="hris.roster", control_ids=["CTL-ACCESS-02"], classification="internal", collected_at=stamp,
                 payload={"summary": f"HRIS roster: {len(EMPLOYEES)} employees, {terminated} terminated in the period", "result": "pass",
                          "employees": [dict(e) for e in EMPLOYEES]})
    store.append(source="okta", kind="idp.users", control_ids=["CTL-ACCESS-02"], classification="internal", collected_at=stamp,
                 payload={"summary": f"IdP users: {sum(1 for u in IDP_USERS if u['status'] == 'active')} active, "
                                     f"{sum(1 for u in IDP_USERS if u['status'] != 'active')} deprovisioned", "result": "pass",
                          "users": [dict(u) for u in IDP_USERS]})
    from attest.collectors.joiner_leaver import run_join
    run_join(store, now=now)
    audit.record(actor="collector-agent", action="evidence.seeded", subject="evidence-store",
                 detail=f"{len(store.all())} records from {len({r.source for r in store.all()})} sources")
    return store, audit

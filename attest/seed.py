"""Representative seed data. One evidence gap (missing BAAs) fails three frameworks."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from attest.audit import AuditLog
from attest.evidence import EvidenceStore

# (control_id, kind, source, classification, age_hours, summary, result)
SEED = [
    ("CTL-ACCESS-01", "iam.least-privilege", "aws-config", "publishable", 2, "0 IAM principals with wildcard actions; SCP denies root usage", "pass"),
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
            control_ids=[control_id],
            classification=classification,
            payload={"summary": summary, "result": result},
            collected_at=collected,
        )
    audit.record(actor="collector-agent", action="evidence.seeded", subject=str(data_dir), detail=f"{len(SEED)} records")
    return store, audit

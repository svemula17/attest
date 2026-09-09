"""The evidence-source catalog: which systems prove what.

Hardcoded for now. Every kind of evidence a control consumes belongs to exactly
one source here (tested), so the console can show, per family, what feeds each
control and how fresh it is. The HRIS × IdP join is the one derived check —
the highest-value thing in the whole pipeline.
"""
from __future__ import annotations

from dataclasses import dataclass

FAMILIES: dict[str, str] = {
    "access": "Access control",
    "change": "Change management",
    "vuln": "Vulnerability management",
    "infra": "Infrastructure and configuration",
    "endpoint": "Endpoints",
    "people": "People",
    "ops": "Operations",
    "third-party": "Third party",
}


@dataclass(frozen=True)
class Source:
    id: str
    system: str
    family: str
    proves: str
    kinds: tuple[str, ...]


SOURCES: tuple[Source, ...] = (
    # ── Access control — the biggest evidence family in any audit ──
    Source("okta", "Okta / Entra ID", "access",
           "User list, MFA enrollment, SSO enforcement, group membership, deprovisioning timestamps.",
           ("sso.enforced", "idp.users", "idp.mfa-enrollment", "access.leaver-deprovisioned")),
    Source("aws-iam", "AWS IAM + Access Analyzer", "access",
           "Roles, policies, unused permissions, root account usage, access-key age.",
           ("iam.least-privilege", "iam.access-analyzer", "iam.root-usage", "iam.key-age")),
    Source("hris", "Workday / BambooHR", "access",
           "Hire and termination dates — the input that makes access reviews real when joined against the IdP.",
           ("hris.roster",)),
    Source("access-review", "Access review records", "access",
           "Quarterly privileged-access reviews with reviewer identity and outcome per principal.",
           ("access-review.quarterly",)),
    # ── Change management ──
    Source("github", "GitHub", "change",
           "Branch protection, PR approval records, required status checks, who merged what, secret-scanning alerts.",
           ("pr.review-required", "github.secret-scanning", "github.merge-log")),
    Source("ci-cd", "GitHub Actions / Jenkins", "change",
           "Build history, approval gates, which scans ran, deployment records.",
           ("ci.policy-gate", "ci.build-history", "ci.deploy-record")),
    # ── Vulnerability management ──
    Source("snyk", "Snyk / SonarQube / Trivy", "vuln",
           "Findings, severity, and time-to-remediate against the SLA.",
           ("vuln.findings-sla",)),
    Source("aws-inspector", "AWS Inspector", "vuln",
           "Host and container-image vulnerabilities.",
           ("inspector.findings",)),
    # ── Infrastructure and configuration ──
    Source("aws-config", "AWS Config", "infra",
           "Resource state: encryption on, public access blocked, logging enabled.",
           ("kms.key.rotation", "storage.encrypted", "sg.no-open-ingress", "waf.enabled", "s3.public-access-blocked")),
    Source("cloudtrail", "CloudTrail", "infra",
           "API activity and privileged actions, with log-file integrity validation.",
           ("cloudtrail.enabled", "log.integrity", "tls.policy")),
    Source("guardduty", "GuardDuty / Security Hub", "infra",
           "Detection findings and the posture score.",
           ("guardduty.findings", "securityhub.score")),
    Source("siem", "SIEM", "infra",
           "Detection rules, alert routing and anomaly monitoring.",
           ("siem.alerting",)),
    # ── Endpoints ──
    Source("mdm", "Jamf / Intune / Kandji", "endpoint",
           "Disk encryption, screen lock, OS patch level, EDR installed on every device.",
           ("mdm.disk-encryption", "mdm.edr-installed", "mdm.patch-level")),
    # ── People ──
    Source("training", "KnowBe4", "people",
           "Awareness-training completion and phishing-simulation results.",
           ("training.completion", "training.phishing")),
    Source("hr", "HR system", "people",
           "Background-check completion and policy acknowledgements.",
           ("hr.background-check", "hr.policy-ack")),
    # ── Operations ──
    Source("ticketing", "Jira / ServiceNow", "ops",
           "Incident tickets, remediation-SLA adherence, change approvals.",
           ("incident.sla", "change.approval")),
    Source("secrets", "Vault / Secrets Manager", "ops",
           "Key and secret rotation records.",
           ("secrets.rotation",)),
    Source("backup", "AWS Backup / DR runbook", "ops",
           "Snapshot success and restore-test results.",
           ("backup.snapshot", "backup.restore-test")),
    Source("uptime", "Monitoring / uptime", "ops",
           "Availability, when SOC 2 Availability is in scope.",
           ("uptime.availability",)),
    Source("grc", "GRC platform", "ops",
           "Risk analysis and treatment decisions.",
           ("risk.assessment",)),
    Source("finding-tracker", "Finding tracker", "ops",
           "Open findings with owners and due dates — restricted, never citable.",
           ("finding.open",)),
    # ── Third party ──
    Source("vendor-registry", "Vendor register", "third-party",
           "Vendor list, their SOC 2 reports, DPAs and BAAs, review dates.",
           ("baa.executed", "vendor.soc2-report", "vendor.dpa", "vendor.review-date")),
)

JOIN = {
    "id": "hris-idp-join",
    "name": "Leaver deprovisioning (HRIS × IdP)",
    "inputs": ("hris.roster", "idp.users"),
    "output": "access.leaver-deprovisioned",
    "control": "CTL-ACCESS-02",
    "proves": "Accounts still active after someone left. Joining the HR roster against the identity provider is what makes an access review real — a signature on a quarterly review cannot hide an orphaned account.",
}

_BY_ID = {s.id: s for s in SOURCES}
_BY_KIND = {k: s for s in SOURCES for k in s.kinds}


def sources_by_family() -> dict[str, list[Source]]:
    return {fid: [s for s in SOURCES if s.family == fid] for fid in FAMILIES}


def source_for_kind(kind: str) -> Source | None:
    return _BY_KIND.get(kind)


def source_by_id(source_id: str) -> Source | None:
    return _BY_ID.get(source_id)

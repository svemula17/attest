# Attest — module contract (all agents build against this exactly)

Python 3.11+, **stdlib only** (json, hashlib, dataclasses, datetime, pathlib, re, argparse). Tests use pytest.
Package root: /Users/saikumarvemula/Developer/GitHub/attest/attest/   Tests: /Users/saikumarvemula/Developer/GitHub/attest/tests/
Timestamps: ISO 8601 UTC strings, e.g. "2026-09-09T14:02:11Z". Helper `attest.util.now_iso()` and `attest.util.parse_iso(s) -> datetime` (aware, UTC) exist — Agent A writes util.py.

## attest/evidence.py  (Agent A)
```python
@dataclass(frozen=True)
class EvidenceRecord:
    id: str                 # "EV-0001" zero-padded 4, sequential
    source: str             # "aws-config" | "cloudtrail" | "github" | "okta" | "vendor-registry" | ...
    kind: str               # dotted, e.g. "kms.key.rotation", "tls.policy", "baa.executed"
    control_ids: list[str]  # internal control ids e.g. ["CTL-CRYPTO-01"]
    classification: str     # "publishable" | "internal" | "restricted"
    collected_at: str       # ISO UTC
    payload: dict
    sha256: str             # hex digest of canonical JSON of all fields except sha256, plus prev_sha256
    prev_sha256: str | None

CLASSIFICATION_ORDER = ["publishable", "internal", "restricted"]  # ascending sensitivity

class EvidenceStore:
    def __init__(self, path: Path): ...          # JSONL file, one record per line, created if missing
    def append(self, source, kind, control_ids, classification, payload, collected_at=None) -> EvidenceRecord
    def all(self) -> list[EvidenceRecord]
    def get(self, record_id) -> EvidenceRecord | None
    def query(self, control_id=None, kind=None, max_classification=None) -> list[EvidenceRecord]
        # max_classification="publishable" returns ONLY publishable; "internal" returns publishable+internal
    def verify_chain(self) -> bool                # recompute every hash + prev link
```
No update/delete methods exist. Append-only by construction.

## attest/audit.py  (Agent A)
```python
@dataclass(frozen=True)
class AuditEntry:
    ts: str; actor: str; model_version: str | None; action: str; subject: str; approver: str | None; rule: str | None; detail: str
class AuditLog:
    def __init__(self, path: Path)
    def record(self, actor, action, subject, model_version=None, approver=None, rule=None, detail="") -> AuditEntry
    def all(self) -> list[AuditEntry]
```

## attest/controls.py  (Agent B)
```python
@dataclass(frozen=True)
class Control:
    id: str                       # "CTL-ACCESS-01"
    name: str
    required_kinds: list[str]     # evidence kinds that must all be present and fresh
    freshness_sla_hours: int
    mappings: dict[str, list[str]]  # {"soc2": ["CC6.1"], "iso27001": ["A.5.15"], "hipaa": ["164.312(a)(1)"]}
    hipaa_spec: str | None = None   # "required" | "addressable" | None

@dataclass(frozen=True)
class ControlResult:
    control_id: str
    state: str                    # "PASS" | "DEGRADED" | "FAIL"
    evidence_ids: list[str]
    reason: str

# state rules: all required kinds present & within SLA -> PASS
#              all present but any outside SLA         -> DEGRADED
#              any required kind missing OR any payload has {"result": "fail"} -> FAIL

FRAMEWORKS = {"soc2": "SOC 2 Type II", "iso27001": "ISO/IEC 27001:2022", "hipaa": "HIPAA Security Rule (45 CFR 164)"}

def default_catalog() -> list[Control]   # >= 10 controls covering access, crypto at rest, crypto in transit, logging, change mgmt, vendor/BAA, risk analysis, monitoring, privileged access review, boundary
class ControlEngine:
    def __init__(self, catalog: list[Control], store: EvidenceStore)
    def evaluate(self, now: datetime | None = None) -> list[ControlResult]
    def posture(self, framework: str, now=None) -> list[dict]
        # [{"framework_id": "CC6.1", "control_id": ..., "name": ..., "state": ..., "evidence_ids": [...], "spec": hipaa_spec or None}]
    def summary(self, now=None) -> dict   # {"total": n, "pass": n, "degraded": n, "fail": n, "by_framework": {fw: {"pass":..,"total":..}}}
```

## attest/guardrails.py  (Agent C)
```python
class GuardrailViolation(Exception):
    def __init__(self, rule: str, detail: str)

WRITE_TOOL_PREFIXES = ("write:", "update:", "delete:", "approve:", "send:")

def untrusted_doc_isolation(registered_tools: list[str]) -> None
    # raises GuardrailViolation("untrusted-doc-isolation", ...) if any registered tool name starts with a WRITE_TOOL_PREFIX
def scan_for_injection(text: str) -> list[str]
    # returns list of matched pattern names (e.g. "ignore-prior-instructions", "authority-claim", "hidden-html-comment"); detection is for logging only — isolation is the control
def enforce_tool_allowlist(requested_tool: str, allowlist: frozenset[str]) -> None   # raises ("tool-allowlist")

@dataclass(frozen=True)
class Claim: text: str; evidence_ids: list[str]
def citation_required(claims: list[Claim], store) -> None
    # raises ("citation-required") if any claim has no evidence_ids or any id not found in store.get()
def egress_classification_gate(records, max_classification="publishable") -> None
    # raises ("egress-classification-gate") if any record.classification is above max (use evidence.CLASSIFICATION_ORDER)

class StepBudget:
    def __init__(self, max_steps: int = 12)
    def tick(self, tool: str) -> int      # raises ("max-steps") when exceeded; cannot be raised after construction (no setter)

@dataclass(frozen=True)
class RequesterScope: user: str; grants: frozenset[str]
def enforce_requester_scope(scope: RequesterScope, requested_tool: str) -> None  # raises ("requester-scoped-identity") if tool not in grants
```

## attest/agent.py  (Agent C)
No LLM calls. A deterministic "answer agent" that composes an answer from evidence so the pipeline is testable offline:
```python
@dataclass
class Draft: question_id: str; question: str; answer: str; evidence_ids: list[str]; status: str  # "READY" | "BLOCKED" | "DECLINED"; reason: str = ""
class AnswerAgent:
    def __init__(self, store, audit: AuditLog, scope: RequesterScope, allowlist: frozenset[str], model_version="answer-agent v0.4.2", max_steps=12)
    def draft(self, question_id: str, question: str, control_ids: list[str]) -> Draft
        # queries store with max_classification="publishable" for those control_ids (each query = one tick on the StepBudget),
        # builds Claim list, runs citation_required + egress_classification_gate; any GuardrailViolation -> status BLOCKED with reason=rule;
        # zero evidence -> status DECLINED (never infer from absence); every outcome writes an AuditLog entry
class ReaderAgent:
    def __init__(self, audit: AuditLog, registered_tools: list[str])
    def read(self, doc_id: str, text: str) -> dict   # calls untrusted_doc_isolation first (raises if misconfigured), then scan_for_injection; returns {"doc_id", "injection_patterns": [...], "quarantined": bool, "extracted": {...}}; audits the outcome
```

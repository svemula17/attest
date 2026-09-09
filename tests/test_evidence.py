import dataclasses
import hashlib
import json

import pytest

from attest.evidence import CLASSIFICATION_ORDER, EvidenceRecord, EvidenceStore
from attest.util import canonical_json, parse_iso

T0 = "2026-09-09T10:00:00Z"


def _store(tmp_path) -> EvidenceStore:
    return EvidenceStore(tmp_path / "evidence.jsonl")


def _seed(store: EvidenceStore):
    a = store.append("aws-config", "kms.key.rotation", ["CTL-CRYPTO-01"], "publishable", {"status": "ok"}, collected_at=T0)
    b = store.append("cloudtrail", "log.retention", ["CTL-LOG-01", "CTL-CRYPTO-01"], "internal", {"status": "ok"}, collected_at=T0)
    c = store.append("okta", "mfa.enforced", ["CTL-ACCESS-01"], "restricted", {"status": "ok"}, collected_at=T0)
    return a, b, c


def _lines(path) -> list[str]:
    return path.read_text(encoding="utf-8").splitlines()


# -- construction / ids ----------------------------------------------------------

def test_creates_file_if_missing(tmp_path):
    path = tmp_path / "nested" / "evidence.jsonl"
    assert not path.exists()
    store = EvidenceStore(path)
    assert path.exists()
    assert store.all() == []


def test_sequential_zero_padded_ids(tmp_path):
    store = _store(tmp_path)
    a, b, c = _seed(store)
    assert [a.id, b.id, c.id] == ["EV-0001", "EV-0002", "EV-0003"]
    assert [r.id for r in store.all()] == ["EV-0001", "EV-0002", "EV-0003"]


def test_store_reopened_from_disk_continues_ids(tmp_path):
    path = tmp_path / "evidence.jsonl"
    first = EvidenceStore(path)
    _seed(first)
    reopened = EvidenceStore(path)
    assert [r.id for r in reopened.all()] == ["EV-0001", "EV-0002", "EV-0003"]
    d = reopened.append("github", "branch.protection", ["CTL-CHANGE-01"], "internal", {"status": "ok"}, collected_at=T0)
    assert d.id == "EV-0004"
    assert d.prev_sha256 == first.all()[-1].sha256
    assert reopened.verify_chain() is True
    assert len(_lines(path)) == 4


def test_collected_at_defaults_to_now_iso(tmp_path):
    store = _store(tmp_path)
    rec = store.append("okta", "mfa.enforced", ["CTL-ACCESS-01"], "publishable", {})
    assert rec.collected_at.endswith("Z")
    assert parse_iso(rec.collected_at).tzinfo is not None


# -- hash chain ------------------------------------------------------------------

def test_hash_matches_contract_formula(tmp_path):
    store = _store(tmp_path)
    a, b, _ = _seed(store)
    for rec in (a, b):
        hashed = {
            "id": rec.id,
            "source": rec.source,
            "kind": rec.kind,
            "control_ids": rec.control_ids,
            "classification": rec.classification,
            "collected_at": rec.collected_at,
            "payload": rec.payload,
            "prev_sha256": rec.prev_sha256,
        }
        expected = hashlib.sha256(canonical_json(hashed).encode("utf-8")).hexdigest()
        assert rec.sha256 == expected


def test_hash_chain_links_and_verifies(tmp_path):
    store = _store(tmp_path)
    a, b, c = _seed(store)
    assert a.prev_sha256 is None
    assert b.prev_sha256 == a.sha256
    assert c.prev_sha256 == b.sha256
    assert len({a.sha256, b.sha256, c.sha256}) == 3
    assert store.verify_chain() is True
    assert EvidenceStore(store.path).verify_chain() is True


def test_empty_store_chain_verifies(tmp_path):
    assert _store(tmp_path).verify_chain() is True


def test_tampered_line_on_disk_breaks_chain(tmp_path):
    store = _store(tmp_path)
    _seed(store)
    assert store.verify_chain() is True

    lines = _lines(store.path)
    assert '"status":"ok"' in lines[1]
    lines[1] = lines[1].replace('"status":"ok"', '"status":"bad"')
    store.path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    assert store.verify_chain() is False                      # existing handle re-reads disk
    assert EvidenceStore(store.path).verify_chain() is False  # fresh handle agrees


def test_removed_middle_line_breaks_chain(tmp_path):
    store = _store(tmp_path)
    _seed(store)
    lines = _lines(store.path)
    del lines[1]
    store.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert store.verify_chain() is False


def test_corrupt_json_line_breaks_chain(tmp_path):
    store = _store(tmp_path)
    _seed(store)
    with store.path.open("a", encoding="utf-8") as fh:
        fh.write("{not json\n")
    assert store.verify_chain() is False


def test_on_disk_format_is_jsonl(tmp_path):
    store = _store(tmp_path)
    a, _, _ = _seed(store)
    lines = _lines(store.path)
    assert len(lines) == 3
    first = json.loads(lines[0])
    assert first == dataclasses.asdict(a)


# -- lookup / query --------------------------------------------------------------

def test_get_known_and_unknown(tmp_path):
    store = _store(tmp_path)
    a, _, _ = _seed(store)
    assert store.get("EV-0001") == a
    assert store.get("EV-9999") is None
    assert store.get("") is None


def test_query_by_control_id(tmp_path):
    store = _store(tmp_path)
    a, b, c = _seed(store)
    assert store.query(control_id="CTL-CRYPTO-01") == [a, b]
    assert store.query(control_id="CTL-ACCESS-01") == [c]
    assert store.query(control_id="CTL-NOPE") == []


def test_query_by_kind(tmp_path):
    store = _store(tmp_path)
    a, b, _ = _seed(store)
    assert store.query(kind="kms.key.rotation") == [a]
    assert store.query(kind="log.retention") == [b]
    assert store.query(kind="kms.key") == []  # exact match, not prefix


def test_query_max_classification_publishable_excludes_internal_and_restricted(tmp_path):
    store = _store(tmp_path)
    a, _, _ = _seed(store)
    assert store.query(max_classification="publishable") == [a]


def test_query_max_classification_internal_includes_publishable(tmp_path):
    store = _store(tmp_path)
    a, b, _ = _seed(store)
    assert store.query(max_classification="internal") == [a, b]


def test_query_max_classification_restricted_or_none_returns_all(tmp_path):
    store = _store(tmp_path)
    a, b, c = _seed(store)
    assert store.query(max_classification="restricted") == [a, b, c]
    assert store.query() == [a, b, c]


def test_query_combined_filters(tmp_path):
    store = _store(tmp_path)
    a, _, _ = _seed(store)
    assert store.query(control_id="CTL-CRYPTO-01", max_classification="publishable") == [a]
    assert store.query(control_id="CTL-CRYPTO-01", kind="log.retention", max_classification="publishable") == []


def test_query_unknown_max_classification_rejected(tmp_path):
    store = _store(tmp_path)
    _seed(store)
    with pytest.raises(ValueError):
        store.query(max_classification="public")


# -- invariants ------------------------------------------------------------------

def test_classification_order_is_ascending_sensitivity():
    assert CLASSIFICATION_ORDER == ["publishable", "internal", "restricted"]


def test_invalid_classification_rejected_and_nothing_written(tmp_path):
    store = _store(tmp_path)
    with pytest.raises(ValueError):
        store.append("okta", "mfa.enforced", ["CTL-ACCESS-01"], "secret", {})
    assert store.all() == []
    assert _lines(store.path) == []


def test_records_are_frozen(tmp_path):
    store = _store(tmp_path)
    a, _, _ = _seed(store)
    with pytest.raises(dataclasses.FrozenInstanceError):
        a.classification = "publishable"


def test_store_has_no_mutating_methods():
    forbidden = ("update", "delete", "remove", "pop", "clear", "truncate", "rewrite", "replace")
    public = [name for name in dir(EvidenceStore) if not name.startswith("_")]
    assert public == sorted(["all", "append", "get", "query", "verify_chain"])
    for name in public:
        assert not any(word in name.lower() for word in forbidden)

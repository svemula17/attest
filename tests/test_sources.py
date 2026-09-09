"""The evidence-source catalog and its coverage of the control catalog."""
from attest.controls import default_catalog
from attest.seed import SEED, seed
from attest.sources import FAMILIES, JOIN, SOURCES, source_by_id, source_for_kind, sources_by_family


def test_every_control_kind_belongs_to_exactly_one_source():
    kinds = {k for c in default_catalog() for k in c.required_kinds}
    owners = {k: [s.id for s in SOURCES if k in s.kinds] for k in kinds}
    assert all(len(v) == 1 for v in owners.values()), {k: v for k, v in owners.items() if len(v) != 1}


def test_source_ids_unique_and_families_complete():
    ids = [s.id for s in SOURCES]
    assert len(ids) == len(set(ids))
    assert list(sources_by_family()) == list(FAMILIES)
    assert all(sources_by_family()[f] for f in FAMILIES), "every family has at least one source"


def test_seed_sources_exist_in_catalog_and_every_source_has_a_record(tmp_path):
    assert all(source_by_id(row[2]) for row in SEED), {row[2] for row in SEED if not source_by_id(row[2])}
    store, _ = seed(tmp_path)
    by_source = {r.source for r in store.all()}
    missing = [s.id for s in SOURCES if s.id not in by_source]
    assert not missing, missing


def test_join_output_is_wired_to_the_leaver_control():
    assert source_for_kind(JOIN["output"]) is not None
    ctl = next(c for c in default_catalog() if c.id == JOIN["control"])
    assert JOIN["output"] in ctl.required_kinds
    assert set(ctl.mappings) == {"soc2", "iso27001", "hipaa"}


def test_seeded_catalog_has_only_the_baa_gap(tmp_path):
    from attest.controls import ControlEngine
    store, _ = seed(tmp_path)
    results = {r.control_id: r.state for r in ControlEngine(default_catalog(), store).evaluate()}
    assert results["CTL-ACCESS-02"] == "PASS"
    assert [c for c, s in results.items() if s == "FAIL"] == ["CTL-VENDOR-01"]

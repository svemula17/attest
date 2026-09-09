"""attest gate: FAIL blocks unless a current risk acceptance covers it; DEGRADED blocks only with --strict."""
import json
from datetime import date, timedelta
from pathlib import Path

import pytest

from attest.cli import gate_rows, load_acceptances, main
from attest.controls import ControlResult

REPO_GATE = Path(__file__).resolve().parent.parent / "gate.json"


@pytest.fixture
def data(tmp_path):
    assert main(["--data", str(tmp_path), "seed"]) == 0
    return tmp_path


def accept_file(tmp_path, entries, name="accept.json"):
    path = tmp_path / name
    path.write_text(json.dumps({"accepted": entries}), encoding="utf-8")
    return str(path)


def vendor(expires, owner="s.vemula", reason="BAA execution in progress; VEND-118"):
    return {"control": "CTL-VENDOR-01", "owner": owner, "reason": reason, "expires": expires}


def test_current_acceptance_passes(data, capsys):
    rc = main(["--data", str(data), "gate", "--accept-file", accept_file(data, [vendor("2999-12-31")])])
    out = capsys.readouterr().out
    assert rc == 0
    assert "ACCEPTED (s.vemula, until 2999-12-31)" in out
    assert "accepted: BAA execution in progress; VEND-118" in out
    assert "DEGRADED (does not block)" in out
    assert "gate: PASS" in out and "0 blocking" in out


def test_acceptance_valid_through_its_expiry_date(data, capsys):
    today = date.today().isoformat()
    rc = main(["--data", str(data), "gate", "--accept-file", accept_file(data, [vendor(today)])])
    assert rc == 0
    assert f"until {today}" in capsys.readouterr().out


def test_expired_acceptance_fails(data, capsys):
    rc = main(["--data", str(data), "gate", "--accept-file", accept_file(data, [vendor("2020-01-01")])])
    out = capsys.readouterr().out
    assert rc == 1
    assert "FAIL (acceptance by s.vemula expired 2020-01-01)" in out
    assert "(0 active, 1 expired)" in out
    assert "gate: FAIL" in out and "CTL-VENDOR-01" in out.split("gate: FAIL")[1]


def test_missing_accept_file_fails(data, capsys):
    rc = main(["--data", str(data), "gate", "--accept-file", str(data / "nope.json")])
    out = capsys.readouterr().out
    assert rc == 1
    assert "acceptances: none" in out
    assert "FAIL (no acceptance)" in out


def test_acceptance_for_other_control_does_not_help(data):
    entries = [{"control": "CTL-NET-01", "owner": "x", "reason": "y", "expires": "2999-12-31"}]
    assert main(["--data", str(data), "gate", "--accept-file", accept_file(data, entries)]) == 1


def test_strict_makes_degraded_fail(data, capsys):
    af = accept_file(data, [vendor("2999-12-31")])
    assert main(["--data", str(data), "gate", "--accept-file", af]) == 0
    capsys.readouterr()
    rc = main(["--data", str(data), "gate", "--accept-file", af, "--strict"])
    out = capsys.readouterr().out
    assert rc == 1
    assert "mode: strict" in out
    assert "DEGRADED (no acceptance)" in out
    assert "CTL-PRIV-01" in out.split("gate: FAIL")[1] and "CTL-CHANGE-01" in out.split("gate: FAIL")[1]


def test_strict_honours_acceptances_for_degraded(data):
    entries = [vendor("2999-12-31"),
               {"control": "CTL-PRIV-01", "owner": "a", "reason": "review in flight", "expires": "2999-12-31"},
               {"control": "CTL-CHANGE-01", "owner": "a", "reason": "collector re-run pending", "expires": "2999-12-31"}]
    assert main(["--data", str(data), "gate", "--accept-file", accept_file(data, entries), "--strict"]) == 0


def test_malformed_entries_are_ignored_fail_closed(data, capsys):
    entries = [{"control": "CTL-VENDOR-01", "owner": "s.vemula", "reason": "no date"},
               {"owner": "nobody", "expires": "2999-12-31"}]
    rc = main(["--data", str(data), "gate", "--accept-file", accept_file(data, entries)])
    out = capsys.readouterr().out
    assert rc == 1
    assert out.count("warning:") == 2


def test_gate_writes_audit_entry(data, capsys):
    main(["--data", str(data), "gate", "--accept-file", accept_file(data, [vendor("2999-12-31")])])
    capsys.readouterr()
    main(["--data", str(data), "audit"])
    assert "gate.pass" in capsys.readouterr().out


def test_gate_rows_latest_expiry_wins():
    today = date(2026, 9, 9)
    results = [ControlResult("CTL-X", "FAIL", [], "boom")]
    acceptances = [{"control": "CTL-X", "owner": "a", "reason": "", "expires": today - timedelta(days=1)},
                   {"control": "CTL-X", "owner": "b", "reason": "", "expires": today + timedelta(days=1)}]
    row = gate_rows(results, acceptances, today)[0]
    assert row["blocks"] is False and row["verdict"].startswith("ACCEPTED (b,")


def test_repo_gate_json_is_well_formed():
    accepted, warnings = load_acceptances(REPO_GATE)
    assert warnings == []
    assert [a["control"] for a in accepted] == ["CTL-VENDOR-01"]
    assert accepted[0]["owner"] == "s.vemula"
    assert "VEND-118" in accepted[0]["reason"]
    assert isinstance(accepted[0]["expires"], date)

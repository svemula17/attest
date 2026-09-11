import pytest

from attest.config import ConfigError, default_config_toml, load_config, parse_config


def test_default_config_parses_and_is_self_describing():
    cfg = parse_config(default_config_toml())
    assert cfg.server.mode == "production" and cfg.storage.url.startswith("sqlite")
    assert set(cfg.sources) == {"hris", "idp", "leavers", "evidence"}
    assert cfg.sources["leavers"].type == "hris-idp-join" and cfg.sources["leavers"].schedule == "0 6 * * *"
    assert len(cfg.auth.session_secret) == 64


def test_sandbox_mode_and_paths(tmp_path):
    p = tmp_path / "attest.toml"; p.write_text(default_config_toml(mode="sandbox"))
    cfg = load_config(str(p))
    assert cfg.sandbox and cfg.root == tmp_path and cfg.resolve("imports/x.csv") == tmp_path / "imports/x.csv"


def test_acceptances_and_overrides():
    cfg = parse_config('''
[[acceptances]]
control = "CTL-VENDOR-01"
owner = "s.vemula"
reason = "BAA in progress"
expires = 2026-10-31

[sla_overrides]
CTL-PEOPLE-01 = 1440
''')
    assert cfg.acceptances[0].expires == "2026-10-31" and cfg.sla_overrides["CTL-PEOPLE-01"] == 1440


@pytest.mark.parametrize("text, msg", [
    ('[server]\nmode = "demo"\n', "mode"),
    ('[server]\nbogus = 1\n', "unknown keys"),
    ('[sources.x]\nschedule = "* * * * *"\n', "needs a type"),
    ('[[acceptances]]\ncontrol = "CTL-X"\n', "missing"),
    ('this is not toml = = =\n', "config"),
])
def test_errors_name_the_problem(text, msg):
    with pytest.raises(ConfigError) as ei:
        parse_config(text)
    assert msg in str(ei.value)


def test_missing_config_is_defaults(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path); monkeypatch.delenv("ATTEST_CONFIG", raising=False)
    cfg = load_config()
    assert cfg.path is None and cfg.server.port == 8765
    with pytest.raises(ConfigError):
        load_config(str(tmp_path / "nope.toml"))

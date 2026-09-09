"""GitHub branch-protection collector with an injected fetch (no network)."""
import pytest

from attest.cli import main
from attest.collectors import github as gh
from attest.collectors.github import collect_branch_protection
from attest.controls import ControlEngine, default_catalog
from attest.evidence import EvidenceStore

REPO_URL = "https://api.github.com/repos/acme/widgets"
PROT_URL = "https://api.github.com/repos/acme/widgets/branches/main/protection"

PROTECTED = {
    "required_pull_request_reviews": {"required_approving_review_count": 1, "dismiss_stale_reviews": True},
    "required_status_checks": {"strict": True, "contexts": ["ci/test"], "checks": [{"context": "ci/test", "app_id": 1}, {"context": "lint", "app_id": 1}]},
    "enforce_admins": {"enabled": True},
}


def make_fetch(protection, repo=(200, {"default_branch": "main"})):
    calls = []

    def fetch(url, token):
        calls.append((url, token))
        if url == REPO_URL:
            return repo
        if url == PROT_URL:
            return protection
        raise AssertionError(f"unexpected url {url}")

    fetch.calls = calls
    return fetch


@pytest.fixture
def store(tmp_path):
    return EvidenceStore(tmp_path / "evidence.jsonl")


@pytest.fixture(autouse=True)
def no_env_token(monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GH_TOKEN", raising=False)


def test_protected_repo_both_pass(store):
    fetch = make_fetch((200, PROTECTED))
    records = collect_branch_protection(store, "acme/widgets", token="t0k", fetch=fetch)
    assert [r.kind for r in records] == ["pr.review-required", "ci.policy-gate"]
    assert all(r.payload["result"] == "pass" for r in records)
    review, ci = records
    assert review.payload["summary"] == "Branch protection on main: 1 approving review required"
    assert "ci/test" in ci.payload["summary"] and "lint" in ci.payload["summary"]
    assert review.payload["raw"] == {"protected": True, "required_pull_request_reviews": True, "required_approving_review_count": 1}
    assert ci.payload["raw"]["context_count"] == 2
    # both requests carried the token, and the branch came from the repo lookup
    assert [c[0] for c in fetch.calls] == [REPO_URL, PROT_URL]
    assert all(c[1] == "t0k" for c in fetch.calls)


def test_records_land_in_store_with_contract_fields(store):
    collect_branch_protection(store, "acme/widgets", fetch=make_fetch((200, PROTECTED)))
    stored = store.all()
    assert [r.id for r in stored] == ["EV-0001", "EV-0002"]
    for r in stored:
        assert r.source == "github"
        assert r.control_ids == ["CTL-CHANGE-01"]
        assert r.classification == "publishable"
        assert r.payload["repo"] == "acme/widgets"
        assert r.payload["branch"] == "main"
        assert r.payload["collected_by"] == "attest.collectors.github"
        assert set(r.payload) == {"summary", "result", "repo", "branch", "collected_by", "raw"}
    assert store.verify_chain()
    # the engine can consume them straight away
    result = {r.control_id: r for r in ControlEngine(default_catalog(), store).evaluate()}["CTL-CHANGE-01"]
    assert result.state == "PASS"
    assert result.evidence_ids == ["EV-0001", "EV-0002"]


def test_unprotected_404_both_fail(store):
    records = collect_branch_protection(store, "acme/widgets", fetch=make_fetch((404, {"message": "Branch not protected"})))
    assert [r.payload["result"] for r in records] == ["fail", "fail"]
    assert all(r.payload["summary"] == "no branch protection on main" for r in records)
    assert all(r.payload["raw"] == {"protected": False} for r in records)
    result = {r.control_id: r for r in ControlEngine(default_catalog(), store).evaluate()}["CTL-CHANGE-01"]
    assert result.state == "FAIL"


def test_403_upgrade_to_pro_means_unprotected(store):
    body = {"message": "Upgrade to GitHub Pro or make this repository public to enable this feature."}
    records = collect_branch_protection(store, "acme/widgets", fetch=make_fetch((403, body)))
    assert [r.payload["result"] for r in records] == ["fail", "fail"]


@pytest.mark.parametrize("status", [401, 403])
def test_forbidden_raises_permission_error_naming_scope(store, status):
    with pytest.raises(PermissionError) as exc:
        collect_branch_protection(store, "acme/widgets", fetch=make_fetch((status, {"message": "Resource not accessible"})))
    msg = str(exc.value)
    assert "'repo'" in msg and "Administration: read" in msg and "Resource not accessible" in msg
    assert store.all() == []  # nothing half-written


def test_repo_404_raises_value_error(store):
    with pytest.raises(ValueError, match="repo not found or not accessible"):
        collect_branch_protection(store, "acme/widgets", fetch=make_fetch((200, PROTECTED), repo=(404, {})))


def test_bad_repo_shape_rejected_before_any_request(store):
    fetch = make_fetch((200, PROTECTED))
    with pytest.raises(ValueError, match="owner/name"):
        collect_branch_protection(store, "widgets", fetch=fetch)
    assert fetch.calls == []


def test_reviews_present_with_zero_count_fails(store):
    body = {"required_pull_request_reviews": {"required_approving_review_count": 0}, "required_status_checks": {"contexts": ["ci"]}}
    review, ci = collect_branch_protection(store, "acme/widgets", fetch=make_fetch((200, body)))
    assert review.payload["result"] == "fail" and "0 approving reviews" in review.payload["summary"]
    assert ci.payload["result"] == "pass"


def test_checks_only_no_contexts_still_pass(store):
    body = {"required_status_checks": {"contexts": [], "checks": [{"context": "build", "app_id": None}]}}
    review, ci = collect_branch_protection(store, "acme/widgets", fetch=make_fetch((200, body)))
    assert review.payload["result"] == "fail" and "not required" in review.payload["summary"]
    assert ci.payload["result"] == "pass" and ci.payload["summary"].endswith("required status checks: build")


def test_empty_status_checks_fail(store):
    body = {"required_pull_request_reviews": {"required_approving_review_count": 2}, "required_status_checks": {"contexts": []}}
    review, ci = collect_branch_protection(store, "acme/widgets", fetch=make_fetch((200, body)))
    assert review.payload["result"] == "pass" and "2 approving reviews" in review.payload["summary"]
    assert ci.payload["result"] == "fail" and ci.payload["summary"].endswith("no required status checks")


def test_token_resolution_order(store, monkeypatch):
    fetch = make_fetch((200, PROTECTED))
    collect_branch_protection(store, "acme/widgets", fetch=fetch)
    assert fetch.calls[-1][1] is None
    monkeypatch.setenv("GH_TOKEN", "gh")
    collect_branch_protection(store, "acme/widgets", fetch=fetch)
    assert fetch.calls[-1][1] == "gh"
    monkeypatch.setenv("GITHUB_TOKEN", "github")
    collect_branch_protection(store, "acme/widgets", fetch=fetch)
    assert fetch.calls[-1][1] == "github"
    collect_branch_protection(store, "acme/widgets", token="explicit", fetch=fetch)
    assert fetch.calls[-1][1] == "explicit"


def test_branch_name_is_url_encoded(store):
    seen = []

    def fetch(url, token):
        seen.append(url)
        if url == REPO_URL:
            return 200, {"default_branch": "release/2.0"}
        return 200, PROTECTED

    records = collect_branch_protection(store, "acme/widgets", fetch=fetch)
    assert seen[1] == "https://api.github.com/repos/acme/widgets/branches/release%2F2.0/protection"
    assert records[0].payload["branch"] == "release/2.0"


# -- through the CLI ------------------------------------------------------------

def test_cli_collect_github_appends_and_prints(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(gh, "_default_fetch", make_fetch((200, PROTECTED)))
    rc = main(["--data", str(tmp_path), "collect", "github", "--repo", "acme/widgets", "--token", "t"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "hint:" not in out
    assert "EV-0001  pr.review-required   pass" in out
    assert "EV-0002  ci.policy-gate       pass" in out
    assert len(EvidenceStore(tmp_path / "evidence.jsonl").all()) == 2
    assert main(["--data", str(tmp_path), "verify"]) == 0


def test_cli_collect_github_permission_error_exits_5_with_hint(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(gh, "gh_available", lambda: False)   # the hint only prints without the gh CLI
    monkeypatch.setattr(gh, "_default_fetch", make_fetch((403, {"message": "Must have admin rights to Repository."})))
    rc = main(["--data", str(tmp_path), "collect", "github", "--repo", "acme/widgets"])
    out = capsys.readouterr().out
    assert rc == 5
    assert "hint: no GitHub token found" in out
    assert "'repo'" in out and "Must have admin rights" in out
    assert EvidenceStore(tmp_path / "evidence.jsonl").all() == []


def test_cli_collect_github_repo_not_found_exits_1(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(gh, "_default_fetch", make_fetch((200, PROTECTED), repo=(404, {"message": "Not Found"})))
    rc = main(["--data", str(tmp_path), "collect", "github", "--repo", "acme/widgets", "--token", "t"])
    assert rc == 1
    assert "repo not found or not accessible" in capsys.readouterr().out



# ---- gh CLI fallback ---------------------------------------------------------
import subprocess as _sp  # noqa: E402

from attest.collectors import github as _gh  # noqa: E402


def _completed(rc, out="", err=""):
    return _sp.CompletedProcess(args=["gh"], returncode=rc, stdout=out, stderr=err)


def test_gh_fetch_success_and_http_error(monkeypatch):
    calls = []

    def fake_run(cmd, **kw):
        calls.append(cmd)
        if cmd[-1].endswith("/protection"):
            return _completed(1, "{\"message\": \"Branch not protected\"}", "gh: Branch not protected (HTTP 404)")
        return _completed(0, "{\"default_branch\": \"main\"}")
    monkeypatch.setattr(_gh.subprocess, "run", fake_run)
    assert _gh._gh_fetch(f"{_gh.API}/repos/o/r") == (200, {"default_branch": "main"})
    status, body = _gh._gh_fetch(f"{_gh.API}/repos/o/r/branches/main/protection")
    assert status == 404 and body["message"] == "Branch not protected"
    assert calls[0][:2] == ["gh", "api"] and calls[0][-1] == "repos/o/r"


def test_default_fetch_prefers_gh_when_no_token(monkeypatch):
    monkeypatch.setattr(_gh, "gh_available", lambda: True)
    monkeypatch.setattr(_gh, "_gh_fetch", lambda url: (200, {"via": "gh", "url": url}))
    monkeypatch.setattr(_gh.urllib.request, "urlopen", lambda *a, **k: (_ for _ in ()).throw(AssertionError("urllib must not be used")))
    assert _gh._default_fetch(f"{_gh.API}/repos/o/r", None)[1]["via"] == "gh"

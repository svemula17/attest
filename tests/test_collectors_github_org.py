"""Org-level GitHub collector over httpx.MockTransport (no network)."""
import re

import httpx
import pytest

from attest.audit import AuditLog
from attest.collectors import github as gh
from attest.collectors.github import collect, describe
from attest.collectors.registry import CollectContext
from attest.config import Config, SourceConfig
from attest.controls import ControlEngine, default_catalog
from attest.evidence import EvidenceStore

PROTECTED = {"required_pull_request_reviews": {"required_approving_review_count": 1},
             "required_status_checks": {"contexts": ["ci/test"], "checks": [{"context": "ci/test"}, {"context": "lint"}]}}
NO_CHECKS = {"required_pull_request_reviews": {"required_approving_review_count": 2}, "required_status_checks": {"contexts": []}}


def make_ctx(tmp_path, params, source_id="gh-org"):
    store = EvidenceStore(tmp_path / "data" / "evidence.jsonl")
    audit = AuditLog(tmp_path / "data" / "audit.jsonl")
    return CollectContext(store=store, audit=audit, source=SourceConfig(id=source_id, type="github", params=params), config=Config())


def repo(name, branch="main", protection=(200, PROTECTED), alerts=(200, []), pulls=(), archived=False):
    """pulls: list of (number, merged, review_states)."""
    return {"name": name, "branch": branch, "protection": protection, "alerts": alerts, "pulls": list(pulls), "archived": archived}


class FakeGitHub:
    """Routes api.github.com requests to canned per-repo answers; paginates the org listing."""

    def __init__(self, repos, org="acme", page_size=100, token="t0k"):
        self.repos = {r["name"]: r for r in repos}
        self.org, self.page_size, self.token = org, page_size, token
        self.calls: list[httpx.Request] = []
        self.rate_limit_on: str | None = None   # a path suffix that answers 403 + X-RateLimit-Remaining: 0
        self.unauthorized = False

    def transport(self):
        return httpx.MockTransport(self)

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(request)
        assert request.headers["Accept"] == "application/vnd.github+json"
        assert request.headers["X-GitHub-Api-Version"] == "2022-11-28"
        if self.unauthorized or request.headers.get("Authorization") != f"Bearer {self.token}":
            return httpx.Response(401, json={"message": "Bad credentials"}, request=request)
        path, q = request.url.path, dict(request.url.params)
        if self.rate_limit_on and path.endswith(self.rate_limit_on):
            return httpx.Response(403, json={"message": "API rate limit exceeded"}, request=request,
                                  headers={"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "1800000000"})
        if path == f"/orgs/{self.org}/repos":
            assert q["type"] == "all" and q["per_page"] == "100"
            page, items = int(q.get("page", 1)), list(self.repos.values())
            chunk = items[(page - 1) * self.page_size: page * self.page_size]
            headers = {}
            if page * self.page_size < len(items):
                headers["Link"] = f'<https://api.github.com/orgs/{self.org}/repos?type=all&per_page=100&page={page + 1}>; rel="next"'
            body = [{"full_name": r["name"], "default_branch": r["branch"], "archived": r["archived"]} for r in chunk]
            return httpx.Response(200, json=body, headers=headers, request=request)
        m = re.match(r"^/repos/([^/]+/[^/]+)(.*)$", path)
        if not m or m.group(1) not in self.repos:
            return httpx.Response(404, json={"message": "Not Found"}, request=request)
        r, rest = self.repos[m.group(1)], m.group(2)
        if rest == "":
            return httpx.Response(200, json={"default_branch": r["branch"]}, request=request)
        if rest == f"/branches/{r['branch']}/protection":
            status, body = r["protection"]
            return httpx.Response(status, json=body, request=request)
        if rest == "/secret-scanning/alerts":
            assert q["state"] == "open"
            status, body = r["alerts"]
            return httpx.Response(status, json=body if status == 200 else {"message": "Secret scanning is disabled on this repository."}, request=request)
        if rest == "/pulls":
            assert q["state"] == "closed" and q["sort"] == "updated" and q["direction"] == "desc"
            body = [{"number": n, "merged_at": "2026-09-01T00:00:00Z" if merged else None} for n, merged, _ in r["pulls"]]
            return httpx.Response(200, json=body[: int(q["per_page"])], request=request)
        pr = re.match(r"^/pulls/(\d+)/reviews$", rest)
        if pr:
            states = next(s for n, _, s in r["pulls"] if n == int(pr.group(1)))
            return httpx.Response(200, json=[{"state": s} for s in states], request=request)
        return httpx.Response(404, json={"message": f"unrouted {path}"}, request=request)


@pytest.fixture(autouse=True)
def token_env(monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GH_TOKEN", raising=False)
    monkeypatch.setenv("GH_PAT", "t0k")


def by_kind(store):
    return {r.kind: r for r in store.all()}


def test_healthy_org_all_four_pass_with_per_repo_detail(tmp_path):
    fake = FakeGitHub([
        repo("acme/widgets", pulls=[(1, True, ["COMMENTED", "APPROVED"]), (2, False, [])]),
        repo("acme/api", branch="develop", pulls=[(7, True, ["APPROVED"])]),
        repo("acme/old", archived=True, protection=(404, {})),
    ])
    ctx = make_ctx(tmp_path, {"org": "acme", "token_env": "GH_PAT"})
    out = collect(ctx, transport=fake.transport())
    assert out.records == 4
    assert out.summary == "github org acme: 2 repos, review 2/2, checks 2/2, secret scanning 2/2 (0 open), merges 2/2 reviewed"
    recs = by_kind(ctx.store)
    assert set(recs) == {"pr.review-required", "ci.policy-gate", "github.secret-scanning", "github.merge-log"}
    assert all(r.source == "github" and r.classification == "publishable" and r.payload["result"] == "pass" for r in recs.values())
    assert recs["pr.review-required"].payload["summary"] == "2/2 repos require review"
    assert recs["ci.policy-gate"].payload["summary"] == "2/2 repos require status checks"
    assert recs["github.secret-scanning"].payload["summary"] == "secret scanning enabled on 2/2 repos, 0 open alerts"
    assert recs["github.merge-log"].payload["summary"] == "2 of 2 sampled merges reviewed across 2 repos"
    # control ids come from the catalog, never guessed; the archived repo was skipped
    assert recs["pr.review-required"].control_ids == ["CTL-CHANGE-01"]
    assert recs["github.secret-scanning"].control_ids == ["CTL-CHANGE-02"]
    detail = {d["repo"]: d for d in recs["pr.review-required"].payload["repos"]}
    assert set(detail) == {"acme/widgets", "acme/api"}
    assert detail["acme/widgets"] == {"repo": "acme/widgets", "branch": "main", "protected": True, "review_count": 1,
                                      "checks": ["ci/test", "lint"], "secret_scanning": True, "alerts": 0, "merged": 1, "reviewed": 1}
    assert detail["acme/api"]["branch"] == "develop"
    assert recs["pr.review-required"].payload["collected_by"] == "gh-org"
    assert ctx.store.verify_chain()
    states = {r.control_id: r.state for r in ControlEngine(default_catalog(), ctx.store).evaluate()}
    assert states["CTL-CHANGE-01"] == "PASS" and states["CTL-CHANGE-02"] == "PASS"
    # the org listing used default_branch from the listing: no per-repo lookup
    assert not any(c.url.path in ("/repos/acme/widgets", "/repos/acme/api") for c in fake.calls)
    assert not any(c.url.path.startswith("/repos/acme/old") for c in fake.calls)


def test_org_listing_follows_link_pagination_and_max_repos(tmp_path):
    fake = FakeGitHub([repo(f"acme/r{i}") for i in range(5)], page_size=2)
    ctx = make_ctx(tmp_path, {"org": "acme", "token_env": "GH_PAT"})
    collect(ctx, transport=fake.transport())
    pages = [dict(c.url.params).get("page", "1") for c in fake.calls if c.url.path == "/orgs/acme/repos"]
    assert pages == ["1", "2", "3"]
    assert [d["repo"] for d in by_kind(ctx.store)["ci.policy-gate"].payload["repos"]] == [f"acme/r{i}" for i in range(5)]

    fake = FakeGitHub([repo(f"acme/r{i}") for i in range(5)], page_size=2)
    ctx = make_ctx(tmp_path / "capped", {"org": "acme", "token_env": "GH_PAT", "max_repos": 3})
    out = collect(ctx, transport=fake.transport())
    assert out.summary.startswith("github org acme: 3 repos")
    pages = [dict(c.url.params).get("page", "1") for c in fake.calls if c.url.path == "/orgs/acme/repos"]
    assert pages == ["1", "2"]  # stopped as soon as the cap was reached


def test_unprotected_repo_fails_review_and_checks_and_names_it(tmp_path):
    fake = FakeGitHub([
        repo("acme/widgets"),
        repo("acme/legacy", protection=(404, {"message": "Branch not protected"})),
        repo("acme/pro", protection=(403, {"message": "Upgrade to GitHub Pro or make this repository public to enable this feature."})),
        repo("acme/nochecks", protection=(200, NO_CHECKS)),
    ])
    ctx = make_ctx(tmp_path, {"org": "acme", "token_env": "GH_PAT"})
    collect(ctx, transport=fake.transport())
    recs = by_kind(ctx.store)
    review, ci = recs["pr.review-required"], recs["ci.policy-gate"]
    assert review.payload["result"] == "fail"
    assert review.payload["summary"] == "2/4 repos require review; unprotected: acme/legacy, acme/pro"
    assert ci.payload["result"] == "fail"
    assert ci.payload["summary"] == "1/4 repos require status checks; without checks: acme/legacy, acme/pro, acme/nochecks"
    detail = {d["repo"]: d for d in review.payload["repos"]}
    assert detail["acme/legacy"]["protected"] is False and detail["acme/pro"]["protected"] is False
    assert detail["acme/nochecks"] == {**detail["acme/nochecks"], "protected": True, "review_count": 2, "checks": []}
    assert {r.control_id: r.state for r in ControlEngine(default_catalog(), ctx.store).evaluate()}["CTL-CHANGE-01"] == "FAIL"


def test_secret_scanning_disabled_or_open_alerts_fails(tmp_path):
    fake = FakeGitHub([
        repo("acme/widgets", alerts=(200, [{"number": 1}, {"number": 2}])),
        repo("acme/off", alerts=(404, None)),
    ])
    ctx = make_ctx(tmp_path, {"org": "acme", "token_env": "GH_PAT"})
    out = collect(ctx, transport=fake.transport())
    rec = by_kind(ctx.store)["github.secret-scanning"]
    assert rec.payload["result"] == "fail"
    assert rec.payload["summary"] == "secret scanning enabled on 1/2 repos, 2 open alerts; secret scanning not enabled: acme/off"
    assert rec.payload["open_alerts"] == 2
    detail = {d["repo"]: d for d in rec.payload["repos"]}
    assert detail["acme/off"]["secret_scanning"] is False and detail["acme/off"]["alerts"] is None
    assert detail["acme/widgets"]["alerts"] == 2
    assert "secret scanning 1/2 (2 open)" in out.summary

    fake = FakeGitHub([repo("acme/widgets", alerts=(200, [{"number": 1}]))])
    ctx = make_ctx(tmp_path / "one", {"org": "acme", "token_env": "GH_PAT"})
    collect(ctx, transport=fake.transport())
    assert by_kind(ctx.store)["github.secret-scanning"].payload["summary"] == "secret scanning enabled on 1/1 repos, 1 open alert"


def test_merge_log_needs_95_percent_reviewed(tmp_path):
    pulls = [(n, True, ["APPROVED"]) for n in range(1, 10)] + [(10, True, ["COMMENTED"]), (11, False, ["APPROVED"])]
    fake = FakeGitHub([repo("acme/widgets", pulls=pulls)])
    ctx = make_ctx(tmp_path, {"org": "acme", "token_env": "GH_PAT"})
    collect(ctx, transport=fake.transport())
    rec = by_kind(ctx.store)["github.merge-log"]
    assert rec.payload["result"] == "fail"   # 9/10 = 90 % < 95 %
    assert rec.payload["summary"] == "9 of 10 sampled merges reviewed across 1 repos"
    assert rec.payload["repos"][0]["merged"] == 10 and rec.payload["repos"][0]["reviewed"] == 9
    assert rec.control_ids == []  # no catalog control requires github.merge-log yet — never guessed
    # only merged PRs had their reviews fetched
    review_calls = sorted(int(c.url.path.split("/")[-2]) for c in fake.calls if c.url.path.endswith("/reviews"))
    assert review_calls == list(range(1, 11))

    pulls = [(n, True, ["APPROVED"]) for n in range(1, 20)] + [(20, True, [])]
    fake = FakeGitHub([repo("acme/widgets", pulls=pulls)])
    ctx = make_ctx(tmp_path / "ok", {"org": "acme", "token_env": "GH_PAT"})
    collect(ctx, transport=fake.transport())
    assert by_kind(ctx.store)["github.merge-log"].payload["result"] == "pass"  # 19/20 = 95 %


def test_merge_sample_caps_the_pull_listing(tmp_path):
    pulls = [(n, True, ["APPROVED"]) for n in range(1, 31)]
    fake = FakeGitHub([repo("acme/widgets", pulls=pulls)])
    ctx = make_ctx(tmp_path, {"org": "acme", "token_env": "GH_PAT", "merge_sample": 5})
    collect(ctx, transport=fake.transport())
    listing = next(c for c in fake.calls if c.url.path.endswith("/pulls"))
    assert dict(listing.url.params)["per_page"] == "5"
    rec = by_kind(ctx.store)["github.merge-log"]
    assert rec.payload["summary"] == "5 of 5 sampled merges reviewed across 1 repos" and rec.payload["sample_per_repo"] == 5

    fake = FakeGitHub([repo("acme/quiet", pulls=[(1, False, [])])])
    ctx = make_ctx(tmp_path / "quiet", {"org": "acme", "token_env": "GH_PAT"})
    collect(ctx, transport=fake.transport())
    rec = by_kind(ctx.store)["github.merge-log"]
    assert rec.payload["result"] == "pass" and rec.payload["summary"].endswith("(no merged pull requests in the sample)")


def test_explicit_repos_list_looks_up_default_branch(tmp_path):
    fake = FakeGitHub([repo("acme/widgets"), repo("acme/api", branch="trunk"), repo("acme/unlisted")])
    ctx = make_ctx(tmp_path, {"repos": ["acme/widgets", "acme/api"], "token_env": "GH_PAT"})
    out = collect(ctx, transport=fake.transport())
    assert out.summary.startswith("github repos: 2 repos")
    assert [c.url.path for c in fake.calls][:2] == ["/repos/acme/widgets", "/repos/acme/widgets/branches/main/protection"]
    assert any(c.url.path == "/repos/acme/api/branches/trunk/protection" for c in fake.calls)
    assert not any(c.url.path.startswith("/orgs/") for c in fake.calls)
    rec = by_kind(ctx.store)["pr.review-required"]
    assert rec.payload["org"] is None and [d["repo"] for d in rec.payload["repos"]] == ["acme/widgets", "acme/api"]

    ctx = make_ctx(tmp_path / "single", {"repos": "acme/widgets", "token_env": "GH_PAT"})
    assert collect(ctx, transport=fake.transport()).summary.startswith("github repos: 1 repos")


def test_bad_targets_are_rejected_before_any_request(tmp_path):
    fake = FakeGitHub([repo("acme/widgets")])
    for params, msg in [({"token_env": "GH_PAT"}, "params.org or params.repos"),
                        ({"org": "acme", "repos": ["a/b"], "token_env": "GH_PAT"}, "alternatives"),
                        ({"repos": ["widgets"], "token_env": "GH_PAT"}, "owner/name"),
                        ({"org": "acme/widgets", "token_env": "GH_PAT"}, "organisation login")]:
        with pytest.raises(ValueError, match=msg):
            collect(make_ctx(tmp_path, params), transport=fake.transport())
    assert fake.calls == []
    with pytest.raises(ValueError, match="repo acme/missing not found"):
        collect(make_ctx(tmp_path, {"repos": ["acme/missing"], "token_env": "GH_PAT"}), transport=fake.transport())
    with pytest.raises(ValueError, match="org 'nope' not found"):
        collect(make_ctx(tmp_path, {"org": "nope", "token_env": "GH_PAT"}), transport=fake.transport())


def test_rate_limit_403_raises_naming_the_reset_time(tmp_path):
    fake = FakeGitHub([repo("acme/widgets"), repo("acme/api")])
    fake.rate_limit_on = "/secret-scanning/alerts"
    ctx = make_ctx(tmp_path, {"org": "acme", "token_env": "GH_PAT"})
    with pytest.raises(RuntimeError, match=r"rate limit exhausted; it resets at 2027-01-15T08:00:00Z"):
        collect(ctx, transport=fake.transport())
    assert ctx.store.all() == []  # nothing half-written


def test_401_raises_permission_error_naming_the_scopes(tmp_path):
    fake = FakeGitHub([repo("acme/widgets")])
    fake.unauthorized = True
    ctx = make_ctx(tmp_path, {"org": "acme", "token_env": "GH_PAT"})
    with pytest.raises(PermissionError) as exc:
        collect(ctx, transport=fake.transport())
    msg = str(exc.value)
    assert "401" in msg and "repo, security_events and read:org" in msg and "Bad credentials" in msg
    assert ctx.store.all() == []


def test_token_comes_from_token_env_then_the_environment(tmp_path, monkeypatch):
    fake = FakeGitHub([repo("acme/widgets")], token="from-env")
    monkeypatch.setenv("GITHUB_TOKEN", "from-env")
    collect(make_ctx(tmp_path, {"org": "acme"}), transport=fake.transport())  # no token_env: $GITHUB_TOKEN
    assert fake.calls[0].headers["Authorization"] == "Bearer from-env"
    # a named token_env that is unset is an error, not a silent fallback
    monkeypatch.delenv("GH_PAT")
    with pytest.raises(PermissionError, match="GH_PAT"):
        collect(make_ctx(tmp_path / "unset", {"org": "acme", "token_env": "GH_PAT"}), transport=fake.transport())
    monkeypatch.delenv("GITHUB_TOKEN")
    with pytest.raises(PermissionError, match="no GitHub token"):
        collect(make_ctx(tmp_path / "none", {"org": "acme"}), transport=fake.transport())


def test_describe_and_type():
    assert gh.TYPE == "github"
    d = describe()
    assert d["type"] == "github" and d["source"] == "github"
    assert d["kinds"] == ["pr.review-required", "ci.policy-gate", "github.secret-scanning", "github.merge-log"]
    assert set(d["params"]) == {"org", "repos", "token_env", "max_repos", "merge_sample"}
    assert d["secrets"] == ["token_env"] and "security_events" in d["permissions"]

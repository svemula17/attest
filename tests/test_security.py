"""Request hardening on a tiny FastAPI app: headers, token-bucket rate limits, origin check."""
from __future__ import annotations

import threading

import pytest
from fastapi import FastAPI, Request, Response
from fastapi.testclient import TestClient

from attest.config import parse_config
from attest.security import (CSP, DOCS_CSP, SESSION_COOKIE, OriginCheckMiddleware, RateLimiter, allowed_origins, install,
                             origin_of)

BASE = "http://attest.example.com"
FOREIGN = "https://evil.example"


class Clock:
    def __init__(self, t: float = 1000.0):
        self.t = t

    def __call__(self) -> float:
        return self.t


def config(extra: str = "", api_rate: int = 5) -> "Config":
    return parse_config(f'''
[server]
base_url = "{BASE}"
[security]
login_rate_per_minute = 3
api_rate_per_minute = {api_rate}
{extra}
''')


def make_app(cfg, clock=None) -> FastAPI:
    app = FastAPI(docs_url="/docs", redoc_url="/redoc")

    @app.post("/api/auth/login")
    def login(response: Response):
        response.set_cookie(SESSION_COOKIE, "tok")
        return {"ok": True}

    @app.post("/api/auth/impersonate")
    def impersonate(response: Response):
        response.set_cookie(SESSION_COOKIE, "tok")
        return {"ok": True}

    @app.get("/api/thing")
    def get_thing():
        return {"thing": 1}

    @app.post("/api/thing")
    def post_thing():
        return {"changed": True}

    @app.delete("/api/thing/{i}")
    def del_thing(i: int):
        return {"deleted": i}

    @app.get("/api/who")
    def who(request: Request):
        return {"ip": request.client.host if request.client else None}

    @app.get("/")
    def page():
        return Response("<html>hi</html>", media_type="text/html")

    install(app, cfg, clock=clock or Clock())
    return app


COOKIE = {"Cookie": f"{SESSION_COOKIE}=tok"}


@pytest.fixture
def client():
    """Generous API limit: these tests are about headers and origins, not buckets."""
    with TestClient(make_app(config(api_rate=1000))) as c:
        yield c


# ---- headers ---------------------------------------------------------------------
def test_security_headers_on_every_response(client):
    for path in ("/", "/api/thing", "/nope"):
        h = client.get(path).headers
        assert h["x-content-type-options"] == "nosniff"
        assert h["referrer-policy"] == "strict-origin-when-cross-origin"
        assert h["x-frame-options"] == "DENY"
        assert h["permissions-policy"] == "camera=(), microphone=(), geolocation=()"
        assert h["content-security-policy"] == CSP
        assert "strict-transport-security" not in h


def test_csp_matches_the_spec_and_docs_get_the_cdn_variant(client):
    assert CSP == ("default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' "
                   "https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; "
                   "connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
    r = client.get("/docs")
    assert r.status_code == 200 and r.headers["content-security-policy"] == DOCS_CSP
    assert "cdn.jsdelivr.net" in DOCS_CSP and "frame-ancestors 'none'" in DOCS_CSP
    assert client.get("/openapi.json").headers["content-security-policy"] == CSP


def test_hsts_only_when_configured():
    with TestClient(make_app(config("hsts = true"))) as c:
        assert c.get("/").headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"


def test_headers_wrap_rate_limit_and_origin_responses():
    with TestClient(make_app(config())) as c:
        r = c.post("/api/thing", headers={**COOKIE, "Origin": FOREIGN})
        assert r.status_code == 403 and r.headers["x-frame-options"] == "DENY"
        for _ in range(5):
            c.get("/api/thing")
        r = c.get("/api/thing")
        assert r.status_code == 429 and r.headers["content-security-policy"] == CSP


def test_session_cookie_name_matches_the_api():
    from attest.api import COOKIE
    assert SESSION_COOKIE == COOKIE


# ---- rate limiter unit --------------------------------------------------------------
def test_token_bucket_refills_at_the_configured_rate():
    clock = Clock()
    rl = RateLimiter(per_minute=60, clock=clock)           # 1 token/second, burst 60
    assert all(rl.allow("k")[0] for _ in range(60))
    allowed, wait = rl.allow("k")
    assert not allowed and 0 < wait <= 1.0
    clock.t += 0.5
    assert rl.allow("k")[0] is False
    clock.t += 0.5
    assert rl.allow("k") == (True, 0.0)
    clock.t += 120                                          # capped at capacity, never above
    assert sum(rl.allow("k")[0] for _ in range(61)) == 60


def test_buckets_are_independent_and_disabled_when_zero():
    rl = RateLimiter(per_minute=1, clock=Clock())
    assert rl.allow("a")[0] and not rl.allow("a")[0] and rl.allow("b")[0]
    off = RateLimiter(per_minute=0)
    assert not off.enabled and all(off.allow("x")[0] for _ in range(1000))


def test_bucket_table_prunes_refilled_keys():
    clock = Clock()
    rl = RateLimiter(per_minute=60, clock=clock, max_keys=10)
    for i in range(11):
        rl.allow(f"k{i}")
    assert len(rl) == 11                                     # nothing has refilled yet
    clock.t += 61
    rl.allow("fresh")
    assert len(rl) == 1                                      # the idle ones were dropped


def test_rate_limiter_is_thread_safe():
    rl = RateLimiter(per_minute=1000, clock=Clock())
    hits = []

    def worker():
        hits.extend(rl.allow("shared")[0] for _ in range(100))

    threads = [threading.Thread(target=worker) for _ in range(20)]
    for t in threads: t.start()
    for t in threads: t.join()
    assert sum(hits) == 1000 and len(hits) == 2000           # exactly the capacity got through


# ---- rate limit middleware ---------------------------------------------------------------
def test_login_limited_per_ip_with_retry_after():
    clock = Clock()
    with TestClient(make_app(config(), clock=clock)) as c:
        for _ in range(3):
            assert c.post("/api/auth/login", headers={"Origin": BASE}).status_code == 200
        r = c.post("/api/auth/login", headers={"Origin": BASE})
        assert r.status_code == 429 and r.json() == {"error": "rate limited"}
        assert int(r.headers["retry-after"]) >= 1
        clock.t += 20                                        # 3/min → one token every 20 s
        assert c.post("/api/auth/login", headers={"Origin": BASE}).status_code == 200
        assert c.get("/api/thing").status_code == 200        # the API bucket is separate


def test_api_limited_per_identity_then_ip():
    with TestClient(make_app(config())) as c:
        for _ in range(5):
            assert c.get("/api/thing", headers={"Authorization": "Bearer atst_a"}).status_code == 200
        assert c.get("/api/thing", headers={"Authorization": "Bearer atst_a"}).status_code == 429
        assert c.get("/api/thing", headers={"Authorization": "Bearer atst_b"}).status_code == 200   # another key
        for _ in range(5):
            assert c.get("/api/thing", headers={"Cookie": f"{SESSION_COOKIE}=s1"}).status_code == 200
        assert c.get("/api/thing", headers={"Cookie": f"{SESSION_COOKIE}=s1"}).status_code == 429
        assert c.get("/api/thing", headers={"Cookie": f"{SESSION_COOKIE}=s2"}).status_code == 200    # another session
        for _ in range(5):
            assert c.get("/api/thing").status_code == 200                                            # anonymous: by IP
        assert c.get("/api/thing").status_code == 429
        assert c.get("/").status_code == 200                                                         # pages are not limited


def test_x_forwarded_for_is_ignored():
    with TestClient(make_app(config())) as c:
        for i in range(5):
            assert c.get("/api/thing", headers={"X-Forwarded-For": f"10.0.0.{i}"}).status_code == 200
        assert c.get("/api/thing", headers={"X-Forwarded-For": "10.0.0.99"}).status_code == 429


# ---- origin check ---------------------------------------------------------------------------
def test_origin_of_normalises():
    assert origin_of("https://Attest.Example.com:8443/path?q=1") == "https://attest.example.com:8443"
    assert origin_of("http://127.0.0.1:8765") == "http://127.0.0.1:8765"
    assert origin_of("null") is None and origin_of("") is None and origin_of(None) is None and origin_of("garbage") is None
    cfg = config('allowed_origins = ["https://console.example.com/"]')
    assert allowed_origins(cfg) == {"http://attest.example.com", "https://console.example.com"}


def test_cookie_requests_need_a_matching_origin(client):
    assert client.post("/api/thing", headers={**COOKIE, "Origin": BASE}).status_code == 200
    assert client.post("/api/thing", headers={**COOKIE, "Origin": BASE.upper()}).status_code == 200
    r = client.post("/api/thing", headers={**COOKIE, "Origin": FOREIGN})
    assert r.status_code == 403 and r.json() == {"error": "cross-origin request refused"}
    assert client.delete("/api/thing/1", headers={**COOKIE, "Origin": FOREIGN}).status_code == 403
    assert client.post("/api/thing", headers={**COOKIE, "Origin": "null"}).status_code == 200  # opaque → absent
    # Referer is the fallback when Origin is missing
    assert client.post("/api/thing", headers={**COOKIE, "Referer": f"{BASE}/"}).status_code == 200
    assert client.post("/api/thing", headers={**COOKIE, "Referer": f"{FOREIGN}/page"}).status_code == 403
    # Origin wins over Referer when both are present
    assert client.post("/api/thing", headers={**COOKIE, "Origin": FOREIGN, "Referer": f"{BASE}/"}).status_code == 403


def test_non_browser_clients_pass_through(client):
    assert client.post("/api/thing", headers=COOKIE).status_code == 200                            # cookie, no origin at all
    assert client.post("/api/thing", headers={"Authorization": "Bearer atst_x"}).status_code == 200
    assert client.post("/api/thing", headers={"Authorization": "Bearer atst_x", "Origin": FOREIGN}).status_code == 200
    assert client.post("/api/thing").status_code == 200                                            # neither cookie nor origin
    assert client.post("/api/thing", headers={"Origin": FOREIGN}).status_code == 200               # no cookie to ride
    assert client.get("/api/thing", headers={**COOKIE, "Origin": FOREIGN}).status_code == 200      # safe method


def test_allowed_origins_extend_base_url():
    with TestClient(make_app(config('allowed_origins = ["https://console.example.com"]'))) as c:
        assert c.post("/api/thing", headers={**COOKIE, "Origin": "https://console.example.com"}).status_code == 200
        assert c.post("/api/thing", headers={**COOKIE, "Origin": FOREIGN}).status_code == 403


def test_cookie_setting_endpoints_are_checked_when_an_origin_is_present(client):
    for path in ("/api/auth/login", "/api/auth/impersonate"):
        assert client.post(path, headers={"Origin": FOREIGN}).status_code == 403
        assert client.post(path, headers={"Referer": f"{FOREIGN}/login"}).status_code == 403
        assert client.post(path, headers={"Origin": BASE}).status_code == 200
    assert client.post("/api/auth/impersonate").status_code == 200                                # curl: no origin, fine


def test_origin_check_does_not_touch_non_api_paths():
    cfg = config()
    mw = OriginCheckMiddleware(None, allowed_origins(cfg))
    from starlette.datastructures import Headers
    scope = {"type": "http", "method": "POST", "path": "/login"}
    assert mw.verdict(scope, Headers({"cookie": f"{SESSION_COOKIE}=x", "origin": FOREIGN}))
    scope["path"] = "/api/x"
    assert not mw.verdict(scope, Headers({"cookie": f"{SESSION_COOKIE}=x", "origin": FOREIGN}))


# ---- install() ------------------------------------------------------------------------------
def test_install_orders_headers_outermost():
    app = FastAPI()
    install(app, config())
    names = [m.cls.__name__ for m in app.user_middleware]
    assert names == ["SecurityHeadersMiddleware", "RateLimitMiddleware", "OriginCheckMiddleware"]


def test_real_app_carries_the_hardening(tmp_path):
    """create_app() installs attest.security; the console flow still works from the site's own origin."""
    from attest.api import create_app
    from attest.config import default_config_toml
    cfg_path = tmp_path / "attest.toml"
    cfg_path.write_text(default_config_toml(mode="sandbox", storage_url=f"sqlite:///{tmp_path / 'attest.db'}"))
    cfg = parse_config(cfg_path.read_text(), path=cfg_path)
    with TestClient(create_app(cfg)) as c:
        assert c.get("/api/health").headers["content-security-policy"] == CSP
        r = c.post("/api/auth/login", json={"email": "s.vemula@attest.internal", "password": "attest"}, headers={"Origin": cfg.server.base_url})
        assert r.status_code == 200
        assert c.post("/api/evaluate", headers={"Origin": "https://evil.example"}).status_code == 403
        assert c.post("/api/evaluate", headers={"Origin": cfg.server.base_url}).status_code == 200

"""attest.security — request hardening for the HTTP surface.

    from attest.security import install
    install(app, cfg)        # once, right after create_app(), before the first request

Three pure-ASGI middlewares, outermost first:

* **SecurityHeaders** — nosniff, referrer policy, frame denial, permissions policy, a
  Content-Security-Policy sized for the console (one HTML file with inline script and
  style plus Google Fonts) and, when ``[security] hsts = true``, HSTS. ``/docs`` and
  ``/redoc`` get the same policy widened to the CDN Swagger UI loads from.
* **RateLimit** — token buckets, one per key. ``POST /api/auth/login`` is keyed by client
  IP at ``login_rate_per_minute``; every other ``/api/*`` request by the Authorization
  header, else the session cookie, else the client IP, at ``api_rate_per_minute``.
  Buckets live in this process's memory: run several workers and each has its own.
  ``X-Forwarded-For`` is ignored — there is no trusted-proxy setting, so behind a proxy
  the IP-keyed limits apply to the proxy's address.
* **OriginCheck** — cross-site request forgery. A state-changing ``/api/*`` request that
  rides the session cookie (and carries no Authorization header) must come from
  ``server.base_url`` or one of ``allowed_origins``, judged by ``Origin`` and, failing
  that, the ``Referer``. Bearer requests are not cookie-authenticated and pass through.
"""
from __future__ import annotations

import hashlib
import math
import threading
import time
from typing import Callable
from urllib.parse import urlsplit

from starlette.datastructures import Headers, MutableHeaders
from starlette.responses import JSONResponse

from attest.config import Config

__all__ = ["install", "SecurityHeadersMiddleware", "RateLimitMiddleware", "OriginCheckMiddleware",
           "RateLimiter", "SESSION_COOKIE", "CSP", "DOCS_CSP", "origin_of"]

SESSION_COOKIE = "attest_session"           # mirrors attest.api.COOKIE (tested)
LOGIN_PATH = "/api/auth/login"
COOKIE_SETTING_PATHS = frozenset({"/api/auth/login", "/api/auth/impersonate"})
UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
API_PREFIX = "/api/"

CSP = ("default-src 'self'; script-src 'self' 'unsafe-inline'; "
       "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; "
       "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
# FastAPI's /docs and /redoc pull Swagger UI / ReDoc from jsDelivr and their favicon from fastapi.tiangolo.com.
DOCS_CSP = ("default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
            "font-src https://fonts.gstatic.com https://cdn.jsdelivr.net; "
            "img-src 'self' data: https://cdn.jsdelivr.net https://fastapi.tiangolo.com; connect-src 'self'; "
            "frame-ancestors 'none'; base-uri 'self'; form-action 'self'; worker-src blob:")
DOCS_PATHS = frozenset({"/docs", "/redoc", "/docs/oauth2-redirect"})
HSTS = "max-age=31536000; includeSubDomains"

STATIC_HEADERS = (
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "strict-origin-when-cross-origin"),
    ("X-Frame-Options", "DENY"),
    ("Permissions-Policy", "camera=(), microphone=(), geolocation=()"),
)


# ---- helpers ----------------------------------------------------------------------
def origin_of(url: str | None) -> str | None:
    """``scheme://host[:port]`` of a URL or Origin header, lower-cased; None when there is none."""
    if not url:
        return None
    value = url.strip()
    if value.lower() == "null":
        return None
    parts = urlsplit(value if "//" in value else f"//{value}")
    if not parts.scheme or not parts.netloc:
        return None
    return f"{parts.scheme.lower()}://{parts.netloc.lower()}"


def allowed_origins(cfg: Config) -> frozenset[str]:
    origins = {origin_of(cfg.server.base_url)} | {origin_of(o) for o in cfg.security.allowed_origins}
    return frozenset(o for o in origins if o)


def _client_ip(scope) -> str:
    client = scope.get("client")
    return str(client[0]) if client else "unknown"


def _cookie(headers: Headers, name: str) -> str | None:
    raw = headers.get("cookie")
    if not raw:
        return None
    for part in raw.split(";"):
        key, _, value = part.strip().partition("=")
        if key == name and value:
            return value
    return None


# ---- 1. security headers ------------------------------------------------------------
class SecurityHeadersMiddleware:
    def __init__(self, app, hsts: bool = False):
        self.app = app
        self.hsts = hsts

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        csp = DOCS_CSP if scope.get("path") in DOCS_PATHS else CSP
        hsts = self.hsts

        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                for name, value in STATIC_HEADERS:
                    headers[name] = value
                headers["Content-Security-Policy"] = csp
                if hsts:
                    headers["Strict-Transport-Security"] = HSTS
            await send(message)

        await self.app(scope, receive, send_with_headers)


# ---- 2. rate limiting -------------------------------------------------------------------
class RateLimiter:
    """Token bucket per key: ``per_minute`` capacity, refilled continuously at that rate.

    Thread-safe; the clock is monotonic by default and injectable for tests. Buckets
    that have fully refilled are dropped whenever the table grows past ``max_keys`` so
    memory stays bounded by the number of *active* keys. ``per_minute <= 0`` disables it.
    """

    def __init__(self, per_minute: int, clock: Callable[[], float] = time.monotonic, max_keys: int = 10_000):
        self.capacity = float(per_minute)
        self.rate = per_minute / 60.0
        self.clock = clock
        self.max_keys = max_keys
        self._buckets: dict[str, tuple[float, float]] = {}   # key -> (tokens, last update)
        self._lock = threading.Lock()

    @property
    def enabled(self) -> bool:
        return self.capacity > 0

    def allow(self, key: str) -> tuple[bool, float]:
        """(allowed, seconds until one token is available — 0.0 when allowed)."""
        if not self.enabled:
            return True, 0.0
        now = self.clock()
        with self._lock:
            tokens, updated = self._buckets.get(key, (self.capacity, now))
            tokens = min(self.capacity, tokens + max(0.0, now - updated) * self.rate)
            if tokens >= 1.0:
                self._buckets[key] = (tokens - 1.0, now)
                allowed, wait = True, 0.0
            else:
                self._buckets[key] = (tokens, now)
                allowed, wait = False, (1.0 - tokens) / self.rate
            if len(self._buckets) > self.max_keys:
                self._prune(now)
        return allowed, wait

    def _prune(self, now: float) -> None:
        full_after = self.capacity / self.rate  # seconds an idle bucket needs to refill completely
        for key, (tokens, updated) in list(self._buckets.items()):
            if now - updated >= full_after:
                del self._buckets[key]

    def __len__(self) -> int:
        return len(self._buckets)


class RateLimitMiddleware:
    def __init__(self, app, login_per_minute: int, api_per_minute: int, cookie_name: str = SESSION_COOKIE,
                 clock: Callable[[], float] = time.monotonic):
        self.app = app
        self.cookie_name = cookie_name
        self.login = RateLimiter(login_per_minute, clock=clock)
        self.api = RateLimiter(api_per_minute, clock=clock)

    @staticmethod
    def _digest(value: str) -> str:  # never keep a bearer key or cookie in memory as-is
        return hashlib.sha256(value.encode("utf-8")).hexdigest()[:32]

    def _bucket_and_key(self, scope, headers: Headers) -> tuple[RateLimiter, str]:
        if scope["method"] == "POST" and scope["path"] == LOGIN_PATH:
            return self.login, f"login:{_client_ip(scope)}"
        auth = headers.get("authorization")
        if auth:
            return self.api, f"auth:{self._digest(auth)}"
        cookie = _cookie(headers, self.cookie_name)
        if cookie:
            return self.api, f"cookie:{self._digest(cookie)}"
        return self.api, f"ip:{_client_ip(scope)}"

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or not scope.get("path", "").startswith(API_PREFIX):
            await self.app(scope, receive, send)
            return
        limiter, key = self._bucket_and_key(scope, Headers(scope=scope))
        allowed, wait = limiter.allow(key)
        if allowed:
            await self.app(scope, receive, send)
            return
        retry_after = max(1, math.ceil(wait))
        response = JSONResponse({"error": "rate limited"}, status_code=429, headers={"Retry-After": str(retry_after)})
        await response(scope, receive, send)


# ---- 3. origin check (CSRF) -----------------------------------------------------------------

def self_origin(scope, headers: Headers) -> str | None:
    """The origin this request was addressed to — a same-origin POST always matches it."""
    host = headers.get("host")
    if not host:
        return None
    scheme = headers.get("x-forwarded-proto") or scope.get("scheme") or "http"
    return f"{scheme}://{host}".lower()


class OriginCheckMiddleware:
    """Refuse cookie-authenticated state changes that did not originate from this site.

    Applies to POST/PUT/PATCH/DELETE under ``/api/``. The request's origin is the
    ``Origin`` header, else the origin of ``Referer``; ``Origin: null`` counts as absent.

    * Authorization header present → not cookie-authenticated, pass through.
    * Session cookie present → the origin must be allowed. A request that carries neither
      Origin nor Referer passes: browsers attach Origin to every cross-site POST/PUT/PATCH/
      DELETE, so a cookie-bearing request with no origin at all did not come from another
      site's page — it came from a non-browser client (a test client, a script) that holds
      the cookie legitimately.
    * The cookie-setting endpoints (login, impersonate) have no cookie yet but are still
      checked whenever an origin is present, so a foreign page cannot log the victim in.
    """

    def __init__(self, app, allowed: frozenset[str], cookie_name: str = SESSION_COOKIE):
        self.app = app
        self.allowed = allowed
        self.cookie_name = cookie_name

    def verdict(self, scope, headers: Headers) -> bool:
        """True when the request may proceed."""
        if scope["method"] not in UNSAFE_METHODS or not scope.get("path", "").startswith(API_PREFIX):
            return True
        if headers.get("authorization"):
            return True
        origin = origin_of(headers.get("origin")) or origin_of(headers.get("referer"))
        has_cookie = _cookie(headers, self.cookie_name) is not None
        if has_cookie or scope["path"] in COOKIE_SETTING_PATHS:
            return origin is None or origin in self.allowed or origin == self_origin(scope, headers)
        return True

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or self.verdict(scope, Headers(scope=scope)):
            await self.app(scope, receive, send)
            return
        response = JSONResponse({"error": "cross-origin request refused"}, status_code=403)
        await response(scope, receive, send)


# ---- install --------------------------------------------------------------------------------
def install(app, cfg: Config, *, cookie_name: str = SESSION_COOKIE, clock: Callable[[], float] = time.monotonic) -> None:
    """Add the three middlewares to a FastAPI/Starlette app, headers outermost.

    Starlette wraps the most recently added middleware around all earlier ones, so they
    are added inner-first: origin check, rate limit, then headers — which is why a 429 or
    a 403 from the inner layers still carries the security headers.
    """
    app.add_middleware(OriginCheckMiddleware, allowed=allowed_origins(cfg), cookie_name=cookie_name)
    app.add_middleware(RateLimitMiddleware, login_per_minute=cfg.security.login_rate_per_minute,
                       api_per_minute=cfg.security.api_rate_per_minute, cookie_name=cookie_name, clock=clock)
    app.add_middleware(SecurityHeadersMiddleware, hsts=cfg.security.hsts)

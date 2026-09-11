"""attest.api — the HTTP surface: FastAPI, typed, documented at /docs.

    attest serve            # reads attest.toml, runs migrations, starts the scheduler
Identity: `Authorization: Bearer atst_…` (API keys) or the session cookie set by
POST /api/auth/login. Sandbox mode signs anonymous browsers in as the demo
engineer so the console works out of the box; production returns 401.
"""
from __future__ import annotations

import hmac
import tempfile
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, Response, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field

from attest import auth as A
from attest.auth import AuthError, Identity
from attest.config import Config, load_config
from attest.db import get_engine, upgrade
from attest.guardrails import GuardrailViolation
from attest.importers import ImportProblem
from attest.scheduler import Scheduler
from attest.service import Forbidden, Service

ROOT = Path(__file__).resolve().parent.parent
PAGE = ROOT / "dashboard" / "app.html"
LOGIN = ROOT / "dashboard" / "login.html"
COOKIE = "attest_session"
DEMO_USERS = {  # sandbox only: created by `attest init --sandbox`, password "attest"
    "s.vemula@attest.internal": ("Security engineer", "engineer"),
    "j.okafor@auditfirm.example": ("External auditor", "auditor"),
    "vendor-portal@attest.internal": ("Vendor portal (service)", "service"),
}


# ---- request models ----------------------------------------------------------
class LoginIn(BaseModel):
    email: str
    password: str

class AnswerIn(BaseModel):
    question: str = Field(min_length=1)
    control_ids: list[str] = []
    llm: bool = False

class DecideIn(BaseModel):
    question_id: str
    decision: str

class ReadDocIn(BaseModel):
    doc_id: str | None = None
    text: str | None = None
    example: str | None = None
    tools: list[str] | None = None

class AcceptanceIn(BaseModel):
    control_id: str
    owner: str
    reason: str
    expires: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}$")

class KeyIn(BaseModel):
    email: str
    name: str

class PackageIn(BaseModel):
    framework: str | None = None
    since: str | None = Field(default=None, pattern=r"^\d{4}-\d{2}-\d{2}$")
    include_restricted: bool = False

class UserIn(BaseModel):
    email: str
    role: str
    name: str = ""
    password: str | None = None


def create_app(cfg: Config | None = None) -> FastAPI:
    cfg = cfg or load_config()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        upgrade(cfg.storage.url)
        engine = get_engine(cfg.storage.url)
        service = Service(cfg, engine)
        if cfg.sandbox:
            ensure_demo_users(engine)
            if service.store.count() == 0:
                service.reseed()
        scheduler = Scheduler(cfg, runner=lambda sid, trig: service.run_source(sid, A.SYSTEM, trig))
        scheduler.start()
        app.state.engine, app.state.service, app.state.scheduler = engine, service, scheduler
        app.state.codec = A.SessionCodec(cfg.auth.session_secret or "sandbox-only-secret", cfg.auth.session_hours)
        try:
            yield
        finally:
            scheduler.stop()

    app = FastAPI(title="Attest", version="0.3.0", lifespan=lifespan,
                  description="Continuous compliance control plane with a governed agent layer.")
    try:  # request hardening: security headers, rate limits, origin check (attest/security.py)
        from attest.security import install as install_security
        install_security(app, cfg)
    except ImportError:
        pass
    exports_dir = cfg.resolve("exports")

    # ---- identity ------------------------------------------------------------
    def identity(request: Request) -> Identity:
        engine = request.app.state.engine
        header = request.headers.get("authorization", "")
        if header.lower().startswith("bearer "):
            return A.authenticate_api_key(engine, header[7:].strip())
        token = request.cookies.get(COOKIE)
        if token:
            return request.app.state.codec.resolve(engine, token)
        if cfg.sandbox:
            return demo_identity(engine, "s.vemula@attest.internal")
        raise AuthError("sign in or pass an API key")

    def svc(request: Request) -> Service:
        return request.app.state.service

    # ---- error mapping ---------------------------------------------------------
    @app.exception_handler(AuthError)
    async def _auth(request: Request, e: AuthError):
        return JSONResponse({"error": str(e)}, status_code=e.status)

    @app.exception_handler(Forbidden)
    async def _forbidden(request: Request, e: Forbidden):
        body = {"error": str(e)}
        try:  # the console re-renders from this so the denial shows up in the feed
            body["state"] = svc(request).state(identity(request))
        except Exception:
            pass
        return JSONResponse(body, status_code=403)

    @app.exception_handler(GuardrailViolation)
    async def _guardrail(request: Request, e: GuardrailViolation):
        return JSONResponse({"error": str(e), "rule": e.rule}, status_code=403)

    @app.exception_handler(ImportProblem)
    async def _import(request: Request, e: ImportProblem):
        return JSONResponse({"error": str(e), "problems": getattr(e, "problems", [])}, status_code=422)

    @app.exception_handler(ValueError)
    async def _value(request: Request, e: ValueError):
        return JSONResponse({"error": str(e)}, status_code=400)

    # ---- pages -----------------------------------------------------------------
    @app.get("/", include_in_schema=False)
    def page(request: Request):
        try:
            identity(request)
        except AuthError:
            return FileResponse(LOGIN, media_type="text/html")
        return FileResponse(PAGE, media_type="text/html")

    @app.get("/login", include_in_schema=False)
    def login_page():
        return FileResponse(LOGIN, media_type="text/html")

    @app.get("/api/health")
    def health(request: Request):
        s = svc(request)
        return {"ok": True, "mode": cfg.server.mode, "evidence": s.store.count(), "chain_intact": s.store.verify_chain(),
                "jobs": request.app.state.scheduler.jobs()}

    # ---- auth --------------------------------------------------------------------
    @app.post("/api/auth/login")
    def do_login(body: LoginIn, request: Request, response: Response):
        ident = A.login(request.app.state.engine, body.email, body.password)
        response.set_cookie(COOKIE, request.app.state.codec.issue(ident), httponly=True, samesite="lax",
                            secure=cfg.server.base_url.startswith("https"), max_age=cfg.auth.session_hours * 3600)
        svc(request).audit.record(actor=ident.email, action="auth.login", subject=ident.email, detail=f"role={ident.role}")
        return {"user": ident.email, "role": ident.role, "grants": sorted(ident.grants)}

    @app.get("/api/auth/methods")
    def auth_methods():
        oidc = cfg.auth.oidc
        return {"password": True, "oidc": bool(oidc), "oidc_issuer": oidc.issuer if oidc else None}

    if cfg.auth.oidc:
        OIDC_COOKIE = "attest_oidc"

        def _oidc(request: Request):
            from attest.oidc import OIDC
            return OIDC(cfg.auth.oidc, redirect_uri=f"{cfg.server.base_url.rstrip('/')}/api/auth/oidc/callback")

        @app.get("/api/auth/oidc/start")
        def oidc_start(request: Request):
            from fastapi.responses import RedirectResponse
            flow = _oidc(request).start()
            resp = RedirectResponse(flow["url"], status_code=302)
            resp.set_cookie(OIDC_COOKIE, request.app.state.codec.sign({"state": flow["state"], "nonce": flow["nonce"], "verifier": flow["code_verifier"]}),
                            httponly=True, samesite="lax", max_age=600, secure=cfg.server.base_url.startswith("https"))
            return resp

        @app.get("/api/auth/oidc/callback")
        def oidc_callback(request: Request, code: str, state: str):
            from fastapi.responses import RedirectResponse
            from attest.oidc import OIDCError
            token = request.cookies.get(OIDC_COOKIE)
            if not token:
                raise AuthError("sign-in session expired — start again")
            flow = request.app.state.codec.unsign(token, max_age=600)
            if not hmac.compare_digest(flow.get("state", ""), state):
                raise AuthError("state mismatch")
            oidc = _oidc(request)
            try:
                claims = oidc.finish(code, flow["verifier"], flow["nonce"])
                email = oidc.check_email(claims)
            except OIDCError as e:
                raise AuthError(f"sign-in refused: {e}") from e
            engine = request.app.state.engine
            role = oidc.role_for(claims)
            existing = {u["email"]: u for u in A.list_users(engine)}
            if email not in existing:
                A.create_user(engine, email, role, name=str(claims.get("name") or ""))
                svc(request).audit.record(actor=email, action="user.created", subject=email, detail=f"oidc first login · role={role}")
            elif cfg.auth.oidc.role_claim and existing[email]["role"] != role:
                A.set_user_role(engine, email, role)
                svc(request).audit.record(actor=email, action="user.role", subject=email, detail=f"oidc claim → {role}")
            ident = A.identity_for_email(engine, email, via="oidc")
            resp = RedirectResponse("/", status_code=302)
            resp.delete_cookie(OIDC_COOKIE)
            resp.set_cookie(COOKIE, request.app.state.codec.issue(ident), httponly=True, samesite="lax",
                            secure=cfg.server.base_url.startswith("https"), max_age=cfg.auth.session_hours * 3600)
            svc(request).audit.record(actor=ident.email, action="auth.login", subject=ident.email, detail=f"role={ident.role} via oidc")
            return resp

    @app.post("/api/auth/logout")
    def do_logout(response: Response):
        response.delete_cookie(COOKIE)
        return {"ok": True}

    @app.get("/api/auth/me")
    def me(ident: Identity = Depends(identity)):
        return {"user": ident.email, "name": ident.name, "role": ident.role, "grants": sorted(ident.grants), "via": ident.via}

    # ---- console read model ------------------------------------------------------
    @app.get("/api/state")
    def state(request: Request, ident: Identity = Depends(identity)):
        return svc(request).state(ident)

    # ---- agent + human actions ---------------------------------------------------
    @app.post("/api/answer")
    def answer(body: AnswerIn, request: Request, ident: Identity = Depends(identity)):
        s = svc(request)
        s.answer(ident, body.question, body.control_ids, llm=body.llm)
        return s.state(ident)

    @app.post("/api/decide")
    def decide(body: DecideIn, request: Request, ident: Identity = Depends(identity)):
        s = svc(request)
        s.decide(ident, body.question_id, body.decision)
        return s.state(ident)

    @app.post("/api/read-doc")
    def read_doc(body: ReadDocIn, request: Request, ident: Identity = Depends(identity)):
        s = svc(request)
        text, doc_id = body.text, body.doc_id
        if body.example:
            name = {"injected": "vendor-soc2-excerpt.txt", "clean": "vendor-clean-excerpt.txt"}.get(body.example)
            if not name:
                raise ValueError("example must be 'injected' or 'clean'")
            text = (ROOT / "examples" / name).read_text()
            doc_id = doc_id or {"injected": "northwind-soc2-2025.pdf p.14", "clean": "contoso-soc2-2025.pdf p.9"}[body.example]
        if not text or not text.strip():
            raise ValueError("no document text")
        s.read_doc(ident, doc_id or "pasted-document", text, body.tools)
        return s.state(ident)

    # ---- controls, evidence, audit ------------------------------------------------
    @app.post("/api/evaluate")
    def evaluate(request: Request, ident: Identity = Depends(identity)):
        results = svc(request).evaluate(trigger="api")
        return {cid: {"state": r.state, "reason": r.reason, "evidence_ids": r.evidence_ids} for cid, r in results.items()}

    @app.get("/api/controls")
    def controls(request: Request, ident: Identity = Depends(identity)):
        s = svc(request)
        results = s.evaluate(trigger="api", record=False)
        return [dict(id=c.id, name=c.name, required_kinds=c.required_kinds, sla_hours=c.freshness_sla_hours, mappings=c.mappings,
                     hipaa_spec=c.hipaa_spec, state=results[c.id].state, reason=results[c.id].reason) for c in s.catalog.values()]

    @app.get("/api/controls/{control_id}/history")
    def control_history(control_id: str, request: Request, since: str | None = None, limit: int = 200, ident: Identity = Depends(identity)):
        return svc(request).history(control_id, since=since, limit=limit)

    @app.get("/api/evidence")
    def evidence(request: Request, kind: str | None = None, control_id: str | None = None, source: str | None = None,
                 limit: int = 100, ident: Identity = Depends(identity)):
        ident.require("read:evidence")
        max_class = "publishable" if ident.role == "auditor" and ident.via == "api-key" else None
        rows = svc(request).store.query(kind=kind, control_id=control_id, max_classification=max_class)
        if source:
            rows = [r for r in rows if r.source == source]
        return [r.__dict__ for r in rows[-limit:]]

    @app.get("/api/evidence/{record_id}")
    def evidence_one(record_id: str, request: Request, ident: Identity = Depends(identity)):
        ident.require("read:evidence")
        rec = svc(request).store.get(record_id)
        if rec is None:
            raise HTTPException(404, "no such record")
        return rec.__dict__

    @app.get("/api/audit")
    def audit(request: Request, prefix: str | None = None, limit: int = 200, ident: Identity = Depends(identity)):
        ident.require("read:evidence")
        return [e.__dict__ for e in svc(request).audit.query(action_prefix=prefix, limit=limit)]

    # ---- sources, runs, import ----------------------------------------------------------
    @app.get("/api/sources")
    def sources(request: Request, ident: Identity = Depends(identity)):
        return svc(request).configured_sources()

    @app.post("/api/sources/{source_id}/collect")
    def collect(source_id: str, request: Request, ident: Identity = Depends(identity)):
        return svc(request).run_source(source_id, ident, trigger="api")

    @app.get("/api/runs")
    def runs(request: Request, source_id: str | None = None, limit: int = 50, ident: Identity = Depends(identity)):
        return svc(request).runs.list(source_id=source_id, limit=limit)

    @app.post("/api/import")
    async def import_upload(request: Request, file: UploadFile = File(...), mapping: str | None = Form(None),
                            source: str | None = Form(None), ident: Identity = Depends(identity)):
        suffix = Path(file.filename or "upload").suffix or ".csv"
        with tempfile.NamedTemporaryFile("wb", suffix=suffix, delete=False) as tmp:
            tmp.write(await file.read())
            tmp_path = Path(tmp.name)
        try:
            result = svc(request).import_file(ident, tmp_path, mapping=mapping, source=source)
        finally:
            tmp_path.unlink(missing_ok=True)
        result["file"] = file.filename
        return result

    # ---- acceptances + gate ---------------------------------------------------------
    @app.get("/api/acceptances")
    def acceptances(request: Request, ident: Identity = Depends(identity)):
        return svc(request).acceptances.all()

    @app.post("/api/acceptances", status_code=201)
    def add_acceptance(body: AcceptanceIn, request: Request, ident: Identity = Depends(identity)):
        ident.require("manage:acceptances")
        s = svc(request)
        if body.control_id not in s.catalog:
            raise ValueError(f"unknown control {body.control_id}")
        row = s.acceptances.add(body.control_id, body.owner, body.reason, body.expires, ident.email)
        s.audit.record(actor=ident.email, action="acceptance.added", subject=body.control_id, detail=f"until {body.expires}: {body.reason}")
        return row

    @app.delete("/api/acceptances/{acceptance_id}")
    def revoke_acceptance(acceptance_id: int, request: Request, ident: Identity = Depends(identity)):
        ident.require("manage:acceptances")
        s = svc(request)
        row = s.acceptances.revoke(acceptance_id, A.utcnow())
        s.audit.record(actor=ident.email, action="acceptance.revoked", subject=row["control_id"], detail=f"acceptance #{acceptance_id}")
        return row

    @app.get("/api/gate")
    def gate(request: Request, strict: bool = False, ident: Identity = Depends(identity)):
        return svc(request).gate(strict=strict)

    # ---- history, notifications, packages, questionnaires ------------------------------------
    @app.get("/api/history/summary")
    def history_summary(request: Request, days: int = 90, ident: Identity = Depends(identity)):
        return svc(request).history_summary(days=days)

    @app.get("/api/notifications")
    def notifications(request: Request, limit: int = 50, ident: Identity = Depends(identity)):
        ident.require("read:evidence")
        return svc(request).notifications(limit)

    @app.post("/api/package")
    def package(body: PackageIn, request: Request, ident: Identity = Depends(identity)):
        stamp = A.utcnow().replace(":", "").replace("-", "")
        out = exports_dir / f"attest-package-{body.framework or 'all'}-{stamp}.zip"
        result = svc(request).build_package(ident, out, framework=body.framework, since=body.since, include_restricted=body.include_restricted)
        return FileResponse(result["path"], media_type="application/zip", filename=out.name,
                            headers={"X-Attest-Package-SHA256": result["sha256"]})

    @app.get("/api/packages")
    def packages(request: Request, ident: Identity = Depends(identity)):
        from attest.store_sql import PackageStore
        return PackageStore(request.app.state.engine).list()

    @app.get("/api/questionnaires")
    def questionnaires(request: Request, ident: Identity = Depends(identity)):
        return svc(request).questionnaires()

    @app.post("/api/questionnaires", status_code=201)
    async def import_questionnaire(request: Request, file: UploadFile = File(...), name: str | None = Form(None),
                                   ident: Identity = Depends(identity)):
        suffix = Path(file.filename or "questionnaire.csv").suffix or ".csv"
        with tempfile.NamedTemporaryFile("wb", suffix=suffix, delete=False) as tmp:
            tmp.write(await file.read())
            tmp_path = Path(tmp.name)
        try:
            result = svc(request).import_questionnaire(ident, tmp_path, name=name or Path(file.filename or "").stem or None)
        finally:
            tmp_path.unlink(missing_ok=True)
        return dict(questionnaire=result["questionnaire"], drafted=len(result["drafts"]), state=svc(request).state(ident))

    @app.get("/api/questionnaires/{qn_id}/rows")
    def questionnaire_rows(qn_id: str, request: Request, ident: Identity = Depends(identity)):
        return svc(request).questionnaire_rows(qn_id)

    @app.get("/api/questionnaires/{qn_id}/export")
    def export_questionnaire(qn_id: str, request: Request, fmt: str = "csv", ident: Identity = Depends(identity)):
        if fmt not in ("csv", "xlsx"):
            raise ValueError("fmt must be csv or xlsx")
        out = exports_dir / f"{qn_id}.{fmt}"
        exports_dir.mkdir(parents=True, exist_ok=True)
        svc(request).export_questionnaire(ident, qn_id, out, fmt)
        media = "text/csv" if fmt == "csv" else "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        return FileResponse(out, media_type=media, filename=out.name)

    # ---- users + keys (admin) ---------------------------------------------------------
    @app.get("/api/users")
    def users(request: Request, ident: Identity = Depends(identity)):
        ident.require("manage:users")
        return A.list_users(request.app.state.engine)

    @app.post("/api/users", status_code=201)
    def add_user(body: UserIn, request: Request, ident: Identity = Depends(identity)):
        ident.require("manage:users")
        row = A.create_user(request.app.state.engine, body.email, body.role, body.name, body.password)
        svc(request).audit.record(actor=ident.email, action="user.created", subject=row["email"], detail=f"role={row['role']}")
        return row

    @app.get("/api/keys")
    def keys(request: Request, ident: Identity = Depends(identity)):
        ident.require("manage:users")
        return A.list_api_keys(request.app.state.engine)

    @app.post("/api/keys", status_code=201)
    def add_key(body: KeyIn, request: Request, ident: Identity = Depends(identity)):
        ident.require("manage:users")
        secret, row = A.create_api_key(request.app.state.engine, body.email, body.name)
        svc(request).audit.record(actor=ident.email, action="key.created", subject=body.email, detail=f"{body.name} ({row['prefix']}…)")
        return {**row, "secret": secret}

    @app.delete("/api/keys/{key_id}")
    def del_key(key_id: int, request: Request, ident: Identity = Depends(identity)):
        ident.require("manage:users")
        A.revoke_api_key(request.app.state.engine, key_id)
        svc(request).audit.record(actor=ident.email, action="key.revoked", subject=str(key_id))
        return {"ok": True}

    # ---- sandbox-only demo operations ------------------------------------------------
    if cfg.sandbox:
        @app.post("/api/reseed", tags=["sandbox"])
        def reseed(request: Request, ident: Identity = Depends(identity)):
            s = svc(request); s.reseed(); return s.state(ident)

        @app.post("/api/tamper", tags=["sandbox"])
        def tamper(request: Request, ident: Identity = Depends(identity)):
            s = svc(request); s.tamper(); return s.state(ident)

        @app.post("/api/demo/terminate", tags=["sandbox"])
        def terminate(request: Request, ident: Identity = Depends(identity)):
            s = svc(request); s.terminate_user(ident); return s.state(ident)

        @app.post("/api/collect/join", tags=["sandbox"])
        def collect_join(request: Request, ident: Identity = Depends(identity)):
            s = svc(request); s.run_join(ident, trigger="manual"); return s.state(ident)

        @app.get("/api/personas", tags=["sandbox"])
        def personas():
            return [dict(id=email, label=label, user=email, role=role) for email, (label, role) in DEMO_USERS.items()]

        @app.post("/api/auth/impersonate", tags=["sandbox"])
        def impersonate(body: dict, request: Request, response: Response):
            email = body.get("email")
            if email not in DEMO_USERS:
                raise ValueError("unknown demo user")
            ident = demo_identity(request.app.state.engine, email)
            response.set_cookie(COOKIE, request.app.state.codec.issue(ident), httponly=True, samesite="lax")
            return {"user": ident.email, "role": ident.role, "grants": sorted(ident.grants)}

    return app


def ensure_demo_users(engine) -> None:
    existing = {u["email"] for u in A.list_users(engine)}
    for email, (name, role) in DEMO_USERS.items():
        if email not in existing:
            A.create_user(engine, email, role, name=name, password="attest")


def demo_identity(engine, email: str) -> Identity:
    from sqlalchemy import select
    from attest.db import User, session_scope
    with session_scope(engine) as s:
        u = s.scalar(select(User).where(User.email == email))
        if u is None:
            ensure_demo_users(engine)
            u = s.scalar(select(User).where(User.email == email))
        return Identity(user_id=u.id, email=u.email, name=u.name, role=u.role, via="sandbox", grants=A.ROLE_GRANTS[u.role])


app = None  # `uvicorn attest.api:app` is not the entry point — use `attest serve`, which builds it from attest.toml.

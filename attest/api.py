"""attest.api — the HTTP surface: FastAPI, typed, documented at /docs.

    attest serve            # reads attest.toml, runs migrations, starts the scheduler
Identity: `Authorization: Bearer atst_…` (API keys) or the session cookie set by
POST /api/auth/login. Sandbox mode signs anonymous browsers in as the demo
engineer so the console works out of the box; production returns 401.
"""
from __future__ import annotations

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

    app = FastAPI(title="Attest", version="0.2.0", lifespan=lifespan,
                  description="Continuous compliance control plane with a governed agent layer.")

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

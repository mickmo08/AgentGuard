"""HTTP application.

Credentials by audience:
  agents        Authorization: Bearer ag_...    /v1/actions, /v1/tools
  people        Authorization: Bearer ags_...   (dashboard session from /v1/auth/login)
  automation    Authorization: Bearer agt_...   (API token, scoped to an org and role)
"""
from __future__ import annotations

import json
import logging
import time
import uuid
from contextlib import asynccontextmanager
from importlib import resources
from typing import Any

import httpx
from fastapi import BackgroundTasks, Depends, FastAPI, Header, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from sqlalchemy import text

from agentguard.server.auth import IdentityService, Principal
from agentguard.server.connectors import Executor
from agentguard.server.crypto import Vault
from agentguard.server.db import Agent, make_engine, make_sessionmaker
from agentguard.server.metrics import Metrics
from agentguard.server.migrate import migrate
from agentguard.server.notifications import EVENTS, Notifier
from agentguard.server.service import Gateway, starter_policy
from agentguard.server.settings import Settings
from agentguard.server.slack import SlackInteractions
from agentguard.server.store import ApiError, Store
from agentguard.server.worker import Worker

log = logging.getLogger("agentguard.http")
VERSION = "0.2.0"


# ------------------------------------------------------------------- bodies


class ActionIn(BaseModel):
    action: str = Field(min_length=1, max_length=200)
    params: dict[str, Any] = Field(default_factory=dict)
    idempotency_key: str | None = Field(default=None, min_length=1, max_length=200)
    run_id: str | None = Field(default=None, max_length=200)
    context: dict[str, Any] = Field(default_factory=dict)


class SignupIn(BaseModel):
    organization: str = Field(min_length=1, max_length=200)
    email: str
    password: str
    name: str = ""


class LoginIn(BaseModel):
    email: str
    password: str
    organization_id: str | None = None


class AcceptInviteIn(BaseModel):
    token: str
    password: str
    name: str = ""


class PasswordIn(BaseModel):
    current_password: str
    new_password: str


class OrgIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)


class SwitchIn(BaseModel):
    organization_id: str


class AgentIn(BaseModel):
    slug: str
    name: str = ""
    owner: str = ""
    description: str = ""
    environment: str = "production"


class AgentPatch(BaseModel):
    name: str | None = None
    owner: str | None = None
    description: str | None = None
    environment: str | None = None


class StatusIn(BaseModel):
    reason: str = ""


class DecisionIn(BaseModel):
    decision: str
    note: str = Field(default="", max_length=2000)


class PolicyIn(BaseModel):
    source: str
    comment: str = ""
    activate: bool = True


class SourceIn(BaseModel):
    source: str


class SimulateIn(BaseModel):
    agent: str
    action: str
    params: dict[str, Any] = Field(default_factory=dict)


class SecretIn(BaseModel):
    value: str


class RoleIn(BaseModel):
    role: str


class InviteIn(BaseModel):
    email: str
    role: str = "viewer"


class TokenIn(BaseModel):
    name: str
    role: str = "viewer"


class ChannelIn(BaseModel):
    kind: str
    name: str = ""
    config: dict[str, Any] = Field(default_factory=dict)
    events: list[str] | None = None


class ChannelPatch(BaseModel):
    name: str | None = None
    enabled: bool | None = None
    events: list[str] | None = None


# --------------------------------------------------------------------- app


def _configure_logging(json_logs: bool) -> None:
    root = logging.getLogger("agentguard")
    if root.handlers:
        return

    class JsonFormatter(logging.Formatter):
        def format(self, record: logging.LogRecord) -> str:
            out = {"ts": self.formatTime(record), "level": record.levelname, "logger": record.name, "msg": record.getMessage()}
            for key in ("request_id", "method", "path", "status", "ms", "result"):
                if hasattr(record, key):
                    out[key] = getattr(record, key)
            if record.exc_info:
                out["exc"] = self.formatException(record.exc_info)
            return json.dumps(out, default=str)

    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter() if json_logs else logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
    root.addHandler(handler)
    root.setLevel(logging.INFO)


def _bearer(authorization: str | None) -> str:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise ApiError(401, "missing bearer token")
    return authorization[7:].strip()


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else ""


CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; "
       "frame-ancestors 'none'; base-uri 'none'; form-action 'self'")


def create_app(
    settings: Settings | None = None,
    executor: Executor | None = None,
    http_client: httpx.Client | None = None,
    start_worker: bool | None = None,
) -> FastAPI:
    settings = settings or Settings.from_env()
    settings.validate()
    _configure_logging(settings.log_json)

    engine = make_engine(settings.database_url)
    if settings.auto_migrate:
        migrate(engine)
    store = Store(make_sessionmaker(engine))
    vault = Vault(settings.encryption_keys)
    metrics = Metrics()
    notifier = Notifier(store, vault, settings, metrics, http_client=http_client)
    gateway = Gateway(store, settings, vault, notifier, metrics, executor)
    identity = IdentityService(
        store, settings,
        on_org_created=lambda org_id, actor: gateway.create_policy_version(None, starter_policy(), "Starter policy", True, org_id=org_id, actor=actor),
    )
    slack = SlackInteractions(store, gateway, notifier)
    worker = Worker(gateway, notifier, metrics, settings.worker_interval_seconds)
    run_worker = settings.worker_enabled if start_worker is None else start_worker

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        if run_worker:
            worker.start()
        yield
        worker.stop()
        engine.dispose()

    app = FastAPI(title="AgentGuard", version=VERSION, lifespan=lifespan, docs_url="/docs", redoc_url=None)
    app.state.settings, app.state.engine, app.state.store = settings, engine, store
    app.state.gateway, app.state.identity, app.state.notifier = gateway, identity, notifier
    app.state.worker, app.state.metrics = worker, metrics

    # ------------------------------------------------------------ middleware

    @app.middleware("http")
    async def _envelope(request: Request, call_next):
        request_id = request.headers.get("x-request-id") or uuid.uuid4().hex
        length = request.headers.get("content-length")
        if length and length.isdigit() and int(length) > settings.max_body_bytes:
            return JSONResponse({"error": {"code": "too_large", "message": "request body too large"}, "detail": "request body too large"}, status_code=413)
        started = time.perf_counter()
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Frame-Options"] = "DENY"
        if not request.url.path.startswith("/docs") and not request.url.path.startswith("/openapi"):
            response.headers["Content-Security-Policy"] = CSP
        if request.url.path.startswith("/v1/"):
            response.headers["Cache-Control"] = "no-store"
        if request.url.path not in ("/healthz", "/readyz", "/metrics"):
            log.info("request", extra={"request_id": request_id, "method": request.method, "path": request.url.path,
                                       "status": response.status_code, "ms": round((time.perf_counter() - started) * 1000, 1)})
        return response

    @app.exception_handler(ApiError)
    async def _api_error(_: Request, exc: ApiError) -> JSONResponse:
        return JSONResponse({"error": {"code": exc.code, "message": exc.message}, "detail": exc.message}, status_code=exc.status_code,
                            headers={"WWW-Authenticate": "Bearer"} if exc.status_code == 401 else None)

    @app.exception_handler(RequestValidationError)
    async def _validation_error(_: Request, exc: RequestValidationError) -> JSONResponse:
        msg = "; ".join(f"{'.'.join(str(p) for p in e['loc'][1:])}: {e['msg']}" for e in exc.errors())
        return JSONResponse({"error": {"code": "invalid", "message": msg}, "detail": msg}, status_code=422)

    # ---------------------------------------------------------- dependencies

    def principal(authorization: str | None = Header(default=None)) -> Principal:
        p = identity.authenticate(_bearer(authorization))
        if p is None:
            raise ApiError(401, "invalid or expired credentials")
        return p

    def agent_auth(authorization: str | None = Header(default=None)) -> Agent:
        agent = gateway.authenticate_agent(_bearer(authorization))
        if agent is None:
            raise ApiError(401, "invalid agent key")
        return agent

    def role(min_role: str):
        def dep(p: Principal = Depends(principal)) -> Principal:
            p.require(min_role)
            return p
        return dep

    viewer, approver, admin = role("viewer"), role("approver"), role("admin")

    # ------------------------------------------------------------------ ops

    @app.get("/healthz", include_in_schema=False)
    def healthz() -> dict:
        return {"ok": True, "version": VERSION}

    @app.get("/readyz", include_in_schema=False)
    def readyz() -> JSONResponse:
        try:
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
        except Exception:
            return JSONResponse({"ok": False, "database": "unreachable"}, status_code=503)
        return JSONResponse({"ok": True})

    @app.get("/metrics", include_in_schema=False)
    def metrics_endpoint() -> Response:
        return Response(metrics.render(), media_type=metrics.content_type)

    # ------------------------------------------------------------ dashboard

    static_dir = resources.files("agentguard.server").joinpath("static")
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    @app.get("/", include_in_schema=False)
    def index() -> FileResponse:
        return FileResponse(str(static_dir.joinpath("index.html")))

    # ----------------------------------------------------------------- auth

    @app.get("/v1/auth/config", tags=["auth"])
    def auth_config() -> dict:
        return {"signup_enabled": settings.allow_signup, "version": VERSION}

    @app.post("/v1/auth/signup", status_code=201, tags=["auth"])
    def signup(body: SignupIn, request: Request) -> dict:
        if not settings.allow_signup:
            raise ApiError(403, "self-service signup is disabled on this server; ask an admin for an invitation")
        org, _ = identity.create_org_with_owner(body.organization, body.email, body.password, body.name)
        return identity.login(body.email, body.password, _client_ip(request), request.headers.get("user-agent", ""), org["id"])

    @app.post("/v1/auth/login", tags=["auth"])
    def login(body: LoginIn, request: Request) -> dict:
        return identity.login(body.email, body.password, _client_ip(request), request.headers.get("user-agent", ""), body.organization_id)

    @app.post("/v1/auth/logout", status_code=204, tags=["auth"])
    def logout(p: Principal = Depends(principal)) -> Response:
        identity.logout(p)
        return Response(status_code=204)

    @app.get("/v1/auth/me", tags=["auth"])
    def me(p: Principal = Depends(principal)) -> dict:
        return identity.me(p)

    @app.post("/v1/auth/switch-org", tags=["auth"])
    def switch_org(body: SwitchIn, p: Principal = Depends(principal)) -> dict:
        identity.switch_org(p, body.organization_id)
        return {"ok": True}

    @app.post("/v1/auth/password", status_code=204, tags=["auth"])
    def change_password(body: PasswordIn, p: Principal = Depends(principal)) -> Response:
        identity.change_password(p, body.current_password, body.new_password)
        return Response(status_code=204)

    @app.post("/v1/auth/accept-invite", tags=["auth"])
    def accept_invite(body: AcceptInviteIn, request: Request) -> dict:
        return identity.accept_invitation(body.token, body.password, body.name, _client_ip(request), request.headers.get("user-agent", ""))

    @app.post("/v1/organizations", status_code=201, tags=["auth"])
    def create_org(body: OrgIn, p: Principal = Depends(principal)) -> dict:
        return identity.create_additional_org(p, body.name)

    # ------------------------------------------------------------ agent API

    @app.post("/v1/actions", tags=["agent"])
    def submit_action(body: ActionIn, agent: Agent = Depends(agent_auth)) -> dict:
        req, replayed = gateway.submit_action(agent, body.action, body.params, body.idempotency_key, body.run_id, body.context)
        return {**req, "replayed": replayed}

    @app.get("/v1/actions/{request_id}", tags=["agent"])
    def get_own_action(request_id: str, agent: Agent = Depends(agent_auth)) -> dict:
        return gateway.get_action(agent.org_id, request_id, agent_id=agent.id)

    @app.get("/v1/tools", tags=["agent"])
    def tools(agent: Agent = Depends(agent_auth)) -> list[dict]:
        return gateway.tools_for(agent)

    # ------------------------------------------------------------ operators

    @app.get("/v1/admin/overview", tags=["admin"])
    def overview(p: Principal = Depends(viewer)) -> dict:
        return gateway.overview(p)

    @app.get("/v1/admin/agents", tags=["agents"])
    def list_agents(p: Principal = Depends(viewer)) -> list[dict]:
        return gateway.list_agents(p)

    @app.post("/v1/admin/agents", status_code=201, tags=["agents"])
    def create_agent(body: AgentIn, p: Principal = Depends(admin)) -> dict:
        agent, key = gateway.create_agent(p, body.slug, body.name, body.owner, body.description, body.environment)
        return {"agent": agent, "api_key": key, "note": "store this key now; it is not shown again"}

    @app.get("/v1/admin/agents/{agent_id}", tags=["agents"])
    def get_agent(agent_id: str, p: Principal = Depends(viewer)) -> dict:
        return gateway.get_agent(p, agent_id)

    @app.patch("/v1/admin/agents/{agent_id}", tags=["agents"])
    def update_agent(agent_id: str, body: AgentPatch, p: Principal = Depends(admin)) -> dict:
        return gateway.update_agent(p, agent_id, **body.model_dump(exclude_none=True))

    @app.post("/v1/admin/agents/{agent_id}/pause", tags=["agents"])
    def pause_agent(agent_id: str, body: StatusIn, p: Principal = Depends(admin)) -> dict:
        return gateway.set_agent_status(p, agent_id, "paused", body.reason)

    @app.post("/v1/admin/agents/{agent_id}/resume", tags=["agents"])
    def resume_agent(agent_id: str, p: Principal = Depends(admin)) -> dict:
        return gateway.set_agent_status(p, agent_id, "active")

    @app.post("/v1/admin/agents/{agent_id}/disable", tags=["agents"])
    def disable_agent(agent_id: str, body: StatusIn, p: Principal = Depends(admin)) -> dict:
        return gateway.set_agent_status(p, agent_id, "disabled", body.reason)

    @app.post("/v1/admin/agents/{agent_id}/rotate-key", tags=["agents"])
    def rotate_key(agent_id: str, p: Principal = Depends(admin)) -> dict:
        return {"api_key": gateway.rotate_agent_key(p, agent_id), "note": "the previous key stopped working"}

    @app.get("/v1/admin/actions", tags=["actions"])
    def list_actions(agent: str | None = None, status: str | None = None, action: str | None = None, run_id: str | None = None,
                     before: str | None = None, limit: int = 100, p: Principal = Depends(viewer)) -> list[dict]:
        return gateway.list_actions(p, agent=agent, status=status, action=action, run_id=run_id, before=before, limit=limit)

    @app.get("/v1/admin/actions/{request_id}", tags=["actions"])
    def action_detail(request_id: str, p: Principal = Depends(viewer)) -> dict:
        return gateway.action_detail(p, request_id)

    @app.get("/v1/admin/approvals", tags=["actions"])
    def approvals(p: Principal = Depends(viewer)) -> list[dict]:
        return gateway.pending_approvals(p)

    @app.post("/v1/admin/approvals/{request_id}", tags=["actions"])
    def decide(request_id: str, body: DecisionIn, p: Principal = Depends(approver)) -> dict:
        return gateway.decide(p, request_id, body.decision, body.note, via="dashboard" if p.session_hash else "api")

    # policies
    @app.get("/v1/admin/policies", tags=["policies"])
    def policy_versions(p: Principal = Depends(viewer)) -> list[dict]:
        return gateway.list_policy_versions(p)

    @app.get("/v1/admin/policies/active", tags=["policies"])
    def active_policy(p: Principal = Depends(viewer)) -> dict:
        return gateway.get_policy_version(p)

    @app.get("/v1/admin/policies/diff", tags=["policies"])
    def policy_diff(from_version: int, to_version: int, p: Principal = Depends(viewer)) -> dict:
        return gateway.diff_policy(p, from_version, to_version)

    @app.get("/v1/admin/policies/{version}", tags=["policies"])
    def policy_version(version: int, p: Principal = Depends(viewer)) -> dict:
        return gateway.get_policy_version(p, version)

    @app.post("/v1/admin/policies/validate", tags=["policies"])
    def validate_policy(body: SourceIn, p: Principal = Depends(viewer)) -> dict:
        return gateway.validate_policy(p, body.source)

    @app.post("/v1/admin/policies", status_code=201, tags=["policies"])
    def create_policy(body: PolicyIn, p: Principal = Depends(admin)) -> dict:
        return gateway.create_policy_version(p, body.source, body.comment, body.activate)

    @app.post("/v1/admin/policies/{version}/activate", tags=["policies"])
    def activate_policy(version: int, p: Principal = Depends(admin)) -> dict:
        return gateway.activate_policy(p, version)

    @app.post("/v1/admin/policies/simulate", tags=["policies"])
    def simulate(body: SimulateIn, p: Principal = Depends(viewer)) -> dict:
        return gateway.simulate(p, body.agent, body.action, body.params)

    # secrets
    @app.get("/v1/admin/secrets", tags=["secrets"])
    def list_secrets(p: Principal = Depends(admin)) -> list[dict]:
        return gateway.list_secrets(p)

    @app.put("/v1/admin/secrets/{name}", tags=["secrets"])
    def put_secret(name: str, body: SecretIn, p: Principal = Depends(admin)) -> dict:
        return gateway.put_secret(p, name, body.value)

    @app.delete("/v1/admin/secrets/{name}", status_code=204, tags=["secrets"])
    def delete_secret(name: str, p: Principal = Depends(admin)) -> Response:
        gateway.delete_secret(p, name)
        return Response(status_code=204)

    # team
    @app.get("/v1/admin/members", tags=["team"])
    def members(p: Principal = Depends(viewer)) -> list[dict]:
        return identity.list_members(p)

    @app.patch("/v1/admin/members/{user_id}", tags=["team"])
    def member_role(user_id: str, body: RoleIn, p: Principal = Depends(admin)) -> dict:
        return identity.update_member_role(p, user_id, body.role)

    @app.delete("/v1/admin/members/{user_id}", status_code=204, tags=["team"])
    def remove_member(user_id: str, p: Principal = Depends(admin)) -> Response:
        identity.remove_member(p, user_id)
        return Response(status_code=204)

    @app.get("/v1/admin/invitations", tags=["team"])
    def invitations(p: Principal = Depends(admin)) -> list[dict]:
        return identity.list_invitations(p)

    @app.post("/v1/admin/invitations", status_code=201, tags=["team"])
    def invite(body: InviteIn, p: Principal = Depends(admin)) -> dict:
        return identity.create_invitation(p, body.email, body.role)

    @app.delete("/v1/admin/invitations/{invitation_id}", status_code=204, tags=["team"])
    def revoke_invite(invitation_id: str, p: Principal = Depends(admin)) -> Response:
        identity.revoke_invitation(p, invitation_id)
        return Response(status_code=204)

    @app.get("/v1/admin/tokens", tags=["team"])
    def tokens(p: Principal = Depends(admin)) -> list[dict]:
        return identity.list_api_tokens(p)

    @app.post("/v1/admin/tokens", status_code=201, tags=["team"])
    def create_token(body: TokenIn, p: Principal = Depends(admin)) -> dict:
        return identity.create_api_token(p, body.name, body.role)

    @app.delete("/v1/admin/tokens/{token_id}", status_code=204, tags=["team"])
    def revoke_token(token_id: str, p: Principal = Depends(admin)) -> Response:
        identity.revoke_api_token(p, token_id)
        return Response(status_code=204)

    # integrations
    @app.get("/v1/admin/channels", tags=["integrations"])
    def channels(p: Principal = Depends(admin)) -> dict:
        return {"channels": notifier.list_channels(p), "events": EVENTS}

    @app.post("/v1/admin/channels", status_code=201, tags=["integrations"])
    def create_channel(body: ChannelIn, p: Principal = Depends(admin)) -> dict:
        return notifier.create_channel(p, body.kind, body.name, body.config, body.events)

    @app.patch("/v1/admin/channels/{channel_id}", tags=["integrations"])
    def update_channel(channel_id: str, body: ChannelPatch, p: Principal = Depends(admin)) -> dict:
        return notifier.update_channel(p, channel_id, enabled=body.enabled, events=body.events, name=body.name)

    @app.delete("/v1/admin/channels/{channel_id}", status_code=204, tags=["integrations"])
    def delete_channel(channel_id: str, p: Principal = Depends(admin)) -> Response:
        notifier.delete_channel(p, channel_id)
        return Response(status_code=204)

    @app.post("/v1/admin/channels/{channel_id}/test", tags=["integrations"])
    def test_channel(channel_id: str, p: Principal = Depends(admin)) -> dict:
        return notifier.send_test(p, channel_id)

    @app.get("/v1/admin/deliveries", tags=["integrations"])
    def deliveries(limit: int = 100, p: Principal = Depends(admin)) -> list[dict]:
        return notifier.list_deliveries(p, limit)

    @app.post("/v1/integrations/slack/{channel_id}/interactions", include_in_schema=False)
    async def slack_interactions(channel_id: str, request: Request, background: BackgroundTasks) -> Response:
        body = await request.body()
        response, work = slack.handle(channel_id, {k.lower(): v for k, v in request.headers.items()}, body)
        if work:
            background.add_task(work)
        return JSONResponse(response) if response else Response(status_code=200)

    # audit
    @app.get("/v1/admin/audit", tags=["audit"])
    def audit_log(request_id: str | None = None, agent_id: str | None = None, event_type: str | None = None,
                  before_seq: int | None = None, limit: int = 200, p: Principal = Depends(viewer)) -> list[dict]:
        return gateway.audit_events(p, request_id=request_id, agent_id=agent_id, event_type=event_type, before_seq=before_seq, limit=limit)

    @app.get("/v1/admin/audit/verify", tags=["audit"])
    def audit_verify(p: Principal = Depends(viewer)) -> dict:
        return gateway.verify_audit(p)

    @app.get("/v1/admin/audit/export", tags=["audit"])
    def audit_export(p: Principal = Depends(admin)) -> StreamingResponse:
        return StreamingResponse(gateway.export_audit(p), media_type="application/x-ndjson",
                                 headers={"Content-Disposition": f'attachment; filename="agentguard-audit-{p.org_id}.ndjson"'})

    @app.get("/v1/version", include_in_schema=False)
    def version() -> PlainTextResponse:
        return PlainTextResponse(VERSION)

    return app


def app_from_env() -> FastAPI:
    """`uvicorn --factory agentguard.server.app:app_from_env`"""
    return create_app(Settings.from_env())

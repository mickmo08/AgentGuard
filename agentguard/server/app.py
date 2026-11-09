"""HTTP API.

Two audiences, two credentials:
  /v1/actions, /v1/tools   agents, authenticated by their agent API key
  /v1/admin/*              operators, authenticated by the admin token
"""
from __future__ import annotations

import os
from importlib import resources
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

from agentguard.server.config import GatewayConfig, load_config
from agentguard.server.connectors import Executor
from agentguard.server.db import Agent, make_sessionmaker
from agentguard.server.security import constant_time_equal
from agentguard.server.service import Gateway, GatewayError


class ActionIn(BaseModel):
    action: str = Field(min_length=1, max_length=200)
    params: dict[str, Any] = Field(default_factory=dict)
    idempotency_key: str | None = Field(default=None, max_length=200)
    run_id: str | None = Field(default=None, max_length=200)
    context: dict[str, Any] = Field(default_factory=dict)


class AgentIn(BaseModel):
    id: str
    name: str = ""
    owner: str = ""
    description: str = ""


class StatusIn(BaseModel):
    reason: str = ""


class DecisionIn(BaseModel):
    reviewer: str = Field(min_length=1, max_length=200)
    note: str = ""


class SimulateIn(BaseModel):
    agent_id: str
    action: str
    params: dict[str, Any] = Field(default_factory=dict)


def _bearer(authorization: str | None) -> str:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "missing bearer token", headers={"WWW-Authenticate": "Bearer"})
    return authorization[7:].strip()


def create_app(
    config: GatewayConfig | str | Path,
    database_url: str = "sqlite:///agentguard.db",
    admin_token: str | None = None,
    executor: Executor | None = None,
) -> FastAPI:
    if not isinstance(config, GatewayConfig):
        config = load_config(config)
    admin_token = admin_token or os.environ.get("AGENTGUARD_ADMIN_TOKEN")
    if not admin_token or len(admin_token) < 16:
        raise RuntimeError("an admin token of at least 16 characters is required (AGENTGUARD_ADMIN_TOKEN)")

    gateway = Gateway(config, make_sessionmaker(database_url), executor)
    app = FastAPI(title="AgentGuard", version="0.1.0", docs_url="/docs")
    app.state.gateway = gateway

    @app.exception_handler(GatewayError)
    async def _gateway_error(_: Request, exc: GatewayError) -> JSONResponse:
        return JSONResponse({"detail": exc.message}, status_code=exc.status_code)

    def require_agent(authorization: str | None = Header(default=None)) -> Agent:
        agent = gateway.authenticate(_bearer(authorization))
        if agent is None:
            raise HTTPException(401, "invalid agent key")
        return agent

    def require_admin(authorization: str | None = Header(default=None)) -> None:
        if not constant_time_equal(_bearer(authorization), admin_token):
            raise HTTPException(401, "invalid admin token")

    # ---------------------------------------------------------------- public

    @app.get("/", response_class=HTMLResponse, include_in_schema=False)
    def dashboard() -> str:
        return resources.files("agentguard.server").joinpath("dashboard.html").read_text(encoding="utf-8")

    @app.get("/healthz")
    def healthz() -> dict:
        return {"ok": True}

    # ----------------------------------------------------------------- agent

    @app.post("/v1/actions")
    def submit_action(body: ActionIn, agent: Agent = Depends(require_agent)) -> dict:
        req, replayed = gateway.submit_action(agent, body.action, body.params, body.idempotency_key, body.run_id, body.context)
        return {**req, "replayed": replayed}

    @app.get("/v1/actions/{request_id}")
    def get_own_action(request_id: str, agent: Agent = Depends(require_agent)) -> dict:
        return gateway.get_action(request_id, agent_id=agent.id)

    @app.get("/v1/tools")
    def list_tools(agent: Agent = Depends(require_agent)) -> list[dict]:
        """Tool definitions (JSON Schema) for every brokered action, ready to hand to an LLM."""
        tools = []
        for name, spec in config.all_actions().items():
            props = {k: {"type": p.type, **({"description": p.description} if p.description else {})} for k, p in spec.params.items()}
            tools.append(
                {
                    "name": name,
                    "description": spec.description,
                    "input_schema": {
                        "type": "object",
                        "properties": props,
                        "required": [k for k, p in spec.params.items() if p.required],
                        "additionalProperties": False,
                    },
                }
            )
        return tools

    # ----------------------------------------------------------------- admin

    admin = [Depends(require_admin)]

    @app.get("/v1/admin/stats", dependencies=admin)
    def stats() -> dict:
        return gateway.stats()

    @app.get("/v1/admin/agents", dependencies=admin)
    def list_agents() -> list[dict]:
        return gateway.list_agents()

    @app.post("/v1/admin/agents", dependencies=admin, status_code=201)
    def create_agent(body: AgentIn) -> dict:
        agent, key = gateway.create_agent(body.id, body.name, body.owner, body.description)
        return {"agent": agent, "api_key": key, "note": "store this key now; it is not shown again"}

    @app.post("/v1/admin/agents/{agent_id}/pause", dependencies=admin)
    def pause_agent(agent_id: str, body: StatusIn) -> dict:
        return gateway.set_agent_status(agent_id, "paused", body.reason)

    @app.post("/v1/admin/agents/{agent_id}/resume", dependencies=admin)
    def resume_agent(agent_id: str) -> dict:
        return gateway.set_agent_status(agent_id, "active")

    @app.post("/v1/admin/agents/{agent_id}/rotate-key", dependencies=admin)
    def rotate_key(agent_id: str) -> dict:
        return {"api_key": gateway.rotate_key(agent_id), "note": "the previous key no longer works"}

    @app.get("/v1/admin/actions", dependencies=admin)
    def list_actions(agent_id: str | None = None, status: str | None = None, run_id: str | None = None, limit: int = 100) -> list[dict]:
        return gateway.list_actions(agent_id, status, run_id, limit)

    @app.get("/v1/admin/actions/{request_id}", dependencies=admin)
    def get_action(request_id: str) -> dict:
        return {**gateway.get_action(request_id), "timeline": list(reversed(gateway.audit_events(request_id=request_id)))}

    @app.get("/v1/admin/approvals", dependencies=admin)
    def approvals() -> list[dict]:
        return gateway.list_actions(status="pending_approval")

    @app.post("/v1/admin/approvals/{request_id}/approve", dependencies=admin)
    def approve(request_id: str, body: DecisionIn) -> dict:
        return gateway.decide(request_id, True, body.reviewer, body.note)

    @app.post("/v1/admin/approvals/{request_id}/deny", dependencies=admin)
    def deny(request_id: str, body: DecisionIn) -> dict:
        return gateway.decide(request_id, False, body.reviewer, body.note)

    @app.get("/v1/admin/audit", dependencies=admin)
    def audit_log(request_id: str | None = None, agent_id: str | None = None, limit: int = 200) -> list[dict]:
        return gateway.audit_events(request_id, agent_id, limit)

    @app.get("/v1/admin/audit/verify", dependencies=admin)
    def verify() -> dict:
        return gateway.verify_audit()

    @app.get("/v1/admin/policies", dependencies=admin)
    def policies() -> dict:
        # Connector configs only name env vars; secret values never leave the gateway.
        return {
            "policies": config.policies.model_dump(),
            "actions": sorted(config.all_actions()),
            "connectors": {k: {"type": c.type, "description": c.description} for k, c in config.connectors.items()},
            "approval_ttl_seconds": config.approval_ttl_seconds,
        }

    @app.post("/v1/admin/policies/simulate", dependencies=admin)
    def simulate(body: SimulateIn) -> dict:
        return gateway.simulate(body.agent_id, body.action, body.params)

    return app


def app_from_env() -> FastAPI:
    """Entry point for `uvicorn --factory agentguard.server.app:app_from_env`."""
    return create_app(
        os.environ.get("AGENTGUARD_CONFIG", "agentguard.yaml"),
        os.environ.get("AGENTGUARD_DATABASE_URL", "sqlite:///agentguard.db"),
    )

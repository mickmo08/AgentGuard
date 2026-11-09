"""Shared fixtures. Every API test runs on SQLite, and on Postgres too when
AGENTGUARD_TEST_POSTGRES_URL is set (CI sets it; see .github/workflows/ci.yml)."""
from __future__ import annotations

import json
import os
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text

from agentguard.server.app import create_app
from agentguard.server.connectors import Executor, MockBackends
from agentguard.server.crypto import generate_key
from agentguard.server.settings import Settings

PG_URL = os.environ.get("AGENTGUARD_TEST_POSTGRES_URL")
DB_PARAMS = ["sqlite"] + (["postgres"] if PG_URL else [])
PASSWORD = "correct horse battery staple"


class FakeHttp:
    """Routes outbound HTTP (connectors, webhooks, Slack) to per-host handlers and records calls."""

    def __init__(self) -> None:
        self.calls: list[httpx.Request] = []
        self.handlers: dict[str, Callable[[httpx.Request], httpx.Response]] = {}

    def route(self, host: str, handler: Callable[[httpx.Request], httpx.Response]) -> None:
        self.handlers[host] = handler

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(request)
        handler = self.handlers.get(request.url.host)
        if handler is None:
            return httpx.Response(599, json={"error": f"no fake route for {request.url.host}"})
        return handler(request)

    def to(self, host: str) -> list[httpx.Request]:
        return [c for c in self.calls if c.url.host == host]


def _reset_postgres(url: str) -> None:
    engine = create_engine(url)
    with engine.begin() as conn:
        conn.execute(text("DROP SCHEMA public CASCADE"))
        conn.execute(text("CREATE SCHEMA public"))
    engine.dispose()


@dataclass
class Env:
    client: TestClient
    app: Any
    mocks: MockBackends
    http: FakeHttp
    settings: Settings
    tokens: dict[str, str] = field(default_factory=dict)

    @property
    def gateway(self):
        return self.app.state.gateway

    def auth(self, who: str = "owner") -> dict[str, str]:
        return {"Authorization": f"Bearer {self.tokens[who]}"}

    def call(self, method: str, path: str, who: str | None = "owner", **kw: Any) -> httpx.Response:
        headers = kw.pop("headers", {})
        if who:
            headers = {**self.auth(who), **headers}
        return self.client.request(method, path, headers=headers, **kw)

    def ok(self, method: str, path: str, who: str | None = "owner", status: int | None = None, **kw: Any) -> Any:
        r = self.call(method, path, who, **kw)
        assert r.status_code < 300 if status is None else r.status_code == status, f"{method} {path} -> {r.status_code} {r.text}"
        return r.json() if r.content else None

    def add_member(self, who: str, role: str) -> None:
        inv = self.ok("POST", "/v1/admin/invitations", json={"email": f"{who}@acme.com", "role": role})
        r = self.ok("POST", "/v1/auth/accept-invite", who=None, json={"token": inv["token"], "password": PASSWORD, "name": who})
        self.tokens[who] = r["token"]

    def agent(self, slug: str = "support-bot") -> dict[str, str]:
        key = self.ok("POST", "/v1/admin/agents", json={"slug": slug})["api_key"]
        return {"Authorization": f"Bearer {key}"}

    def act(self, agent_headers: dict, action: str, params: dict, **extra: Any) -> httpx.Response:
        return self.client.post("/v1/actions", headers=agent_headers, json={"action": action, "params": params, **extra})

    def refund(self, agent_headers: dict, amount: float, **extra: Any) -> dict:
        r = self.act(agent_headers, "payments.refund", {"customer_id": "cus_alice", "amount": amount}, **extra)
        assert r.status_code == 200, r.text
        return r.json()


@pytest.fixture(params=DB_PARAMS)
def make_env(request, tmp_path) -> Callable[..., Env]:
    created: list[TestClient] = []

    def factory(**overrides: Any) -> Env:
        if request.param == "postgres":
            _reset_postgres(PG_URL)
            db_url = PG_URL
        else:
            db_url = f"sqlite:///{tmp_path}/agentguard.db"
        settings = Settings(database_url=db_url, encryption_keys=[generate_key()], allow_signup=True, worker_enabled=False,
                            log_json=False, allow_private_network_egress=True, public_url="https://agentguard.test")
        for k, v in overrides.items():
            setattr(settings, k, v)
        http = FakeHttp()
        client_http = httpx.Client(transport=httpx.MockTransport(http))
        mocks = MockBackends()
        app = create_app(settings, executor=Executor(mocks, http_client=client_http, egress_guard=None), http_client=client_http, start_worker=False)
        client = TestClient(app)
        created.append(client)
        env = Env(client, app, mocks, http, settings)
        r = client.post("/v1/auth/signup", json={"organization": "Acme", "email": "owner@acme.com", "password": PASSWORD, "name": "Olivia"})
        assert r.status_code == 201, r.text
        env.tokens["owner"] = r.json()["token"]
        return env

    yield factory
    for c in created:
        c.app.state.engine.dispose()


@pytest.fixture
def env(make_env) -> Env:
    return make_env()


def json_body(req: httpx.Request) -> Any:
    return json.loads(req.content)

"""End-to-end tests through the HTTP API with the in-memory mock backends."""
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import update

from agentguard import ActionBlocked, AgentGuard, ApprovalDenied, ApprovalPending
from agentguard.server.app import create_app
from agentguard.server.config import load_config
from agentguard.server.connectors import Executor, MockBackends
from agentguard.server.db import AuditEvent

CONFIG = Path(__file__).parent.parent / "examples" / "agentguard.yaml"
ADMIN = "test-admin-token-0123456789"


@pytest.fixture
def env(monkeypatch):
    monkeypatch.setenv("PAYMENTS_API_KEY", "sk_test_secret")
    mocks = MockBackends()
    app = create_app(load_config(CONFIG), "sqlite://", admin_token=ADMIN, executor=Executor(mocks))
    client = TestClient(app)
    admin = {"Authorization": f"Bearer {ADMIN}"}
    r = client.post("/v1/admin/agents", json={"id": "support-bot", "owner": "cx"}, headers=admin)
    assert r.status_code == 201
    key = r.json()["api_key"]

    class Env:
        pass

    e = Env()
    e.client, e.admin, e.key, e.mocks, e.app = client, admin, key, mocks, app
    e.agent = {"Authorization": f"Bearer {key}"}
    e.sdk = AgentGuard("http://testserver", key, client=client)
    return e


def refund(e, amount, **extra):
    return e.client.post("/v1/actions", json={"action": "payments.refund", "params": {"customer_id": "cus_alice", "amount": amount}, **extra}, headers=e.agent)


def test_auth_required(env):
    assert env.client.post("/v1/actions", json={"action": "payments.refund"}).status_code == 401
    assert env.client.post("/v1/actions", json={"action": "x"}, headers={"Authorization": "Bearer ag_dead_beef"}).status_code == 401
    assert env.client.get("/v1/admin/agents", headers=env.agent).status_code == 401  # agent key is not admin


def test_small_refund_executes_with_brokered_credential(env):
    body = refund(env, 20).json()
    assert body["decision"] == "allow" and body["status"] == "executed"
    assert body["result"]["status"] == "succeeded"
    assert len(env.mocks.refunds) == 1
    assert "sk_test_secret" not in str(body)  # the agent never sees the credential


def test_large_refund_blocked_and_not_executed(env):
    body = refund(env, 900).json()
    assert body["status"] == "blocked" and body["rule_id"] == "refund-large"
    assert env.mocks.refunds == []


def test_review_then_approve_executes_once(env):
    body = refund(env, 200).json()
    assert body["status"] == "pending_approval" and env.mocks.refunds == []
    pending = env.client.get("/v1/admin/approvals", headers=env.admin).json()
    assert [p["id"] for p in pending] == [body["id"]]

    r = env.client.post(f"/v1/admin/approvals/{body['id']}/approve", json={"reviewer": "maria"}, headers=env.admin)
    assert r.json()["status"] == "executed" and r.json()["reviewer"] == "maria"
    assert len(env.mocks.refunds) == 1
    # second approval is rejected; no double refund
    r2 = env.client.post(f"/v1/admin/approvals/{body['id']}/approve", json={"reviewer": "sam"}, headers=env.admin)
    assert r2.status_code == 409 and len(env.mocks.refunds) == 1


def test_deny(env):
    body = refund(env, 200).json()
    r = env.client.post(f"/v1/admin/approvals/{body['id']}/deny", json={"reviewer": "maria", "note": "duplicate ticket"}, headers=env.admin)
    assert r.json()["status"] == "denied" and env.mocks.refunds == []


def test_idempotency_prevents_double_execution(env):
    a = refund(env, 20, idempotency_key="ticket-42").json()
    b = refund(env, 20, idempotency_key="ticket-42").json()
    assert a["id"] == b["id"] and b["replayed"] is True
    assert len(env.mocks.refunds) == 1
    assert refund(env, 25, idempotency_key="ticket-42").status_code == 409  # same key, different params


def test_param_validation(env):
    r = env.client.post("/v1/actions", json={"action": "payments.refund", "params": {"customer_id": "cus_alice", "amount": "20"}}, headers=env.agent)
    assert r.status_code == 422
    r = env.client.post("/v1/actions", json={"action": "payments.refund", "params": {"customer_id": "cus_alice", "amount": 5, "to_account": "x"}}, headers=env.agent)
    assert r.status_code == 422 and "unknown params" in r.json()["detail"]
    assert env.client.post("/v1/actions", json={"action": "payments.drain"}, headers=env.agent).status_code == 404


def test_rate_limit_trips_kill_switch(env):
    for _ in range(5):
        assert refund(env, 10).json()["status"] == "executed"
    sixth = refund(env, 10).json()
    assert sixth["status"] == "blocked" and sixth["rule_id"] == "refund-burst"
    agents = env.client.get("/v1/admin/agents", headers=env.admin).json()
    assert agents[0]["status"] == "paused"
    # paused agents are blocked across all actions, not just refunds
    r = env.client.post("/v1/actions", json={"action": "payments.get_customer", "params": {"customer_id": "cus_bob"}}, headers=env.agent).json()
    assert r["status"] == "blocked" and "paused" in r["reason"]
    env.client.post("/v1/admin/agents/support-bot/resume", headers=env.admin)
    assert env.client.post("/v1/actions", json={"action": "payments.get_customer", "params": {"customer_id": "cus_bob"}}, headers=env.agent).json()["status"] == "executed"


def test_cannot_approve_for_paused_agent(env):
    body = refund(env, 200).json()
    env.client.post("/v1/admin/agents/support-bot/pause", json={"reason": "investigating"}, headers=env.admin)
    r = env.client.post(f"/v1/admin/approvals/{body['id']}/approve", json={"reviewer": "maria"}, headers=env.admin)
    assert r.status_code == 409 and env.mocks.refunds == []


def test_missing_credential_fails_safely(env, monkeypatch):
    monkeypatch.delenv("PAYMENTS_API_KEY")
    body = refund(env, 20).json()
    assert body["status"] == "failed" and "PAYMENTS_API_KEY" in body["error"]


def test_agents_cannot_read_each_others_actions(env):
    body = refund(env, 20).json()
    other = env.client.post("/v1/admin/agents", json={"id": "sales-bot"}, headers=env.admin).json()["api_key"]
    assert env.client.get(f"/v1/actions/{body['id']}", headers={"Authorization": f"Bearer {other}"}).status_code == 404


def test_audit_chain_verifies_and_detects_tampering(env):
    refund(env, 20)
    refund(env, 200)
    v = env.client.get("/v1/admin/audit/verify", headers=env.admin).json()
    assert v["valid"] and v["events"] >= 6

    gw = env.app.state.gateway
    with gw.sessions() as s:  # an insider quietly rewrites history
        s.execute(update(AuditEvent).where(AuditEvent.event_type == "policy.evaluated").values(data={"decision": "allow"}))
        s.commit()
    v = env.client.get("/v1/admin/audit/verify", headers=env.admin).json()
    assert not v["valid"] and "hash" in v["problem"]


def test_timeline_for_an_action(env):
    body = refund(env, 200).json()
    env.client.post(f"/v1/admin/approvals/{body['id']}/approve", json={"reviewer": "maria"}, headers=env.admin)
    detail = env.client.get(f"/v1/admin/actions/{body['id']}", headers=env.admin).json()
    assert [e["event_type"] for e in detail["timeline"]] == ["action.requested", "policy.evaluated", "approval.granted", "action.executed"]


def test_simulate(env):
    r = env.client.post("/v1/admin/policies/simulate", json={"agent_id": "support-bot", "action": "payments.refund", "params": {"customer_id": "c", "amount": 75}}, headers=env.admin).json()
    assert r["decision"] == "review" and r["rule_id"] == "refund-medium"
    assert env.mocks.refunds == []


def test_policies_endpoint_does_not_leak_secrets(env):
    body = env.client.get("/v1/admin/policies", headers=env.admin).text
    assert "sk_test_secret" not in body


def test_http_connector_injects_secret_and_encodes_path(monkeypatch, env):
    monkeypatch.setenv("CRM_TOKEN", "crm-secret")
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"], seen["auth"], seen["idem"] = str(request.url), request.headers.get("authorization"), request.headers.get("idempotency-key")
        return httpx.Response(201, json={"id": "note_1"})

    env.app.state.gateway.executor._http = httpx.Client(transport=httpx.MockTransport(handler))
    r = env.client.post("/v1/actions", json={"action": "crm.add_note", "params": {"customer_id": "../admin", "note": "hi"}, "idempotency_key": "k1"}, headers=env.agent).json()
    assert r["status"] == "executed" and r["result"]["body"] == {"id": "note_1"}
    assert seen["auth"] == "Bearer crm-secret" and seen["idem"] == "k1"
    assert seen["url"].endswith("/customers/..%2Fadmin/notes")


def test_sdk_flow(env):
    with env.sdk.run() as run_id:
        assert env.sdk.act("payments.refund", {"customer_id": "cus_bob", "amount": 15})["status"] == "succeeded"
        with pytest.raises(ActionBlocked) as exc:
            env.sdk.act("payments.refund", {"customer_id": "cus_bob", "amount": 1000})
        assert exc.value.request["rule_id"] == "refund-large"
        with pytest.raises(ApprovalPending) as pend:
            env.sdk.act("payments.refund", {"customer_id": "cus_bob", "amount": 100}, wait=False)
    runs = env.client.get(f"/v1/admin/actions?run_id={run_id}", headers=env.admin).json()
    assert len(runs) == 3

    env.client.post(f"/v1/admin/approvals/{pend.value.request_id}/deny", json={"reviewer": "maria"}, headers=env.admin)
    with pytest.raises(ApprovalDenied):
        env.sdk.act("payments.refund", {"customer_id": "cus_bob", "amount": 100}, idempotency_key=pend.value.request["idempotency_key"])


def test_sdk_handler_returns_readable_outcomes(env):
    tool = env.sdk.handler("payments.refund")
    assert tool(customer_id="cus_bob", amount=5)["ok"] is True
    out = tool(customer_id="cus_bob", amount=100)
    assert out["status"] == "pending_approval" and out["request_id"]
    assert tool(customer_id="cus_bob", amount=10_000)["status"] == "blocked"


def test_tools_endpoint_gives_json_schema(env):
    tools = {t["name"]: t for t in env.sdk.tools()}
    assert tools["payments.refund"]["input_schema"]["required"] == ["customer_id", "amount"]
    assert "crm.add_note" in tools

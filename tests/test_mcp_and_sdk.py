"""The Python SDK and the MCP front door, end to end against the real app."""
import json

import anyio
import pytest
from mcp.client import Client

from agentguard import ActionBlocked, AgentGuard, AgentGuardAdmin, ApprovalDenied, ApprovalPending
from agentguard.mcp_server import build_server
from tests.conftest import PASSWORD


def _sdk(env):
    key = env.ok("POST", "/v1/admin/agents", json={"slug": "support-bot"})["api_key"]
    return AgentGuard("http://testserver", key, client=env.client)


def test_sdk_flow(env):
    guard = _sdk(env)
    with guard.run() as run_id:
        assert guard.act("payments.refund", {"customer_id": "cus_bob", "amount": 15})["status"] == "succeeded"
        with pytest.raises(ActionBlocked):
            guard.act("payments.refund", {"customer_id": "cus_bob", "amount": 9000})
        with pytest.raises(ApprovalPending) as pend:
            guard.act("payments.refund", {"customer_id": "cus_bob", "amount": 100}, wait=False)
    assert len(env.ok("GET", f"/v1/admin/actions?run_id={run_id}")) == 3
    admin = AgentGuardAdmin.login("http://testserver", "owner@acme.com", PASSWORD, client=env.client)
    admin.deny(pend.value.request_id, "not eligible")
    with pytest.raises(ApprovalDenied):
        guard.act("payments.refund", {"customer_id": "cus_bob", "amount": 100}, idempotency_key=pend.value.request["idempotency_key"])


def test_sdk_handler_outcomes(env):
    tool = _sdk(env).handler("payments.refund")
    assert tool(customer_id="cus_bob", amount=5)["ok"] is True
    assert tool(customer_id="cus_bob", amount=100)["status"] == "pending_approval"
    assert tool(customer_id="cus_bob", amount=10_000)["status"] == "blocked"


def test_mcp_server_lists_and_calls_brokered_tools(env):
    server = build_server(_sdk(env))

    async def run():
        async with Client(server) as client:
            tools = await client.list_tools()
            names = {t.name for t in tools.tools}
            assert {"payments__refund", "payments__get_customer", "email__send"} <= names
            ok = await client.call_tool("payments__refund", {"customer_id": "cus_alice", "amount": 12})
            pending = await client.call_tool("payments__refund", {"customer_id": "cus_alice", "amount": 300})
            blocked = await client.call_tool("payments__refund", {"customer_id": "cus_alice", "amount": 9000})
            return ok, pending, blocked

    ok, pending, blocked = anyio.run(run)
    assert json.loads(ok.content[0].text)["status"] == "executed" and not ok.is_error
    assert json.loads(pending.content[0].text)["status"] == "pending_approval" and not pending.is_error
    assert json.loads(blocked.content[0].text)["status"] == "blocked" and blocked.is_error
    assert len(env.mocks.refunds) == 1

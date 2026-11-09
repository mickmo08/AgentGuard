"""The action lifecycle: decisions, approvals, idempotency, kill switch, policies, secrets, audit."""
import datetime as dt

from sqlalchemy import select, update

from agentguard.server.db import ActionRequest, AuditEvent, Organization, Secret


def test_refund_tiers(env):
    a = env.agent()
    small, medium, large, huge = (env.refund(a, x) for x in (20, 200, 900, 5000))
    assert (small["status"], small["rule_id"]) == ("executed", "refund-small")
    assert (medium["status"], medium["approvals_required"]) == ("pending_approval", 1)
    assert (large["status"], large["approvals_required"], large["approver_roles"]) == ("pending_approval", 2, ["owner", "admin"])
    assert (huge["status"], huge["rule_id"]) == ("blocked", "refund-huge")
    assert len(env.mocks.refunds) == 1


def test_single_approval_executes_once(env):
    a = env.agent()
    req = env.refund(a, 200)
    out = env.ok("POST", f"/v1/admin/approvals/{req['id']}", json={"decision": "approve", "note": "valid"})
    assert out["status"] == "executed" and out["approvals"][0]["user"] == "owner@acme.com"
    assert env.call("POST", f"/v1/admin/approvals/{req['id']}", json={"decision": "approve"}).status_code == 409
    assert len(env.mocks.refunds) == 1


def test_two_person_rule(env):
    env.add_member("ada", "admin")
    env.add_member("abe", "approver")
    a = env.agent()
    req = env.refund(a, 900)
    # Approvers are not allowed on this rule; only owners and admins.
    assert env.call("POST", f"/v1/admin/approvals/{req['id']}", who="abe", json={"decision": "approve"}).status_code == 403
    first = env.ok("POST", f"/v1/admin/approvals/{req['id']}", json={"decision": "approve"})
    assert first["status"] == "pending_approval" and env.mocks.refunds == []
    # The same person cannot supply the second approval.
    assert env.call("POST", f"/v1/admin/approvals/{req['id']}", json={"decision": "approve"}).status_code == 409
    second = env.ok("POST", f"/v1/admin/approvals/{req['id']}", who="ada", json={"decision": "approve"})
    assert second["status"] == "executed" and len(env.mocks.refunds) == 1
    assert [v["user"] for v in second["approvals"]] == ["owner@acme.com", "ada@acme.com"]


def test_any_deny_is_final(env):
    env.add_member("ada", "admin")
    a = env.agent()
    req = env.refund(a, 900)
    env.ok("POST", f"/v1/admin/approvals/{req['id']}", json={"decision": "approve"})
    out = env.ok("POST", f"/v1/admin/approvals/{req['id']}", who="ada", json={"decision": "deny", "note": "duplicate ticket"})
    assert out["status"] == "denied" and env.mocks.refunds == []


def test_api_tokens_cannot_approve(env):
    env.tokens["ci"] = env.ok("POST", "/v1/admin/tokens", json={"name": "ci", "role": "owner"})["token"]
    req = env.refund(env.agent(), 200)
    r = env.call("POST", f"/v1/admin/approvals/{req['id']}", who="ci", json={"decision": "approve"})
    assert r.status_code == 403 and "people" in r.json()["detail"]


def test_idempotency(env):
    a = env.agent()
    x = env.refund(a, 20, idempotency_key="ticket-1")
    y = env.refund(a, 20, idempotency_key="ticket-1")
    assert x["id"] == y["id"] and y["replayed"] is True and len(env.mocks.refunds) == 1
    assert env.act(a, "payments.refund", {"customer_id": "cus_alice", "amount": 25}, idempotency_key="ticket-1").status_code == 409


def test_param_validation_and_unknown_actions(env):
    a = env.agent()
    assert env.act(a, "payments.refund", {"customer_id": "cus_alice", "amount": "20"}).status_code == 422
    assert env.act(a, "payments.refund", {"customer_id": "cus_alice", "amount": 5, "to": "x"}).status_code == 422
    assert env.act(a, "payments.drain", {}).status_code == 404
    assert env.act(a, "payments.refund", {"customer_id": "x" * 70_000, "amount": 1}).status_code == 413


def test_rate_limit_kill_switch_and_resume(env):
    a = env.agent()
    for _ in range(5):
        assert env.refund(a, 10)["status"] == "executed"
    sixth = env.refund(a, 10)
    assert (sixth["status"], sixth["rule_id"]) == ("blocked", "refund-burst")
    agent = env.ok("GET", "/v1/admin/agents")[0]
    assert agent["status"] == "paused"
    blocked = env.act(a, "payments.get_customer", {"customer_id": "cus_bob"}).json()
    assert blocked["rule_id"] == "agent-paused"
    env.ok("POST", f"/v1/admin/agents/{agent['id']}/resume")
    assert env.act(a, "payments.get_customer", {"customer_id": "cus_bob"}).json()["status"] == "executed"


def test_cannot_approve_for_paused_agent(env):
    a = env.agent()
    req = env.refund(a, 200)
    env.ok("POST", "/v1/admin/agents/support-bot/pause", json={"reason": "investigating"})
    assert env.call("POST", f"/v1/admin/approvals/{req['id']}", json={"decision": "approve"}).status_code == 409


def test_disabled_agent_key_stops_working(env):
    a = env.agent()
    env.ok("POST", "/v1/admin/agents/support-bot/disable", json={"reason": "decommissioned"})
    assert env.act(a, "payments.get_customer", {"customer_id": "cus_bob"}).status_code == 401
    assert env.call("POST", "/v1/admin/agents/support-bot/resume").status_code == 409


def test_rotate_key(env):
    old = env.agent()
    new_key = env.ok("POST", "/v1/admin/agents/support-bot/rotate-key")["api_key"]
    assert env.act(old, "payments.get_customer", {"customer_id": "cus_bob"}).status_code == 401
    assert env.act({"Authorization": f"Bearer {new_key}"}, "payments.get_customer", {"customer_id": "cus_bob"}).status_code == 200


POLICY_V2 = """
connectors:
  payments: {type: mock_payments}
policies:
  default: block
  rules:
    - id: everything-reviewed
      action: payments.refund
      decision: review
      approvals: {min: 1, roles: [owner]}
"""


def test_policy_versions_activate_rollback_diff(env):
    a = env.agent()
    v2 = env.ok("POST", "/v1/admin/policies", json={"source": POLICY_V2, "comment": "lock down"}, status=201)
    assert v2["version"] == 2 and v2["active"]
    assert env.refund(a, 10)["status"] == "pending_approval"
    env.ok("POST", "/v1/admin/policies/1/activate")
    assert env.refund(a, 10)["status"] == "executed"
    diff = env.ok("GET", "/v1/admin/policies/diff?from_version=1&to_version=2")["diff"]
    assert "+    - id: everything-reviewed" in diff
    events = [e["event_type"] for e in env.ok("GET", "/v1/admin/audit?event_type=policy.activated")]
    assert len(events) == 3


def test_invalid_policy_rejected_with_readable_errors(env):
    bad = "policies:\n  rules:\n    - id: r\n      decision: maybe\n      wen: {}\n"
    v = env.ok("POST", "/v1/admin/policies/validate", json={"source": bad})
    assert not v["valid"] and any("decision" in e for e in v["errors"]) and any("wen" in e for e in v["errors"])
    assert env.call("POST", "/v1/admin/policies", json={"source": bad}).status_code == 422
    assert env.ok("GET", "/v1/admin/policies/active")["version"] == 1


def test_env_secret_references_refused_by_default(env):
    src = "connectors:\n  api: {type: http, base_url: 'https://x.example', secret: 'env:AWS_SECRET_ACCESS_KEY'}\n"
    v = env.ok("POST", "/v1/admin/policies/validate", json={"source": src})
    assert not v["valid"] and "env:" in v["errors"][0]


def test_execution_uses_the_policy_version_that_approved_it(env):
    a = env.agent()
    req = env.refund(a, 200)  # decided under v1 (mock payments)
    env.ok("POST", "/v1/admin/policies", json={"source": "policies: {default: block}\n"}, status=201)  # v2 removes the connector
    out = env.ok("POST", f"/v1/admin/approvals/{req['id']}", json={"decision": "approve"})
    assert out["status"] == "executed" and out["policy_version"] == 1


def test_secrets_are_write_only_and_encrypted(env):
    env.ok("PUT", "/v1/admin/secrets/stripe_key", json={"value": "sk_live_supersecret"})
    listing = env.ok("GET", "/v1/admin/secrets")
    assert listing[0]["name"] == "stripe_key" and "sk_live" not in str(listing)
    with env.app.state.store.read() as s:
        stored = s.execute(select(Secret)).scalar_one()
        assert "supersecret" not in stored.ciphertext
    assert env.call("PUT", "/v1/admin/secrets/Bad-Name", json={"value": "x"}).status_code == 422


def test_params_encrypted_at_rest_and_redacted(env):
    src = env.ok("GET", "/v1/admin/policies/active")["source"].replace("redact_params: [card_number, ssn, password]", "redact_params: [reason]")
    env.ok("POST", "/v1/admin/policies", json={"source": src}, status=201)
    a = env.agent()
    out = env.act(a, "payments.refund", {"customer_id": "cus_alice", "amount": 20, "reason": "SSN 123-45-6789"}).json()
    assert out["params"]["reason"] == "***redacted***" and out["status"] == "executed"
    with env.app.state.store.read() as s:
        row = s.get(ActionRequest, out["id"])
        assert "123-45-6789" not in row.params_enc and "123-45-6789" not in str(row.params_view)
        assert "123-45-6789" not in str([e.data for e in s.execute(select(AuditEvent)).scalars()])
    assert env.mocks.refunds[0]["amount"] == 20  # the connector still received the real params


def test_audit_chain_detects_edits_and_truncation(env):
    a = env.agent()
    env.refund(a, 20)
    env.refund(a, 200)
    assert env.ok("GET", "/v1/admin/audit/verify")["valid"]
    store = env.app.state.store
    with store.tx_global() as s:  # an insider rewrites a decision
        s.execute(update(AuditEvent).where(AuditEvent.event_type == "policy.evaluated").values(data={"decision": "allow"}))
    v = env.ok("GET", "/v1/admin/audit/verify")
    assert not v["valid"] and "hash" in v["problem"]


def test_audit_truncation_detected(env):
    env.refund(env.agent(), 20)
    with env.app.state.store.tx_global() as s:
        last = s.execute(select(AuditEvent).order_by(AuditEvent.seq.desc()).limit(1)).scalar_one()
        s.delete(last)
    v = env.ok("GET", "/v1/admin/audit/verify")
    assert not v["valid"] and "missing" in v["problem"]


def test_audit_export_ndjson(env):
    env.refund(env.agent(), 20)
    r = env.call("GET", "/v1/admin/audit/export")
    lines = [ln for ln in r.text.splitlines() if ln]
    assert r.status_code == 200 and r.headers["content-type"].startswith("application/x-ndjson") and len(lines) >= 4


def test_worker_expires_approvals(env):
    req = env.refund(env.agent(), 200)
    with env.app.state.store.tx_global() as s:
        s.execute(update(ActionRequest).where(ActionRequest.id == req["id"]).values(expires_at=dt.datetime(2000, 1, 1)))
    assert env.app.state.worker.run_once()["expired"] == 1
    assert env.ok("GET", f"/v1/admin/actions/{req['id']}")["status"] == "expired"


def test_worker_marks_stuck_executions_unknown(env):
    req = env.refund(env.agent(), 20)
    with env.app.state.store.tx_global() as s:  # simulate a crash mid-execution
        s.execute(update(ActionRequest).where(ActionRequest.id == req["id"]).values(status="executing", execution_started_at=dt.datetime(2000, 1, 1)))
    assert env.app.state.worker.run_once()["stuck"] == 1
    detail = env.ok("GET", f"/v1/admin/actions/{req['id']}")
    assert detail["status"] == "unknown" and "check the downstream system" in detail["error"]
    assert env.ok("GET", "/v1/admin/overview")["unknown_outcomes"] == 1


def test_missing_connector_secret_fails_safely(env):
    src = env.ok("GET", "/v1/admin/policies/active")["source"].replace("type: mock_payments", "type: mock_payments\n    secret: payments_key")
    env.ok("POST", "/v1/admin/policies", json={"source": src}, status=201)
    out = env.refund(env.agent(), 20)
    assert out["status"] == "failed" and "payments_key" in out["error"]
    env.ok("PUT", "/v1/admin/secrets/payments_key", json={"value": "k"})
    assert env.refund(env.agent("support-two"), 20)["status"] == "executed"


def test_action_detail_timeline_and_run_grouping(env):
    a = env.agent()
    req = env.refund(a, 200, run_id="run-42", context={"ticket": "4822"})
    env.ok("POST", f"/v1/admin/approvals/{req['id']}", json={"decision": "approve"})
    d = env.ok("GET", f"/v1/admin/actions/{req['id']}")
    assert [e["event_type"] for e in d["timeline"]] == ["action.requested", "policy.evaluated", "approval.vote", "approval.granted", "action.executed"]
    assert d["context"] == {"ticket": "4822"}
    assert len(env.ok("GET", "/v1/admin/actions?run_id=run-42")) == 1


def test_simulate_and_tools(env):
    sim = env.ok("POST", "/v1/admin/policies/simulate", json={"agent": "support-bot", "action": "payments.refund", "params": {"customer_id": "c", "amount": 900}})
    assert sim["decision"] == "review" and sim["approvals"] == {"min": 2, "roles": ["owner", "admin"]}
    tools = {t["name"]: t for t in env.client.get("/v1/tools", headers=env.agent()).json()}
    assert tools["payments.refund"]["input_schema"]["required"] == ["customer_id", "amount"]


def test_overview_metrics_health(env):
    a = env.agent()
    env.refund(a, 20)
    env.refund(a, 5000)
    o = env.ok("GET", "/v1/admin/overview")
    assert o["actions"] == 2 and o["by_decision"] == {"allow": 1, "block": 1} and len(o["hourly"]) == 24
    m = env.client.get("/metrics").text
    assert 'agentguard_actions_total{decision="allow"} 1.0' in m
    assert env.client.get("/healthz").json()["ok"] and env.client.get("/readyz").status_code == 200


def test_security_headers_and_body_limit(env):
    r = env.client.get("/")
    assert "script-src 'self'" in r.headers["content-security-policy"] and r.headers["x-frame-options"] == "DENY"
    big = env.client.post("/v1/auth/login", content=b"x" * 2_000_001, headers={"content-type": "application/json"})
    assert big.status_code == 413


def test_org_lock_row_exists_per_org(env):
    with env.app.state.store.read() as s:
        assert s.execute(select(Organization)).scalars().first().audit_seq > 0

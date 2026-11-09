"""Connectors: Stripe, generic HTTP, egress guard, amounts."""
from urllib.parse import parse_qs

import httpx
import pytest

from agentguard.server.connectors import ConnectorError, check_egress, to_minor_units

STRIPE_POLICY = """
connectors:
  stripe: {type: stripe, secret: stripe_key}
  crm:
    type: http
    base_url: https://crm.example.com/api
    secret: crm_token
    actions:
      add_note:
        method: POST
        path: /customers/{customer_id}/notes
        params: {customer_id: {type: string}, note: {type: string}}
policies:
  default: block
  rules:
    - {id: refunds, agents: ["*"], action: stripe.refund, when: {amount: {lte: 100}}, decision: allow}
    - {id: lookups, action: stripe.get_payment, decision: allow}
    - {id: notes, action: crm.add_note, decision: allow}
"""


def _setup(env):
    env.ok("PUT", "/v1/admin/secrets/stripe_key", json={"value": "sk_test_123"})
    env.ok("PUT", "/v1/admin/secrets/crm_token", json={"value": "crm-secret"})
    env.ok("POST", "/v1/admin/policies", json={"source": STRIPE_POLICY}, status=201)
    return env.agent()


def test_stripe_refund(env):
    def stripe(req: httpx.Request) -> httpx.Response:
        assert req.url.path == "/v1/refunds"
        form = parse_qs(req.content.decode())
        assert form["amount"] == ["1250"] and form["payment_intent"] == ["pi_123"] and form["reason"] == ["duplicate"]
        assert req.headers["authorization"] == "Bearer sk_test_123" and req.headers["idempotency-key"] == "t-9"
        return httpx.Response(200, json={"id": "re_1", "object": "refund", "status": "succeeded", "amount": 1250, "currency": "usd", "payment_intent": "pi_123", "charge": "ch_secret"})

    env.http.route("api.stripe.com", stripe)
    a = _setup(env)
    out = env.act(a, "stripe.refund", {"payment_intent": "pi_123", "amount": 12.5, "currency": "usd", "reason": "duplicate"}, idempotency_key="t-9").json()
    assert out["status"] == "executed" and out["result"] == {"id": "re_1", "object": "refund", "status": "succeeded", "amount": 1250, "currency": "usd", "payment_intent": "pi_123"}
    assert "sk_test_123" not in str(out)


def test_stripe_error_surfaces_message_and_enum_validation(env):
    env.http.route("api.stripe.com", lambda r: httpx.Response(400, json={"error": {"message": "Refund amount exceeds charge", "code": "amount_too_large"}}))
    a = _setup(env)
    out = env.act(a, "stripe.refund", {"payment_intent": "pi_1", "amount": 5, "currency": "usd"}).json()
    assert out["status"] == "failed" and "exceeds charge" in out["error"]
    bad = env.act(a, "stripe.refund", {"payment_intent": "pi_1", "amount": 5, "currency": "usd", "reason": "because"})
    assert bad.status_code == 422 and "must be one of" in bad.json()["detail"]


def test_http_connector_injects_secret_and_encodes_path(env):
    seen = {}

    def crm(req: httpx.Request) -> httpx.Response:
        seen["path"], seen["auth"] = req.url.raw_path.decode(), req.headers["authorization"]
        return httpx.Response(201, json={"id": "note_1"})

    env.http.route("crm.example.com", crm)
    a = _setup(env)
    out = env.act(a, "crm.add_note", {"customer_id": "../admin", "note": "hi"}).json()
    assert out["status"] == "executed" and out["result"]["body"] == {"id": "note_1"}
    assert seen == {"path": "/api/customers/..%2Fadmin/notes", "auth": "Bearer crm-secret"}


@pytest.mark.parametrize("url", ["http://169.254.169.254/latest/meta-data", "http://127.0.0.1:8080/", "http://localhost/", "http://10.0.0.5/"])
def test_egress_guard_blocks_internal_addresses(url):
    with pytest.raises(ConnectorError):
        check_egress(url)


@pytest.mark.parametrize("amount,currency,minor", [(12.5, "usd", 1250), (0.1, "usd", 10), (500, "jpy", 500), (1.234, "kwd", 1234)])
def test_minor_units(amount, currency, minor):
    assert to_minor_units(amount, currency) == minor


@pytest.mark.parametrize("amount,currency", [(1.005, "usd"), (10.5, "jpy"), (0, "usd"), (-1, "usd")])
def test_minor_units_rejects_bad_amounts(amount, currency):
    with pytest.raises(ConnectorError):
        to_minor_units(amount, currency)

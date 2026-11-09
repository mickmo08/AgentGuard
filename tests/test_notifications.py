"""Webhooks, Slack approvals and the delivery outbox."""
import hashlib
import hmac
import json
import time
from urllib.parse import urlencode

import httpx
from sqlalchemy import update

from agentguard.server.db import Delivery
from agentguard.server.notifications import verify_webhook_signature
from tests.conftest import json_body


def test_webhook_signed_delivery(env):
    received = []
    env.http.route("hooks.example.com", lambda r: (received.append(r), httpx.Response(204))[1])
    ch = env.ok("POST", "/v1/admin/channels", json={"kind": "webhook", "name": "ops", "config": {"url": "https://hooks.example.com/ag"}}, status=201)
    secret = ch["signing_secret"]
    req = env.refund(env.agent(), 200)
    assert received == []  # queued, not sent inline
    assert env.app.state.worker.run_once()["delivered"] == 1
    hit = received[0]
    assert hit.headers["x-agentguard-event"] == "approval.requested"
    assert verify_webhook_signature(secret, hit.content, hit.headers["x-agentguard-signature"])
    assert not verify_webhook_signature("wrong", hit.content, hit.headers["x-agentguard-signature"])
    body = json.loads(hit.content)
    assert body["request"]["id"] == req["id"] and body["url"].endswith(f"/#/actions/{req['id']}")
    assert env.ok("GET", "/v1/admin/deliveries")[0]["status"] == "sent"


def test_webhook_retries_with_backoff(env):
    env.http.route("hooks.example.com", lambda r: httpx.Response(500))
    env.ok("POST", "/v1/admin/channels", json={"kind": "webhook", "config": {"url": "https://hooks.example.com/ag"}, "events": ["action.blocked"]}, status=201)
    env.refund(env.agent(), 5000)
    env.app.state.worker.run_once()
    d = env.ok("GET", "/v1/admin/deliveries")[0]
    assert d["status"] == "pending" and d["attempts"] == 1 and "500" in d["last_error"]
    env.app.state.worker.run_once()
    assert env.ok("GET", "/v1/admin/deliveries")[0]["attempts"] == 1  # backoff: not due yet
    env.http.route("hooks.example.com", lambda r: httpx.Response(200))
    with env.app.state.store.tx_global() as s:
        s.execute(update(Delivery).values(next_attempt_at=Delivery.created_at))
    env.app.state.worker.run_once()
    assert env.ok("GET", "/v1/admin/deliveries")[0]["status"] == "sent"


def test_channel_events_filter_and_https_required(make_env):
    env = make_env(allow_private_network_egress=False)
    r = env.call("POST", "/v1/admin/channels", json={"kind": "webhook", "config": {"url": "http://hooks.example.com/x"}})
    assert r.status_code == 422
    assert env.call("POST", "/v1/admin/channels", json={"kind": "webhook", "config": {"url": "https://h.example.com"}, "events": ["nope"]}).status_code == 422


def _slack_env(env):
    posts = []

    def slack(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/api/chat.postMessage":
            posts.append(json_body(req))
            return httpx.Response(200, json={"ok": True, "channel": "C1", "ts": "1.2"})
        if req.url.path == "/api/users.info":
            uid = dict(x.split("=") for x in req.content.decode().split("&"))["user"]
            email = {"U_OWNER": "owner@acme.com", "U_ADA": "ada@acme.com"}.get(uid)
            return httpx.Response(200, json={"ok": bool(email), "user": {"profile": {"email": email}}})
        return httpx.Response(404)

    responses = []
    env.http.route("slack.com", slack)
    env.http.route("hooks.slack.com", lambda r: (responses.append(json_body(r)), httpx.Response(200))[1])
    ch = env.ok("POST", "/v1/admin/channels", json={"kind": "slack", "name": "#approvals",
                                                     "config": {"bot_token": "xoxb-1", "signing_secret": "shh", "channel": "C1"}}, status=201)
    return ch, posts, responses


def _click(env, ch, request_id, slack_user, action="agentguard_approve", secret="shh", ts=None):
    payload = {"type": "block_actions", "user": {"id": slack_user}, "response_url": "https://hooks.slack.com/actions/T/1/x",
               "actions": [{"action_id": action, "value": request_id}]}
    body = urlencode({"payload": json.dumps(payload)}).encode()
    ts = str(ts or int(time.time()))
    sig = "v0=" + hmac.new(secret.encode(), f"v0:{ts}:".encode() + body, hashlib.sha256).hexdigest()
    return env.client.post(f"/v1/integrations/slack/{ch['id']}/interactions", content=body,
                           headers={"content-type": "application/x-www-form-urlencoded", "x-slack-request-timestamp": ts, "x-slack-signature": sig})


def test_slack_approval_message_escapes_agent_text(env):
    ch, posts, _ = _slack_env(env)
    a = env.agent()
    env.act(a, "payments.refund", {"customer_id": "cus_alice", "amount": 200, "reason": "<!channel> click <https://evil|here>"})
    env.app.state.worker.run_once()
    text = json.dumps(posts[0])
    assert "<!channel>" not in text and "&lt;!channel&gt;" in text
    actions = next(b for b in posts[0]["blocks"] if b["type"] == "actions")
    assert [e["action_id"] for e in actions["elements"]][:2] == ["agentguard_approve", "agentguard_deny"]


def test_slack_two_person_approval_flow(env):
    env.add_member("ada", "admin")
    ch, _, responses = _slack_env(env)
    req = env.refund(env.agent(), 900)
    assert _click(env, ch, req["id"], "U_OWNER").status_code == 200
    assert "1 of 2" in responses[-1]["text"]
    assert _click(env, ch, req["id"], "U_OWNER").status_code == 200  # same person again
    assert "already voted" in responses[-1]["text"]
    _click(env, ch, req["id"], "U_ADA")
    assert responses[-1]["replace_original"] is True and "executed" in responses[-1]["text"]
    detail = env.ok("GET", f"/v1/admin/actions/{req['id']}")
    assert detail["status"] == "executed" and {v["via"] for v in detail["approvals"]} == {"slack"}
    assert len(env.mocks.refunds) == 1
    assert any(m["slack_linked"] for m in env.ok("GET", "/v1/admin/members"))


def test_slack_rejects_bad_signature_replay_and_strangers(env):
    ch, _, responses = _slack_env(env)
    req = env.refund(env.agent(), 200)
    assert _click(env, ch, req["id"], "U_OWNER", secret="wrong").status_code == 401
    assert _click(env, ch, req["id"], "U_OWNER", ts=int(time.time()) - 3600).status_code == 401
    _click(env, ch, req["id"], "U_STRANGER")
    assert "not linked" in responses[-1]["text"]
    assert env.ok("GET", f"/v1/admin/actions/{req['id']}")["status"] == "pending_approval"

"""Notifications: a transactional outbox delivered by the background worker.

Events are written to `deliveries` in the same transaction as the state change
that caused them, so a crash can never lose a notification or send one for a
change that rolled back. The worker sends with exponential backoff.

Channel kinds:
  webhook  POST JSON, signed: X-AgentGuard-Signature: t=<unix>,v1=<hex hmac_sha256(secret, "<t>.<body>")>
  slack    Slack app bot token; approval requests get Approve / Deny buttons
"""
from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import json
import secrets
import time
from collections.abc import Callable
from typing import Any
from urllib.parse import urlsplit

import httpx
from sqlalchemy import select

from agentguard.server import audit
from agentguard.server.auth import Principal
from agentguard.server.connectors import ConnectorError, check_egress
from agentguard.server.crypto import Vault
from agentguard.server.db import Delivery, NotificationChannel, Organization, iso, utcnow
from agentguard.server.metrics import Metrics
from agentguard.server.settings import Settings
from agentguard.server.store import ApiError, Store, new_id

EVENTS = ["approval.requested", "approval.decided", "action.blocked", "action.failed", "action.stuck", "agent.paused"]
MAX_ATTEMPTS = 10
LEASE_SECONDS = 60
SLACK_API = "https://slack.com/api"


def sign_webhook(secret: str, body: bytes, ts: int | None = None) -> str:
    ts = ts or int(time.time())
    mac = hmac.new(secret.encode(), f"{ts}.".encode() + body, hashlib.sha256).hexdigest()
    return f"t={ts},v1={mac}"


def verify_webhook_signature(secret: str, body: bytes, header: str, tolerance: int = 300) -> bool:
    """Reference verifier for receivers (also used in tests)."""
    try:
        parts = dict(p.split("=", 1) for p in header.split(","))
        ts = int(parts["t"])
    except (ValueError, KeyError):
        return False
    if abs(time.time() - ts) > tolerance:
        return False
    expected = hmac.new(secret.encode(), f"{ts}.".encode() + body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, parts.get("v1", ""))


def slack_escape(text: Any) -> str:
    """Agent-supplied text must not be able to @channel, link or format in Slack."""
    return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


class Notifier:
    def __init__(self, store: Store, vault: Vault, settings: Settings, metrics: Metrics,
                 http_client: httpx.Client | None = None, egress_guard: Callable[[str], None] | None = check_egress):
        self.store = store
        self.vault = vault
        self.settings = settings
        self.metrics = metrics
        self._http = http_client
        self._egress_guard = None if settings.allow_private_network_egress else egress_guard

    # ------------------------------------------------------------- outbox

    def enqueue(self, s, org: Organization, event_type: str, payload: dict[str, Any], request_id: str | None = None) -> int:
        channels = s.execute(select(NotificationChannel).where(NotificationChannel.org_id == org.id, NotificationChannel.enabled.is_(True))).scalars().all()
        n = 0
        for ch in channels:
            if event_type in ch.events:
                s.add(Delivery(id=new_id("dlv"), org_id=org.id, channel_id=ch.id, event_type=event_type, request_id=request_id,
                               payload={"event": event_type, "org_id": org.id, "occurred_at": iso(utcnow()), **payload}))
                n += 1
        return n

    def deliver_due(self, limit: int = 50) -> int:
        now = utcnow()
        with self.store.tx_global() as s:
            q = (select(Delivery).where(Delivery.status == "pending", Delivery.next_attempt_at <= now)
                 .order_by(Delivery.next_attempt_at).limit(limit))
            if s.bind.dialect.name == "postgresql":
                q = q.with_for_update(skip_locked=True)  # multiple workers never take the same row
            batch = s.execute(q).scalars().all()
            for d in batch:  # lease: if this worker dies, the row becomes due again
                d.next_attempt_at = now + dt.timedelta(seconds=LEASE_SECONDS)
            claimed = [(d.id, d.channel_id) for d in batch]
        for delivery_id, channel_id in claimed:
            self._attempt(delivery_id, channel_id)
        return len(claimed)

    def _attempt(self, delivery_id: str, channel_id: str) -> None:
        with self.store.read() as s:
            d = s.get(Delivery, delivery_id)
            ch = s.get(NotificationChannel, channel_id)
            if d is None:
                return
            payload, event_type = d.payload, d.event_type
            kind = ch.kind if ch else "unknown"
            config = self.vault.decrypt_json(ch.config_enc) if ch else None
        error, response = None, None
        try:
            if config is None:
                raise ConnectorError("channel was deleted")
            response = self._send(kind, config, event_type, payload)
        except ConnectorError as exc:
            error = str(exc)
        except Exception as exc:  # pragma: no cover - defensive
            error = f"unexpected error ({exc.__class__.__name__})"
        self.metrics.deliveries.labels(kind, "error" if error else "ok").inc()
        with self.store.tx_global() as s:
            d = s.get(Delivery, delivery_id)
            if d is None:
                return
            d.attempts += 1
            if error is None:
                d.status, d.sent_at, d.response, d.last_error = "sent", utcnow(), response, None
            elif d.attempts >= MAX_ATTEMPTS or config is None:
                d.status, d.last_error = "failed", error
            else:
                d.last_error = error
                d.next_attempt_at = utcnow() + dt.timedelta(seconds=min(10 * 2 ** d.attempts, 3600))

    # ------------------------------------------------------------- senders

    def _post(self, url: str, **kwargs: Any) -> httpx.Response:
        if self._egress_guard is not None:
            self._egress_guard(url)
        client = self._http or httpx.Client(timeout=10, follow_redirects=False)
        try:
            return client.post(url, **kwargs)
        except httpx.HTTPError as exc:
            raise ConnectorError(f"request failed: {exc.__class__.__name__}") from exc
        finally:
            if self._http is None:
                client.close()

    def _send(self, kind: str, config: dict, event_type: str, payload: dict) -> dict:
        if kind == "webhook":
            body = json.dumps(payload, separators=(",", ":"), default=str).encode()
            headers = {"Content-Type": "application/json", "User-Agent": "AgentGuard-Webhooks/0.2", "X-AgentGuard-Event": event_type}
            if config.get("secret"):
                headers["X-AgentGuard-Signature"] = sign_webhook(config["secret"], body)
            resp = self._post(config["url"], content=body, headers=headers)
            if resp.status_code >= 300:
                raise ConnectorError(f"webhook endpoint returned HTTP {resp.status_code}")
            return {"status_code": resp.status_code}
        if kind == "slack":
            message = slack_message(event_type, payload)
            resp = self._post(f"{SLACK_API}/chat.postMessage", headers={"Authorization": f"Bearer {config['bot_token']}"},
                              json={"channel": config["channel"], **message})
            data = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
            if not data.get("ok"):
                raise ConnectorError(f"Slack API error: {data.get('error', resp.status_code)}")
            return {"channel": data.get("channel"), "ts": data.get("ts")}
        raise ConnectorError(f"unknown channel kind {kind!r}")

    # ------------------------------------------------------------- channels

    def _validate_config(self, kind: str, config: dict) -> dict:
        if kind == "webhook":
            url = str(config.get("url", ""))
            parts = urlsplit(url)
            if parts.scheme not in ("https", "http") or not parts.hostname:
                raise ApiError(422, "webhook url must be an absolute http(s) URL")
            if parts.scheme != "https" and not self.settings.allow_private_network_egress:
                raise ApiError(422, "webhook url must use https")
            return {"url": url, "secret": str(config.get("secret") or "") or secrets.token_urlsafe(32)}
        if kind == "slack":
            missing = [k for k in ("bot_token", "signing_secret", "channel") if not config.get(k)]
            if missing:
                raise ApiError(422, f"slack channels require: {', '.join(missing)}")
            return {k: str(config[k]) for k in ("bot_token", "signing_secret", "channel")}
        raise ApiError(422, "kind must be webhook or slack")

    @staticmethod
    def _public_config(kind: str, config: dict) -> dict:
        if kind == "webhook":
            return {"url": config["url"]}
        return {"channel": config["channel"]}

    def _channel_dict(self, ch: NotificationChannel) -> dict:
        cfg = self.vault.decrypt_json(ch.config_enc)
        return {"id": ch.id, "kind": ch.kind, "name": ch.name, "events": ch.events, "enabled": ch.enabled,
                "config": self._public_config(ch.kind, cfg), "created_at": iso(ch.created_at),
                **({"interactions_url": f"{self.settings.public_url}/v1/integrations/slack/{ch.id}/interactions"} if ch.kind == "slack" else {})}

    def create_channel(self, principal: Principal, kind: str, name: str, config: dict, events: list[str] | None) -> dict:
        principal.require("admin")
        events = events or list(EVENTS)
        bad = [e for e in events if e not in EVENTS]
        if bad:
            raise ApiError(422, f"unknown events {bad}; choose from {EVENTS}")
        cfg = self._validate_config(kind, config)
        with self.store.tx(principal.org_id) as (s, org):
            ch = NotificationChannel(id=new_id("chn"), org_id=org.id, kind=kind, name=(name or kind).strip()[:200],
                                     config_enc=self.vault.encrypt_json(cfg), events=events)
            s.add(ch)
            audit.append(s, org, actor=principal.actor, event_type="channel.created", data={"kind": kind, "name": ch.name, "events": events})
            out = self._channel_dict(ch)
        if kind == "webhook":
            out["signing_secret"] = cfg["secret"]  # shown once
        return out

    def list_channels(self, principal: Principal) -> list[dict]:
        with self.store.read() as s:
            rows = s.execute(select(NotificationChannel).where(NotificationChannel.org_id == principal.org_id).order_by(NotificationChannel.created_at)).scalars().all()
            return [self._channel_dict(c) for c in rows]

    def update_channel(self, principal: Principal, channel_id: str, *, enabled: bool | None = None, events: list[str] | None = None, name: str | None = None) -> dict:
        principal.require("admin")
        if events is not None and any(e not in EVENTS for e in events):
            raise ApiError(422, f"events must be chosen from {EVENTS}")
        with self.store.tx(principal.org_id) as (s, org):
            ch = s.get(NotificationChannel, channel_id)
            if ch is None or ch.org_id != org.id:
                raise ApiError(404, "channel not found")
            if enabled is not None:
                ch.enabled = enabled
            if events is not None:
                ch.events = events
            if name:
                ch.name = name.strip()[:200]
            audit.append(s, org, actor=principal.actor, event_type="channel.updated", data={"channel": ch.id, "enabled": ch.enabled, "events": ch.events})
            return self._channel_dict(ch)

    def delete_channel(self, principal: Principal, channel_id: str) -> None:
        principal.require("admin")
        with self.store.tx(principal.org_id) as (s, org):
            ch = s.get(NotificationChannel, channel_id)
            if ch is None or ch.org_id != org.id:
                raise ApiError(404, "channel not found")
            s.delete(ch)
            audit.append(s, org, actor=principal.actor, event_type="channel.deleted", data={"channel": channel_id, "name": ch.name})

    def send_test(self, principal: Principal, channel_id: str) -> dict:
        principal.require("admin")
        with self.store.read() as s:
            ch = s.get(NotificationChannel, channel_id)
            if ch is None or ch.org_id != principal.org_id:
                raise ApiError(404, "channel not found")
            kind, cfg = ch.kind, self.vault.decrypt_json(ch.config_enc)
        payload = {"event": "test", "org_id": principal.org_id, "occurred_at": iso(utcnow()), "message": f"Test notification sent by {principal.label}"}
        try:
            self._send(kind, cfg, "test", payload)
        except ConnectorError as exc:
            return {"ok": False, "error": str(exc)}
        return {"ok": True}

    def list_deliveries(self, principal: Principal, limit: int = 100) -> list[dict]:
        with self.store.read() as s:
            rows = s.execute(select(Delivery).where(Delivery.org_id == principal.org_id).order_by(Delivery.created_at.desc()).limit(min(limit, 500))).scalars().all()
        return [{"id": d.id, "channel_id": d.channel_id, "event_type": d.event_type, "request_id": d.request_id, "status": d.status,
                 "attempts": d.attempts, "last_error": d.last_error, "created_at": iso(d.created_at), "sent_at": iso(d.sent_at)} for d in rows]

    def channel_config(self, channel_id: str) -> tuple[str, str, dict] | None:
        """(org_id, kind, decrypted config) for internal use by integrations."""
        with self.store.read() as s:
            ch = s.get(NotificationChannel, channel_id)
            if ch is None or not ch.enabled:
                return None
            return ch.org_id, ch.kind, self.vault.decrypt_json(ch.config_enc)


# ------------------------------------------------------------- slack rendering


def slack_message(event_type: str, payload: dict) -> dict:
    req = payload.get("request") or {}
    agent = payload.get("agent") or {}
    url = payload.get("url")
    action = slack_escape(req.get("action", ""))
    who = slack_escape(agent.get("slug", req.get("agent_slug", "an agent")))
    if event_type == "test":
        return {"text": slack_escape(payload.get("message", "AgentGuard test notification"))}
    if event_type == "approval.requested":
        fields = [{"type": "mrkdwn", "text": f"*{slack_escape(k)}*\n{slack_escape(json.dumps(v))[:200]}"} for k, v in list((req.get("params") or {}).items())[:10]]
        need = req.get("approvals_required", 1)
        roles = ", ".join(req.get("approver_roles", []))
        blocks: list[dict] = [
            {"type": "section", "text": {"type": "mrkdwn", "text": f":raised_hand: *{action}* requested by *{who}*\n{slack_escape(req.get('reason', ''))}"}},
        ]
        if fields:
            blocks.append({"type": "section", "fields": fields})
        ctx = req.get("context") or {}
        if ctx:
            blocks.append({"type": "context", "elements": [{"type": "mrkdwn", "text": f"Agent context: {slack_escape(json.dumps(ctx))[:500]}"}]})
        blocks.append({"type": "context", "elements": [{"type": "mrkdwn", "text": f"Needs {need} approval(s) from: {slack_escape(roles)} · expires {slack_escape(req.get('expires_at', ''))}"}]})
        buttons: list[dict] = [
            {"type": "button", "style": "primary", "text": {"type": "plain_text", "text": "Approve"}, "action_id": "agentguard_approve", "value": req.get("id", "")},
            {"type": "button", "style": "danger", "text": {"type": "plain_text", "text": "Deny"}, "action_id": "agentguard_deny", "value": req.get("id", "")},
        ]
        if url:
            buttons.append({"type": "button", "text": {"type": "plain_text", "text": "Open in AgentGuard"}, "url": url, "action_id": "agentguard_open"})
        blocks.append({"type": "actions", "block_id": f"agentguard:{req.get('id', '')}", "elements": buttons})
        return {"text": f"Approval needed: {action} by {who}", "blocks": blocks}
    titles = {
        "approval.decided": f"{action} by {who} was *{slack_escape(req.get('status', ''))}*",
        "action.blocked": f":no_entry: Blocked *{action}* by *{who}*: {slack_escape(req.get('reason', ''))}",
        "action.failed": f":warning: *{action}* by *{who}* failed: {slack_escape(req.get('error', ''))}",
        "action.stuck": f":hourglass: *{action}* by *{who}* did not finish; its outcome is unknown and needs checking",
        "agent.paused": f":octagonal_sign: Agent *{who}* was paused: {slack_escape(payload.get('reason', ''))}",
    }
    text = titles.get(event_type, f"AgentGuard event {slack_escape(event_type)}")
    if url:
        text += f" (<{url}|view>)"
    return {"text": text}

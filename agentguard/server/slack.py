"""Slack interactivity: Approve / Deny buttons on approval-request messages.

Setup (per Slack channel configured in AgentGuard):
  1. Create a Slack app with the bot scopes chat:write, users:read, users:read.email.
  2. Enable Interactivity and set the Request URL to the channel's interactions_url.
  3. Store the bot token and signing secret on the AgentGuard channel.

Requests are authenticated with Slack's signing secret (v0 HMAC over the raw
body, 5-minute replay window). A Slack user may decide only if their Slack
email matches a member of the organization with an eligible role.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import time
from collections.abc import Callable
from urllib.parse import parse_qs, urlsplit

from sqlalchemy import select

from agentguard.server.auth import Principal
from agentguard.server.connectors import ConnectorError
from agentguard.server.db import Membership, User
from agentguard.server.notifications import SLACK_API, Notifier, slack_escape
from agentguard.server.service import Gateway
from agentguard.server.store import ApiError, Store

log = logging.getLogger("agentguard.slack")


def verify_slack_signature(signing_secret: str, timestamp: str, body: bytes, signature: str, tolerance: int = 300) -> bool:
    try:
        ts = int(timestamp)
    except (TypeError, ValueError):
        return False
    if abs(time.time() - ts) > tolerance:
        return False
    base = f"v0:{ts}:".encode() + body
    expected = "v0=" + hmac.new(signing_secret.encode(), base, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature or "")


class SlackInteractions:
    def __init__(self, store: Store, gateway: Gateway, notifier: Notifier):
        self.store = store
        self.gateway = gateway
        self.notifier = notifier

    def handle(self, channel_id: str, headers: dict[str, str], body: bytes) -> tuple[dict, Callable[[], None] | None]:
        """Returns (immediate response, work to run after responding)."""
        found = self.notifier.channel_config(channel_id)
        if found is None or found[1] != "slack":
            raise ApiError(404, "unknown Slack channel")
        org_id, _, config = found
        if not verify_slack_signature(config["signing_secret"], headers.get("x-slack-request-timestamp", ""), body,
                                      headers.get("x-slack-signature", "")):
            raise ApiError(401, "invalid Slack signature")
        try:
            payload = json.loads(parse_qs(body.decode())["payload"][0])
        except (KeyError, IndexError, ValueError) as exc:
            raise ApiError(400, "malformed Slack payload") from exc
        if payload.get("type") != "block_actions" or not payload.get("actions"):
            return {}, None
        act = payload["actions"][0]
        decision = {"agentguard_approve": "approve", "agentguard_deny": "deny"}.get(act.get("action_id", ""))
        if decision is None:
            return {}, None  # e.g. the "Open in AgentGuard" link button
        request_id = act.get("value", "")
        slack_user = (payload.get("user") or {}).get("id", "")
        response_url = payload.get("response_url", "")

        def work() -> None:
            try:
                principal = self._principal_for(org_id, slack_user, config["bot_token"])
                if principal is None:
                    self._respond(response_url, {"response_type": "ephemeral", "replace_original": False,
                                                 "text": "Your Slack account is not linked to a member of this AgentGuard organization (your Slack email must match your AgentGuard email)."})
                    return
                result = self.gateway.decide(principal, request_id, decision, via="slack")
                verb = "approved" if decision == "approve" else "denied"
                if result["status"] == "pending_approval":
                    got = sum(1 for a in result["approvals"] if a["decision"] == "approve")
                    self._respond(response_url, {"response_type": "ephemeral", "replace_original": False,
                                                 "text": f"Recorded your approval ({got} of {result['approvals_required']}). Another approver is still needed."})
                    return
                outcome = result["status"] + (f": {result['error']}" if result.get("error") else "")
                self._respond(response_url, {"replace_original": True,
                                             "text": f"*{slack_escape(result['action'])}* by *{slack_escape(result['agent_slug'])}* was {verb} by {slack_escape(principal.label)} → {slack_escape(outcome)}"})
            except ApiError as exc:
                self._respond(response_url, {"response_type": "ephemeral", "replace_original": False, "text": f"Could not record your decision: {slack_escape(exc.message)}"})
            except Exception:
                log.exception("slack interaction failed")

        return {}, work

    def _principal_for(self, org_id: str, slack_user: str, bot_token: str) -> Principal | None:
        if not slack_user:
            return None
        with self.store.read() as s:
            row = s.execute(select(Membership, User).join(User, User.id == Membership.user_id)
                            .where(Membership.org_id == org_id, Membership.slack_user_id == slack_user)).first()
        if row is None:
            email = self._slack_email(slack_user, bot_token)
            if not email:
                return None
            with self.store.tx(org_id) as (s, org):
                row = s.execute(select(Membership, User).join(User, User.id == Membership.user_id)
                                .where(Membership.org_id == org_id, User.email == email.lower())).first()
                if row is None:
                    return None
                row[0].slack_user_id = slack_user
        membership, user = row
        if not user.is_active:
            return None
        return Principal("user", org_id, membership.role, user.email, user_id=user.id)

    def _slack_email(self, slack_user: str, bot_token: str) -> str | None:
        try:
            resp = self.notifier._post(f"{SLACK_API}/users.info", headers={"Authorization": f"Bearer {bot_token}"}, data={"user": slack_user})
            data = resp.json()
        except (ConnectorError, ValueError):
            return None
        if not data.get("ok"):
            return None
        return ((data.get("user") or {}).get("profile") or {}).get("email")

    def _respond(self, response_url: str, message: dict) -> None:
        if urlsplit(response_url).hostname != "hooks.slack.com":
            return
        try:
            self.notifier._post(response_url, json=message)
        except ConnectorError:
            log.warning("could not post Slack response")

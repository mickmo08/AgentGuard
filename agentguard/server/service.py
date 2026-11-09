"""Gateway service: agents, policies, secrets and the action lifecycle.

    submit ─► validate ─► policy ─┬─ allow  ─► execute ─► executed | failed
                                  ├─ review ─► pending_approval ─┬─ N approvals ─► execute
                                  │                              ├─ any deny    ─► denied
                                  │                              └─ ttl         ─► expired
                                  └─ block  ─► blocked
    execute that never reports back ─► unknown (reconciler; needs a human to check downstream)

Every transition is written together with its audit event and notifications
in one transaction holding the org lock. Connector calls happen outside it.
"""
from __future__ import annotations

import datetime as dt
import difflib
import fnmatch
import hashlib
import json
import os
import re
import time
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass
from importlib import resources
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from agentguard.server import audit
from agentguard.server.auth import Principal
from agentguard.server.config import PolicyDocument, PolicyError, RateLimit, parse_policy
from agentguard.server.connectors import ConnectorError, Executor, check_egress, validate_params
from agentguard.server.crypto import Vault
from agentguard.server.db import (
    ActionRequest,
    Agent,
    Approval,
    AuditEvent,
    Organization,
    PolicyVersion,
    Secret,
    iso,
    utcnow,
)
from agentguard.server.metrics import Metrics
from agentguard.server.notifications import Notifier
from agentguard.server.policy import PolicyEngine
from agentguard.server.security import constant_time_equal, digest, new_prefixed, parse_prefix
from agentguard.server.settings import Settings
from agentguard.server.store import ApiError, Store, new_id

SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{1,63}$")
SECRET_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,99}$")
TERMINAL = {"executed", "failed", "blocked", "denied", "expired"}
MAX_PARAMS_BYTES = 64 * 1024
MAX_CONTEXT_BYTES = 16 * 1024
MAX_SECRET_BYTES = 8 * 1024


def starter_policy() -> str:
    return resources.files("agentguard.server").joinpath("starter_policy.yaml").read_text(encoding="utf-8")


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


@dataclass
class ActivePolicy:
    version: int
    doc: PolicyDocument
    engine: PolicyEngine


class Gateway:
    def __init__(self, store: Store, settings: Settings, vault: Vault, notifier: Notifier, metrics: Metrics, executor: Executor | None = None):
        self.store = store
        self.settings = settings
        self.vault = vault
        self.notifier = notifier
        self.metrics = metrics
        self.executor = executor or Executor(egress_guard=None if settings.allow_private_network_egress else check_egress)
        self._policy_cache: dict[tuple[str, int], ActivePolicy] = {}

    # ================================================================ policies

    def _load_version(self, s, org_id: str, version: int) -> ActivePolicy | None:
        key = (org_id, version)
        cached = self._policy_cache.get(key)
        if cached:
            return cached
        pv = s.execute(select(PolicyVersion).where(PolicyVersion.org_id == org_id, PolicyVersion.version == version)).scalar_one_or_none()
        if pv is None:
            return None
        doc = PolicyDocument.model_validate(pv.document)
        ap = ActivePolicy(pv.version, doc, PolicyEngine(doc.policies))
        if len(self._policy_cache) > 2000:
            self._policy_cache.clear()
        self._policy_cache[key] = ap  # versions are immutable, so caching by (org, version) is always correct
        return ap

    def _active(self, s, org_id: str) -> ActivePolicy | None:
        version = s.execute(select(PolicyVersion.version).where(PolicyVersion.org_id == org_id, PolicyVersion.is_active.is_(True))).scalar_one_or_none()
        return self._load_version(s, org_id, version) if version is not None else None

    def _policy_problems(self, s, org_id: str, doc: PolicyDocument) -> tuple[list[str], list[str]]:
        errors, warnings = [], []
        stored = set(s.execute(select(Secret.name).where(Secret.org_id == org_id)).scalars())
        for cname, conn in doc.connectors.items():
            if not conn.secret:
                continue
            if conn.secret.startswith("env:"):
                if not self.settings.allow_env_secrets:
                    errors.append(f"connectors.{cname}.secret: env: references are disabled on this server; store the secret instead")
            elif not SECRET_NAME_RE.match(conn.secret):
                errors.append(f"connectors.{cname}.secret: {conn.secret!r} is not a valid secret name")
            elif conn.secret not in stored:
                warnings.append(f"connector {cname!r} uses secret {conn.secret!r}, which is not set yet; its actions will fail until it is")
        if not doc.policies.rules and doc.policies.default == "block":
            warnings.append("there are no rules, so every action will be blocked")
        if doc.policies.default == "allow":
            warnings.append("default is allow: any action no rule covers will run without review")
        return errors, warnings

    def validate_policy(self, principal: Principal, source: str) -> dict:
        try:
            doc = parse_policy(source)
        except PolicyError as exc:
            return {"valid": False, "errors": exc.errors, "warnings": []}
        with self.store.read() as s:
            errors, warnings = self._policy_problems(s, principal.org_id, doc)
        return {
            "valid": not errors, "errors": errors, "warnings": warnings,
            "summary": {"connectors": sorted(doc.connectors), "actions": sorted(doc.all_actions()), "rules": len(doc.policies.rules),
                        "rate_limits": len(doc.policies.rate_limits), "default": doc.policies.default},
        }

    def create_policy_version(self, principal: Principal | None, source: str, comment: str = "", activate: bool = True,
                              org_id: str | None = None, actor: str | None = None) -> dict:
        if principal is not None:
            principal.require("admin")
            org_id, actor = principal.org_id, principal.actor
        try:
            doc = parse_policy(source)
        except PolicyError as exc:
            raise ApiError(422, "policy is invalid: " + "; ".join(exc.errors)) from exc
        with self.store.tx(org_id) as (s, org):  # type: ignore[arg-type]
            errors, warnings = self._policy_problems(s, org.id, doc)
            if errors:
                raise ApiError(422, "policy is invalid: " + "; ".join(errors))
            latest = s.execute(select(func.max(PolicyVersion.version)).where(PolicyVersion.org_id == org.id)).scalar_one() or 0
            previous = s.execute(select(PolicyVersion).where(PolicyVersion.org_id == org.id, PolicyVersion.is_active.is_(True))).scalar_one_or_none()
            pv = PolicyVersion(id=new_id("pol"), org_id=org.id, version=latest + 1, source=source, document=doc.model_dump(mode="json"),
                               comment=comment.strip()[:1000], created_by=(actor or "system").split(":", 1)[-1], is_active=False)
            s.add(pv)
            audit.append(s, org, actor=actor or "system", event_type="policy.created",
                         data={"version": pv.version, "comment": pv.comment, "sha256": hashlib.sha256(source.encode()).hexdigest()})
            if activate:
                if previous:
                    previous.is_active = False
                    s.flush()  # keep at most one active row at any instant
                pv.is_active = True
                audit.append(s, org, actor=actor or "system", event_type="policy.activated",
                             data={"version": pv.version, "previous": previous.version if previous else None})
            out = self._policy_dict(pv)
        return {**out, "warnings": warnings}

    def activate_policy(self, principal: Principal, version: int) -> dict:
        principal.require("admin")
        with self.store.tx(principal.org_id) as (s, org):
            target = s.execute(select(PolicyVersion).where(PolicyVersion.org_id == org.id, PolicyVersion.version == version)).scalar_one_or_none()
            if target is None:
                raise ApiError(404, f"policy version {version} not found")
            doc = PolicyDocument.model_validate(target.document)
            errors, _ = self._policy_problems(s, org.id, doc)
            if errors:
                raise ApiError(422, "cannot activate: " + "; ".join(errors))
            current = s.execute(select(PolicyVersion).where(PolicyVersion.org_id == org.id, PolicyVersion.is_active.is_(True))).scalar_one_or_none()
            if current and current.id == target.id:
                return self._policy_dict(target)
            if current:
                current.is_active = False
                s.flush()
            target.is_active = True
            audit.append(s, org, actor=principal.actor, event_type="policy.activated",
                         data={"version": version, "previous": current.version if current else None})
            return self._policy_dict(target)

    def list_policy_versions(self, principal: Principal) -> list[dict]:
        with self.store.read() as s:
            rows = s.execute(select(PolicyVersion).where(PolicyVersion.org_id == principal.org_id).order_by(PolicyVersion.version.desc())).scalars().all()
        return [self._policy_dict(p) for p in rows]

    def get_policy_version(self, principal: Principal, version: int | None = None) -> dict:
        with self.store.read() as s:
            q = select(PolicyVersion).where(PolicyVersion.org_id == principal.org_id)
            q = q.where(PolicyVersion.version == version) if version is not None else q.where(PolicyVersion.is_active.is_(True))
            pv = s.execute(q).scalar_one_or_none()
            if pv is None:
                raise ApiError(404, "policy version not found")
            doc = PolicyDocument.model_validate(pv.document)
        return {**self._policy_dict(pv), "source": pv.source, "document": pv.document, "actions": sorted(doc.all_actions())}

    def diff_policy(self, principal: Principal, from_version: int, to_version: int) -> dict:
        a = self.get_policy_version(principal, from_version)["source"].splitlines(keepends=True)
        b = self.get_policy_version(principal, to_version)["source"].splitlines(keepends=True)
        return {"from": from_version, "to": to_version,
                "diff": "".join(difflib.unified_diff(a, b, fromfile=f"v{from_version}", tofile=f"v{to_version}"))}

    def simulate(self, principal: Principal, agent_slug: str, action: str, params: dict[str, Any]) -> dict:
        with self.store.read() as s:
            ap = self._active(s, principal.org_id)
        out: dict[str, Any] = {"agent": agent_slug, "action": action}
        if ap is None:
            return {**out, "valid": False, "errors": ["no active policy"]}
        resolved = ap.doc.action_spec(action)
        if resolved is None:
            return {**out, "valid": False, "errors": [f"unknown action {action!r}"]}
        errors = validate_params(resolved[3], params)
        if errors:
            return {**out, "valid": False, "errors": errors}
        return {**out, "valid": True, "policy_version": ap.version, **ap.engine.evaluate(agent_slug, action, params).as_dict(),
                "note": "dry run; rate limits and agent status are not applied"}

    @staticmethod
    def _policy_dict(p: PolicyVersion) -> dict:
        return {"version": p.version, "comment": p.comment, "created_by": p.created_by, "created_at": iso(p.created_at), "active": p.is_active}

    # ================================================================= secrets

    def put_secret(self, principal: Principal, name: str, value: str) -> dict:
        principal.require("admin")
        if not SECRET_NAME_RE.match(name):
            raise ApiError(422, "secret names are lowercase letters, digits and underscores, starting with a letter")
        if not value or len(value.encode()) > MAX_SECRET_BYTES:
            raise ApiError(422, "secret value must be between 1 byte and 8 KB")
        with self.store.tx(principal.org_id) as (s, org):
            sec = s.get(Secret, (org.id, name))
            created = sec is None
            if created:
                sec = Secret(org_id=org.id, name=name, ciphertext=self.vault.encrypt(value), created_by=principal.label)
                s.add(sec)
            else:
                sec.ciphertext, sec.updated_at = self.vault.encrypt(value), utcnow()
            audit.append(s, org, actor=principal.actor, event_type="secret.created" if created else "secret.updated", data={"name": name})
            return self._secret_dict(sec, [])

    def delete_secret(self, principal: Principal, name: str) -> None:
        principal.require("admin")
        with self.store.tx(principal.org_id) as (s, org):
            sec = s.get(Secret, (org.id, name))
            if sec is None:
                raise ApiError(404, "secret not found")
            s.delete(sec)
            audit.append(s, org, actor=principal.actor, event_type="secret.deleted", data={"name": name})

    def list_secrets(self, principal: Principal) -> list[dict]:
        with self.store.read() as s:
            rows = s.execute(select(Secret).where(Secret.org_id == principal.org_id).order_by(Secret.name)).scalars().all()
            ap = self._active(s, principal.org_id)
        used: dict[str, list[str]] = {}
        if ap:
            for cname, conn in ap.doc.connectors.items():
                if conn.secret:
                    used.setdefault(conn.secret, []).append(cname)
        return [self._secret_dict(r, used.get(r.name, [])) for r in rows]

    def _resolve_secret(self, org_id: str, name: str) -> str:
        if name.startswith("env:"):
            if not self.settings.allow_env_secrets:
                raise ConnectorError("env: secret references are disabled on this server")
            value = os.environ.get(name[4:])
            if not value:
                raise ConnectorError(f"environment variable {name[4:]} is not set on the gateway")
            return value
        with self.store.read() as s:
            sec = s.get(Secret, (org_id, name))
            if sec is None:
                raise ConnectorError(f"secret {name!r} is not set; an admin can add it under Secrets")
            return self.vault.decrypt(sec.ciphertext)

    @staticmethod
    def _secret_dict(sec: Secret, used_by: list[str]) -> dict:
        return {"name": sec.name, "created_by": sec.created_by, "created_at": iso(sec.created_at), "updated_at": iso(sec.updated_at), "used_by": used_by}

    # ================================================================== agents

    def create_agent(self, principal: Principal, slug: str, name: str = "", owner: str = "", description: str = "", environment: str = "production") -> tuple[dict, str]:
        principal.require("admin")
        if not SLUG_RE.match(slug):
            raise ApiError(422, "agent id must be 2-64 chars of lowercase letters, digits, '-' or '_'")
        key, prefix, key_hash = new_prefixed("ag")
        with self.store.tx(principal.org_id) as (s, org):
            if s.execute(select(Agent.id).where(Agent.org_id == org.id, Agent.slug == slug)).first():
                raise ApiError(409, f"agent {slug!r} already exists")
            agent = Agent(id=new_id("agt"), org_id=org.id, slug=slug, name=(name or slug).strip()[:200], owner=owner.strip()[:200],
                          description=description.strip()[:2000], environment=(environment or "production")[:32], key_prefix=prefix, key_hash=key_hash)
            s.add(agent)
            audit.append(s, org, actor=principal.actor, event_type="agent.created", agent_id=agent.id,
                         data={"slug": slug, "name": agent.name, "owner": agent.owner, "environment": agent.environment})
            return self._agent_dict(agent), key

    def update_agent(self, principal: Principal, agent_id: str, **fields: Any) -> dict:
        principal.require("admin")
        allowed = {"name", "owner", "description", "environment"}
        changes = {k: str(v).strip() for k, v in fields.items() if k in allowed and v is not None}
        with self.store.tx(principal.org_id) as (s, org):
            agent = self._agent_or_404(s, org.id, agent_id)
            for k, v in changes.items():
                setattr(agent, k, v[:2000])
            audit.append(s, org, actor=principal.actor, event_type="agent.updated", agent_id=agent.id, data=changes)
            return self._agent_dict(agent)

    def rotate_agent_key(self, principal: Principal, agent_id: str) -> str:
        principal.require("admin")
        key, prefix, key_hash = new_prefixed("ag")
        with self.store.tx(principal.org_id) as (s, org):
            agent = self._agent_or_404(s, org.id, agent_id)
            agent.key_prefix, agent.key_hash = prefix, key_hash
            audit.append(s, org, actor=principal.actor, event_type="agent.key_rotated", agent_id=agent.id)
        return key

    def set_agent_status(self, principal: Principal, agent_id: str, status: str, reason: str = "") -> dict:
        principal.require("admin")
        if status not in ("active", "paused", "disabled"):
            raise ApiError(422, "status must be active, paused or disabled")
        with self.store.tx(principal.org_id) as (s, org):
            agent = self._agent_or_404(s, org.id, agent_id)
            if agent.status == "disabled" and status != "disabled":
                raise ApiError(409, "disabled agents cannot be re-enabled; create a new agent")
            self._apply_status(s, org, agent, status, reason, principal.actor)
            return self._agent_dict(agent)

    def _apply_status(self, s, org: Organization, agent: Agent, status: str, reason: str, actor: str, request_id: str | None = None) -> None:
        agent.status = status
        agent.paused_reason = reason.strip()[:500] if status != "active" else ""
        event = {"active": "agent.resumed", "paused": "agent.paused", "disabled": "agent.disabled"}[status]
        audit.append(s, org, actor=actor, event_type=event, agent_id=agent.id, request_id=request_id, data={"reason": agent.paused_reason})
        if status == "paused":
            self.notifier.enqueue(s, org, "agent.paused", {"agent": {"id": agent.id, "slug": agent.slug, "name": agent.name},
                                                           "reason": agent.paused_reason, "url": f"{self.settings.public_url}/#/agents"})

    def list_agents(self, principal: Principal) -> list[dict]:
        since = utcnow() - dt.timedelta(hours=24)
        with self.store.read() as s:
            agents = s.execute(select(Agent).where(Agent.org_id == principal.org_id).order_by(Agent.created_at)).scalars().all()
            rows = s.execute(select(ActionRequest.agent_id, ActionRequest.status, func.count()).where(
                ActionRequest.org_id == principal.org_id, ActionRequest.created_at >= since).group_by(ActionRequest.agent_id, ActionRequest.status)).all()
        per: dict[str, dict[str, int]] = {}
        for agent_id, status, n in rows:
            per.setdefault(agent_id, {})[status] = n
        return [{**self._agent_dict(a), "last_24h": per.get(a.id, {})} for a in agents]

    def get_agent(self, principal: Principal, agent_id: str) -> dict:
        with self.store.read() as s:
            return self._agent_dict(self._agent_or_404(s, principal.org_id, agent_id))

    def authenticate_agent(self, key: str) -> Agent | None:
        prefix = parse_prefix(key) if key.startswith("ag_") else None
        if not prefix:
            return None
        key_hash = digest(key)
        with self.store.read() as s:
            rows = s.execute(select(Agent).where(Agent.key_prefix == prefix)).scalars().all()
            agent = next((a for a in rows if constant_time_equal(a.key_hash, key_hash)), None)
        if agent is None or agent.status == "disabled":
            return None
        now = utcnow()
        if agent.last_seen_at is None or (now - agent.last_seen_at).total_seconds() > 60:
            with self.store.tx_global() as s:
                a = s.get(Agent, agent.id)
                a.last_seen_at = now
        return agent

    def tools_for(self, agent: Agent) -> list[dict]:
        with self.store.read() as s:
            ap = self._active(s, agent.org_id)
        if ap is None:
            return []
        tools = []
        for name, spec in sorted(ap.doc.all_actions().items()):
            props = {}
            for k, p in spec.params.items():
                prop: dict[str, Any] = {"type": p.type}
                if p.description:
                    prop["description"] = p.description
                if p.enum is not None:
                    prop["enum"] = p.enum
                props[k] = prop
            tools.append({"name": name, "description": spec.description,
                          "input_schema": {"type": "object", "properties": props, "required": [k for k, p in spec.params.items() if p.required],
                                           "additionalProperties": False}})
        return tools

    def _agent_or_404(self, s, org_id: str, agent_id: str) -> Agent:
        agent = s.get(Agent, agent_id)
        if agent is None or agent.org_id != org_id:
            # Accept the slug too, which is what humans type.
            agent = s.execute(select(Agent).where(Agent.org_id == org_id, Agent.slug == agent_id)).scalar_one_or_none()
        if agent is None:
            raise ApiError(404, "agent not found")
        return agent

    @staticmethod
    def _agent_dict(a: Agent) -> dict:
        return {"id": a.id, "slug": a.slug, "name": a.name, "owner": a.owner, "description": a.description, "environment": a.environment,
                "status": a.status, "paused_reason": a.paused_reason, "key_prefix": f"ag_{a.key_prefix}_…",
                "created_at": iso(a.created_at), "last_seen_at": iso(a.last_seen_at)}

    # ================================================================= actions

    def submit_action(self, agent: Agent, action: str, params: dict[str, Any], idempotency_key: str | None = None,
                      run_id: str | None = None, context: dict[str, Any] | None = None) -> tuple[dict, bool]:
        context = context or {}
        params_json = _canonical(params)
        if len(params_json.encode()) > MAX_PARAMS_BYTES:
            raise ApiError(413, "params are larger than 64 KB")
        if len(_canonical(context).encode()) > MAX_CONTEXT_BYTES:
            raise ApiError(413, "context is larger than 16 KB")
        params_hash = hashlib.sha256(f"{action}\n{params_json}".encode()).hexdigest()
        idem = idempotency_key or new_id("idem")
        actor = f"agent:{agent.slug}"

        with self.store.tx(agent.org_id) as (s, org):
            existing = s.execute(select(ActionRequest).where(ActionRequest.org_id == org.id, ActionRequest.agent_id == agent.id,
                                                             ActionRequest.idempotency_key == idem)).scalar_one_or_none()
            if existing is not None:
                if existing.params_hash != params_hash:
                    raise ApiError(409, "idempotency key was already used with a different action or params")
                return self._serialize(s, existing), True

            current = s.get(Agent, agent.id)
            if current is None or current.status == "disabled":
                raise ApiError(401, "agent is disabled")
            ap = self._active(s, org.id)
            if ap is None:
                raise ApiError(409, "this organization has no active policy")
            resolved = ap.doc.action_spec(action)
            reject = None
            if resolved is None:
                reject = (404, f"unknown action {action!r}", {"reason": "unknown action"})
            else:
                errors = validate_params(resolved[3], params)
                if errors:
                    reject = (422, "; ".join(errors), {"reason": "invalid params", "errors": errors})
            if reject:
                audit.append(s, org, actor=actor, event_type="action.rejected", agent_id=agent.id, data={"action": action, **reject[2]})
                s.commit()
                raise ApiError(reject[0], reject[1])

            now = utcnow()
            limit: RateLimit | None = None
            approvals = None
            matched: list[str] = []
            if current.status == "paused":
                decision, reason, rule_id = "block", f"agent is paused: {current.paused_reason or 'no reason given'}", "agent-paused"
            else:
                result = ap.engine.evaluate(current.slug, action, params, recent_count=lambda lim: self._recent_count(s, agent.id, lim, now))
                decision, reason, rule_id, matched, limit, approvals = (result.decision, result.reason, result.rule_id,
                                                                        result.matched_rules, result.rate_limit, result.approvals)
            redact_keys = set(ap.doc.redact_params)
            req = ActionRequest(
                id=new_id("act"), org_id=org.id, agent_id=agent.id, agent_slug=current.slug, action=action,
                params_enc=self.vault.encrypt(params_json), params_view=audit.redact(params, redact_keys), params_hash=params_hash,
                idempotency_key=idem, run_id=run_id, context_view=audit.redact(context, redact_keys), policy_version=ap.version,
                decision=decision, rule_id=rule_id, reason=reason,
                status={"allow": "executing", "review": "pending_approval", "block": "blocked"}[decision],
                approvals_required=approvals.min if approvals else 0, approver_roles=approvals.roles if approvals else [],
                created_at=now, decided_at=None if decision == "review" else now,
                execution_started_at=now if decision == "allow" else None,
                expires_at=now + dt.timedelta(seconds=ap.doc.approval_ttl_seconds) if decision == "review" else None,
            )
            s.add(req)
            try:
                s.flush()
            except IntegrityError as exc:
                raise ApiError(409, "duplicate idempotency key") from exc
            audit.append(s, org, actor=actor, event_type="action.requested", request_id=req.id, agent_id=agent.id,
                         data={"action": action, "params": req.params_view, "run_id": run_id, "context": req.context_view})
            audit.append(s, org, actor="system", event_type="policy.evaluated", request_id=req.id, agent_id=agent.id,
                         data={"decision": decision, "rule_id": rule_id, "matched_rules": matched, "reason": reason,
                               "policy_version": ap.version, "approvals": approvals.model_dump() if approvals else None})
            if limit is not None and limit.pause_agent and current.status == "active":
                self._apply_status(s, org, current, "paused", f"auto-paused by rate limit {limit.id!r}", "system", request_id=req.id)
            if decision == "review":
                self.notifier.enqueue(s, org, "approval.requested", self._event_payload(s, req), req.id)
            elif decision == "block":
                self.notifier.enqueue(s, org, "action.blocked", self._event_payload(s, req), req.id)
            req_id = req.id
        self.metrics.actions.labels(decision).inc()
        if decision == "allow":
            self._execute(req_id, actor="system")
        return self.get_action(agent.org_id, req_id), False

    def _recent_count(self, s, agent_id: str, limit: RateLimit, now: dt.datetime) -> int:
        since = now - dt.timedelta(seconds=limit.window_seconds)
        actions = s.execute(select(ActionRequest.action).where(ActionRequest.agent_id == agent_id, ActionRequest.created_at >= since)).scalars()
        return sum(1 for a in actions if any(fnmatch.fnmatchcase(a, p) for p in limit.actions))

    def _execute(self, request_id: str, actor: str) -> None:
        with self.store.read() as s:
            req = s.get(ActionRequest, request_id)
            if req is None or req.status != "executing":
                return
            org_id, idem, version = req.org_id, req.idempotency_key, req.policy_version
            params = json.loads(self.vault.decrypt(req.params_enc))
            # Execute under the connector config of the policy version that approved the request.
            ap = self._load_version(s, org_id, version) if version is not None else None
            resolved = ap.doc.action_spec(req.action) if ap else None

        started = time.perf_counter()
        result: dict[str, Any] | None = None
        error: str | None = None
        if resolved is None:
            error = f"action {req.action!r} is not defined in policy version {version}"
        else:
            cname, conn, aname, spec = resolved
            try:
                result = self.executor.execute(cname, conn, aname, spec, params, idem, lambda n: self._resolve_secret(org_id, n))
            except ConnectorError as exc:
                error = str(exc)
            except Exception as exc:  # never leak internals to agents; record the class only
                error = f"internal connector error ({exc.__class__.__name__})"
        elapsed = time.perf_counter() - started
        self.metrics.execution_seconds.observe(elapsed)
        self.metrics.executions.labels("failed" if error else "executed").inc()

        with self.store.tx(org_id) as (s, org):
            req = s.get(ActionRequest, request_id)
            late = req.status == "unknown"  # the reconciler gave up on it, then it finished after all
            req.status = "failed" if error else "executed"
            req.result_view = audit.redact(result, set(ap.doc.redact_params) if ap else set()) if result is not None else None
            req.error = error
            req.executed_at = utcnow()
            req.duration_ms = int(elapsed * 1000)
            audit.append(s, org, actor=actor, event_type="action.failed" if error else "action.executed", request_id=req.id, agent_id=req.agent_id,
                         data={"duration_ms": req.duration_ms, "error": error, "result": req.result_view, "late": late or None})
            if error:
                self.notifier.enqueue(s, org, "action.failed", self._event_payload(s, req), req.id)

    def get_action(self, org_id: str, request_id: str, agent_id: str | None = None) -> dict:
        with self.store.read() as s:
            req = s.get(ActionRequest, request_id)
            if req is None or req.org_id != org_id or (agent_id is not None and req.agent_id != agent_id):
                raise ApiError(404, "action not found")
            return self._serialize(s, req)

    def action_detail(self, principal: Principal, request_id: str) -> dict:
        out = self.get_action(principal.org_id, request_id)
        out["timeline"] = list(reversed(self.audit_events(principal, request_id=request_id, limit=200)))
        out["can_decide"] = self._can_decide(principal, out)
        return out

    def list_actions(self, principal: Principal, *, agent: str | None = None, status: str | None = None, action: str | None = None,
                     run_id: str | None = None, before: str | None = None, limit: int = 100) -> list[dict]:
        with self.store.read() as s:
            q = select(ActionRequest).where(ActionRequest.org_id == principal.org_id)
            if agent:
                q = q.where((ActionRequest.agent_slug == agent) | (ActionRequest.agent_id == agent))
            if status:
                q = q.where(ActionRequest.status == status)
            if action:
                q = q.where(ActionRequest.action == action)
            if run_id:
                q = q.where(ActionRequest.run_id == run_id)
            if before:
                try:
                    q = q.where(ActionRequest.created_at < dt.datetime.fromisoformat(before.rstrip("Z")))
                except ValueError as exc:
                    raise ApiError(422, "before must be an ISO timestamp") from exc
            rows = s.execute(q.order_by(ActionRequest.created_at.desc()).limit(max(1, min(limit, 500)))).scalars().all()
            return [self._serialize(s, r) for r in rows]

    def pending_approvals(self, principal: Principal) -> list[dict]:
        items = self.list_actions(principal, status="pending_approval", limit=500)
        for it in items:
            it["can_decide"] = self._can_decide(principal, it)
        return items

    @staticmethod
    def _can_decide(principal: Principal, req: dict) -> bool:
        return (req["status"] == "pending_approval" and principal.kind == "user" and principal.role in req["approver_roles"]
                and not any(a["user"] == principal.label for a in req["approvals"]))

    # =============================================================== approvals

    def decide(self, principal: Principal, request_id: str, decision: str, note: str = "", via: str = "dashboard") -> dict:
        if decision not in ("approve", "deny"):
            raise ApiError(422, "decision must be approve or deny")
        if principal.kind != "user":
            raise ApiError(403, "only people can approve or deny actions; API tokens cannot")
        final = False
        with self.store.tx(principal.org_id) as (s, org):
            self._expire_overdue(s, org)
            req = s.get(ActionRequest, request_id)
            if req is None or req.org_id != org.id:
                raise ApiError(404, "action not found")
            if req.status != "pending_approval":
                raise ApiError(409, f"action is {req.status}, not pending approval")
            if principal.role not in req.approver_roles:
                raise ApiError(403, f"approving this action requires one of these roles: {', '.join(req.approver_roles)}")
            if s.execute(select(Approval.id).where(Approval.request_id == req.id, Approval.user_id == principal.user_id)).first():
                raise ApiError(409, "you have already voted on this action; a different person must provide the next approval")
            if decision == "approve":
                agent = s.get(Agent, req.agent_id)
                if agent is None or agent.status != "active":
                    raise ApiError(409, f"agent is {agent.status if agent else 'deleted'}; resume it before approving its actions")
            s.add(Approval(id=new_id("apr"), org_id=org.id, request_id=req.id, user_id=principal.user_id, user_email=principal.label,
                           decision=decision, note=note.strip()[:2000], via=via))
            s.flush()
            audit.append(s, org, actor=principal.actor, event_type="approval.vote", request_id=req.id, agent_id=req.agent_id,
                         data={"decision": decision, "note": note.strip()[:2000], "via": via})
            now = utcnow()
            if decision == "deny":
                req.status, req.decided_at, final = "denied", now, True
                audit.append(s, org, actor=principal.actor, event_type="approval.denied", request_id=req.id, agent_id=req.agent_id)
            else:
                approvals = s.execute(select(func.count()).select_from(Approval).where(Approval.request_id == req.id, Approval.decision == "approve")).scalar_one()
                if approvals >= req.approvals_required:
                    req.status, req.decided_at, req.execution_started_at, final = "executing", now, now, True
                    audit.append(s, org, actor="system", event_type="approval.granted", request_id=req.id, agent_id=req.agent_id,
                                 data={"approvals": approvals, "required": req.approvals_required})
            if final:
                self.notifier.enqueue(s, org, "approval.decided", self._event_payload(s, req), req.id)
            status = req.status
        self.metrics.approvals.labels(decision, via).inc()
        if status == "executing":
            self._execute(request_id, actor=principal.actor)
        return self.get_action(principal.org_id, request_id)

    def _expire_overdue(self, s, org: Organization) -> int:
        now = utcnow()
        overdue = s.execute(select(ActionRequest).where(ActionRequest.org_id == org.id, ActionRequest.status == "pending_approval",
                                                        ActionRequest.expires_at < now)).scalars().all()
        for req in overdue:
            req.status, req.decided_at = "expired", now
            audit.append(s, org, actor="system", event_type="approval.expired", request_id=req.id, agent_id=req.agent_id)
            self.notifier.enqueue(s, org, "approval.decided", self._event_payload(s, req), req.id)
        return len(overdue)

    # ============================================================ worker jobs

    def expire_all(self) -> int:
        with self.store.read() as s:
            org_ids = s.execute(select(ActionRequest.org_id).where(ActionRequest.status == "pending_approval",
                                                                   ActionRequest.expires_at < utcnow()).distinct()).scalars().all()
        total = 0
        for org_id in org_ids:
            with self.store.tx(org_id) as (s, org):
                total += self._expire_overdue(s, org)
        return total

    def mark_stuck(self) -> int:
        """Executions that never reported back (process crash, hung connector) become `unknown`.
        The gateway cannot know whether the downstream call happened, so a human must check."""
        cutoff = utcnow() - dt.timedelta(seconds=self.settings.stuck_after_seconds)
        with self.store.read() as s:
            rows = s.execute(select(ActionRequest.org_id, ActionRequest.id).where(ActionRequest.status == "executing",
                                                                                  ActionRequest.execution_started_at < cutoff)).all()
        for org_id, req_id in rows:
            with self.store.tx(org_id) as (s, org):
                req = s.get(ActionRequest, req_id)
                if req.status != "executing":
                    continue
                req.status = "unknown"
                req.error = "execution did not report a result; check the downstream system before retrying (the idempotency key prevents duplicates)"
                audit.append(s, org, actor="system", event_type="action.stuck", request_id=req.id, agent_id=req.agent_id,
                             data={"started_at": iso(req.execution_started_at)})
                self.notifier.enqueue(s, org, "action.stuck", self._event_payload(s, req), req.id)
        return len(rows)

    def count_pending(self) -> int:
        with self.store.read() as s:
            return s.execute(select(func.count()).select_from(ActionRequest).where(ActionRequest.status == "pending_approval")).scalar_one()

    # ================================================================= reading

    def overview(self, principal: Principal) -> dict:
        now = utcnow()
        since = now - dt.timedelta(hours=24)
        with self.store.read() as s:
            rows = s.execute(select(ActionRequest.status, ActionRequest.decision, ActionRequest.created_at, ActionRequest.action).where(
                ActionRequest.org_id == principal.org_id, ActionRequest.created_at >= since)).all()
            pending = s.execute(select(func.count()).select_from(ActionRequest).where(ActionRequest.org_id == principal.org_id,
                                                                                      ActionRequest.status == "pending_approval")).scalar_one()
            unknown = s.execute(select(func.count()).select_from(ActionRequest).where(ActionRequest.org_id == principal.org_id,
                                                                                      ActionRequest.status == "unknown")).scalar_one()
            agents = s.execute(select(Agent.status).where(Agent.org_id == principal.org_id)).scalars().all()
            ap = self._active(s, principal.org_id)
        hourly = [{"hour": iso((now - dt.timedelta(hours=23 - i)).replace(minute=0, second=0, microsecond=0)), "allow": 0, "review": 0, "block": 0} for i in range(24)]
        for _, decision, created, _a in rows:
            idx = 23 - int((now - created).total_seconds() // 3600)
            if 0 <= idx < 24:
                hourly[idx][decision] += 1
        return {
            "window": "24h", "actions": len(rows),
            "by_status": dict(Counter(r[0] for r in rows)), "by_decision": dict(Counter(r[1] for r in rows)),
            "top_actions": Counter(r[3] for r in rows).most_common(5),
            "pending_approvals": pending, "unknown_outcomes": unknown,
            "agents": {"total": len(agents), "active": agents.count("active"), "paused": agents.count("paused")},
            "policy_version": ap.version if ap else None, "hourly": hourly,
        }

    def audit_events(self, principal: Principal, *, request_id: str | None = None, agent_id: str | None = None,
                     event_type: str | None = None, before_seq: int | None = None, limit: int = 200) -> list[dict]:
        with self.store.read() as s:
            q = select(AuditEvent).where(AuditEvent.org_id == principal.org_id)
            if request_id:
                q = q.where(AuditEvent.request_id == request_id)
            if agent_id:
                q = q.where(AuditEvent.agent_id == agent_id)
            if event_type:
                q = q.where(AuditEvent.event_type == event_type)
            if before_seq:
                q = q.where(AuditEvent.seq < before_seq)
            return [audit.serialize(e) for e in s.execute(q.order_by(AuditEvent.seq.desc()).limit(max(1, min(limit, 1000)))).scalars()]

    def verify_audit(self, principal: Principal) -> dict:
        with self.store.read() as s:
            return audit.verify(s, principal.org_id)

    def export_audit(self, principal: Principal) -> Iterator[str]:
        with self.store.read() as s:
            for ev in audit.iter_events(s, principal.org_id):
                yield json.dumps(audit.serialize(ev), separators=(",", ":")) + "\n"

    # ================================================================ helpers

    def _event_payload(self, s, req: ActionRequest) -> dict:
        agent = s.get(Agent, req.agent_id)
        return {"request": self._serialize(s, req), "agent": {"id": req.agent_id, "slug": req.agent_slug, "name": agent.name if agent else req.agent_slug},
                "url": f"{self.settings.public_url}/#/actions/{req.id}"}

    def _serialize(self, s, r: ActionRequest) -> dict:
        votes = s.execute(select(Approval).where(Approval.request_id == r.id).order_by(Approval.created_at)).scalars().all()
        return {
            "id": r.id, "agent_id": r.agent_id, "agent_slug": r.agent_slug, "action": r.action, "params": r.params_view,
            "run_id": r.run_id, "context": r.context_view, "idempotency_key": r.idempotency_key, "policy_version": r.policy_version,
            "decision": r.decision, "rule_id": r.rule_id, "reason": r.reason, "status": r.status,
            "approvals_required": r.approvals_required, "approver_roles": r.approver_roles,
            "approvals": [{"user": v.user_email, "decision": v.decision, "note": v.note, "via": v.via, "at": iso(v.created_at)} for v in votes],
            "result": r.result_view, "error": r.error,
            "created_at": iso(r.created_at), "decided_at": iso(r.decided_at), "executed_at": iso(r.executed_at),
            "expires_at": iso(r.expires_at), "duration_ms": r.duration_ms, "terminal": r.status in TERMINAL,
        }

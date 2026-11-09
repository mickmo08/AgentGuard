"""Gateway service: the request lifecycle, independent of HTTP.

    submit ─► validate ─► policy ─┬─ allow  ─► execute ─► executed | failed
                                  ├─ review ─► pending_approval ─┬─ approve ─► execute
                                  │                              ├─ deny    ─► denied
                                  │                              └─ ttl     ─► expired
                                  └─ block  ─► blocked

Every transition writes an audit event in the same transaction as the state change.
"""
from __future__ import annotations

import datetime as dt
import fnmatch
import re
import threading
import time
import uuid
from collections import Counter
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from agentguard.server import audit
from agentguard.server.config import GatewayConfig, RateLimit
from agentguard.server.connectors import ConnectorError, Executor, validate_params
from agentguard.server.db import ActionRequest, Agent, AuditEvent, iso, utcnow
from agentguard.server.policy import PolicyEngine
from agentguard.server.security import constant_time_equal, generate_key, hash_key, parse_prefix

AGENT_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{1,63}$")
TERMINAL = {"executed", "failed", "blocked", "denied", "expired"}


class GatewayError(Exception):
    def __init__(self, status_code: int, message: str):
        super().__init__(message)
        self.status_code = status_code
        self.message = message


class Gateway:
    def __init__(self, config: GatewayConfig, sessions: sessionmaker, executor: Executor | None = None):
        self.config = config
        self.policy = PolicyEngine(config.policies)
        self.sessions = sessions
        self.executor = executor or Executor()
        self._redact_keys = set(config.redact_params)
        # Serializes writes so audit sequence numbers stay gap-free (see audit.py).
        self._lock = threading.RLock()

    # ------------------------------------------------------------------ agents

    def create_agent(self, agent_id: str, name: str, owner: str = "", description: str = "", actor: str = "human:admin") -> tuple[dict, str]:
        if not AGENT_ID_RE.match(agent_id):
            raise GatewayError(422, "agent id must be 2-64 chars of lowercase letters, digits, '-' or '_'")
        key, prefix, key_hash = generate_key()
        with self._lock, self.sessions() as s:
            if s.get(Agent, agent_id):
                raise GatewayError(409, f"agent {agent_id!r} already exists")
            agent = Agent(id=agent_id, name=name or agent_id, owner=owner, description=description, key_prefix=prefix, key_hash=key_hash)
            s.add(agent)
            audit.append(s, actor=actor, event_type="agent.created", agent_id=agent_id, data={"name": agent.name, "owner": owner})
            s.commit()
            return agent.as_dict(), key

    def rotate_key(self, agent_id: str, actor: str = "human:admin") -> str:
        key, prefix, key_hash = generate_key()
        with self._lock, self.sessions() as s:
            agent = self._agent_or_404(s, agent_id)
            agent.key_prefix, agent.key_hash = prefix, key_hash
            audit.append(s, actor=actor, event_type="agent.key_rotated", agent_id=agent_id)
            s.commit()
        return key

    def authenticate(self, key: str) -> Agent | None:
        prefix = parse_prefix(key)
        if prefix is None:
            return None
        digest = hash_key(key)
        with self.sessions() as s:
            for agent in s.execute(select(Agent).where(Agent.key_prefix == prefix)).scalars():
                if constant_time_equal(agent.key_hash, digest):
                    return agent
        return None

    def set_agent_status(self, agent_id: str, status: str, reason: str = "", actor: str = "human:admin") -> dict:
        if status not in ("active", "paused"):
            raise GatewayError(422, "status must be active or paused")
        with self._lock, self.sessions() as s:
            agent = self._agent_or_404(s, agent_id)
            agent.status = status
            agent.paused_reason = reason if status == "paused" else ""
            audit.append(
                s,
                actor=actor,
                event_type="agent.paused" if status == "paused" else "agent.resumed",
                agent_id=agent_id,
                data={"reason": reason},
            )
            s.commit()
            return agent.as_dict()

    def list_agents(self) -> list[dict]:
        since = utcnow() - dt.timedelta(hours=24)
        with self.sessions() as s:
            agents = s.execute(select(Agent).order_by(Agent.created_at)).scalars().all()
            rows = s.execute(select(ActionRequest.agent_id, ActionRequest.status).where(ActionRequest.created_at >= since)).all()
        per_agent: dict[str, Counter] = {}
        for agent_id, status in rows:
            per_agent.setdefault(agent_id, Counter())[status] += 1
        out = []
        for a in agents:
            d = a.as_dict()
            d["last_24h"] = dict(per_agent.get(a.id, Counter()))
            out.append(d)
        return out

    # ----------------------------------------------------------------- actions

    def submit_action(
        self,
        agent: Agent,
        action: str,
        params: dict[str, Any],
        idempotency_key: str | None = None,
        run_id: str | None = None,
        context: dict[str, Any] | None = None,
    ) -> tuple[dict, bool]:
        """Returns (request, replayed). replayed=True means the idempotency key was
        seen before and the original result is returned without re-executing."""
        idem = idempotency_key or uuid.uuid4().hex
        actor = f"agent:{agent.id}"
        with self._lock, self.sessions() as s:
            existing = s.execute(
                select(ActionRequest).where(ActionRequest.agent_id == agent.id, ActionRequest.idempotency_key == idem)
            ).scalar_one_or_none()
            if existing is not None:
                if existing.action != action or existing.params != params:
                    raise GatewayError(409, "idempotency key was already used with a different action or params")
                return self._serialize(existing), True

            current = s.get(Agent, agent.id)
            if current is None:
                raise GatewayError(401, "unknown agent")

            resolved = self.config.action_spec(action)
            if resolved is None:
                audit.append(s, actor=actor, event_type="action.rejected", agent_id=agent.id, data={"action": action, "reason": "unknown action"})
                s.commit()
                raise GatewayError(404, f"unknown action {action!r}")
            errors = validate_params(resolved[3], params)
            if errors:
                audit.append(s, actor=actor, event_type="action.rejected", agent_id=agent.id, data={"action": action, "reason": "invalid params", "errors": errors})
                s.commit()
                raise GatewayError(422, "; ".join(errors))

            now = utcnow()
            if current.status == "paused":
                decision, reason, rule_id, matched, limit = "block", f"agent is paused: {current.paused_reason or 'no reason given'}", "agent-paused", [], None
            else:
                result = self.policy.evaluate(agent.id, action, params, recent_count=lambda lim: self._recent_count(s, agent.id, lim, now))
                decision, reason, rule_id, matched, limit = result.decision, result.reason, result.rule_id, result.matched_rules, result.rate_limit

            req = ActionRequest(
                id=f"act_{uuid.uuid4().hex[:20]}",
                agent_id=agent.id,
                action=action,
                params=params,
                idempotency_key=idem,
                run_id=run_id,
                context=context or {},
                decision=decision,
                rule_id=rule_id,
                reason=reason,
                status={"allow": "executing", "review": "pending_approval", "block": "blocked"}[decision],
                created_at=now,
                decided_at=now if decision != "review" else None,
                expires_at=now + dt.timedelta(seconds=self.config.approval_ttl_seconds) if decision == "review" else None,
            )
            s.add(req)
            try:
                s.flush()
            except IntegrityError:  # concurrent duplicate idempotency key
                s.rollback()
                raise GatewayError(409, "duplicate idempotency key")
            audit.append(
                s,
                actor=actor,
                event_type="action.requested",
                request_id=req.id,
                agent_id=agent.id,
                data={"action": action, "params": self._redact(params), "run_id": run_id, "context": self._redact(context or {})},
            )
            audit.append(
                s,
                actor="system",
                event_type="policy.evaluated",
                request_id=req.id,
                agent_id=agent.id,
                data={"decision": decision, "rule_id": rule_id, "matched_rules": matched, "reason": reason},
            )
            if limit is not None and limit.pause_agent and current.status != "paused":
                current.status = "paused"
                current.paused_reason = f"auto-paused by rate limit {limit.id!r}"
                audit.append(
                    s,
                    actor="system",
                    event_type="agent.paused",
                    agent_id=agent.id,
                    request_id=req.id,
                    data={"reason": current.paused_reason, "incident": True},
                )
            s.commit()
            req_id = req.id

        if decision == "allow":
            self._execute(req_id, actor="system")
        return self.get_action(req_id), False

    def _recent_count(self, s: Session, agent_id: str, limit: RateLimit, now: dt.datetime) -> int:
        since = now - dt.timedelta(seconds=limit.window_seconds)
        actions = s.execute(
            select(ActionRequest.action).where(ActionRequest.agent_id == agent_id, ActionRequest.created_at >= since)
        ).scalars()
        return sum(1 for a in actions if any(fnmatch.fnmatchcase(a, p) for p in limit.actions))

    def _execute(self, request_id: str, actor: str) -> None:
        with self.sessions() as s:
            req = s.get(ActionRequest, request_id)
            assert req is not None and req.status == "executing"
            resolved = self.config.action_spec(req.action)
            params, idem = dict(req.params), req.idempotency_key

        started = time.perf_counter()
        result: dict[str, Any] | None = None
        error: str | None = None
        if resolved is None:  # action removed from config after the request was queued
            error = f"action {req.action!r} is no longer configured"
        else:
            cname, conn, aname, spec = resolved
            try:
                result = self.executor.execute(cname, conn, aname, spec, params, idem)
            except ConnectorError as exc:
                error = str(exc)
            except Exception as exc:  # never leak internals; record the class only
                error = f"internal connector error ({exc.__class__.__name__})"
        duration_ms = int((time.perf_counter() - started) * 1000)

        with self._lock, self.sessions() as s:
            req = s.get(ActionRequest, request_id)
            assert req is not None
            req.status = "failed" if error else "executed"
            req.result, req.error = result, error
            req.executed_at = utcnow()
            req.duration_ms = duration_ms
            audit.append(
                s,
                actor=actor,
                event_type="action.failed" if error else "action.executed",
                request_id=req.id,
                agent_id=req.agent_id,
                data={"duration_ms": duration_ms, "error": error, "result": self._redact(result) if result else None},
            )
            s.commit()

    def get_action(self, request_id: str, agent_id: str | None = None) -> dict:
        with self._lock, self.sessions() as s:
            self._expire_overdue(s)
            s.commit()
            req = s.get(ActionRequest, request_id)
            if req is None or (agent_id is not None and req.agent_id != agent_id):
                raise GatewayError(404, "action not found")
            return self._serialize(req)

    def list_actions(self, agent_id: str | None = None, status: str | None = None, run_id: str | None = None, limit: int = 100) -> list[dict]:
        with self._lock, self.sessions() as s:
            self._expire_overdue(s)
            s.commit()
            q = select(ActionRequest).order_by(ActionRequest.created_at.desc()).limit(min(limit, 500))
            if agent_id:
                q = q.where(ActionRequest.agent_id == agent_id)
            if status:
                q = q.where(ActionRequest.status == status)
            if run_id:
                q = q.where(ActionRequest.run_id == run_id)
            return [self._serialize(r) for r in s.execute(q).scalars()]

    # --------------------------------------------------------------- approvals

    def decide(self, request_id: str, approve: bool, reviewer: str, note: str = "") -> dict:
        reviewer = reviewer.strip()
        if not reviewer:
            raise GatewayError(422, "reviewer is required")
        actor = f"human:{reviewer}"
        with self._lock, self.sessions() as s:
            self._expire_overdue(s)
            req = s.get(ActionRequest, request_id)
            if req is None:
                raise GatewayError(404, "action not found")
            if req.status != "pending_approval":
                s.commit()
                raise GatewayError(409, f"action is {req.status}, not pending approval")
            if approve:
                agent = s.get(Agent, req.agent_id)
                if agent is not None and agent.status == "paused":
                    raise GatewayError(409, "agent is paused; resume it before approving its actions")
            new_status = "executing" if approve else "denied"
            # Conditional update guards against two reviewers acting at once.
            changed = s.execute(
                update(ActionRequest)
                .where(ActionRequest.id == request_id, ActionRequest.status == "pending_approval")
                .values(status=new_status, reviewer=reviewer, review_note=note, decided_at=utcnow())
            ).rowcount
            if changed != 1:
                raise GatewayError(409, "action was already decided")
            audit.append(
                s,
                actor=actor,
                event_type="approval.granted" if approve else "approval.denied",
                request_id=request_id,
                agent_id=req.agent_id,
                data={"note": note},
            )
            s.commit()
        if approve:
            self._execute(request_id, actor=actor)
        return self.get_action(request_id)

    def _expire_overdue(self, s: Session) -> None:
        now = utcnow()
        overdue = s.execute(
            select(ActionRequest).where(ActionRequest.status == "pending_approval", ActionRequest.expires_at < now)
        ).scalars().all()
        for req in overdue:
            req.status = "expired"
            req.decided_at = now
            audit.append(s, actor="system", event_type="approval.expired", request_id=req.id, agent_id=req.agent_id)

    # ---------------------------------------------------------- policy & audit

    def simulate(self, agent_id: str, action: str, params: dict[str, Any]) -> dict:
        resolved = self.config.action_spec(action)
        out: dict[str, Any] = {"agent_id": agent_id, "action": action}
        if resolved is None:
            return {**out, "valid": False, "errors": [f"unknown action {action!r}"]}
        errors = validate_params(resolved[3], params)
        if errors:
            return {**out, "valid": False, "errors": errors}
        return {**out, "valid": True, **self.policy.evaluate(agent_id, action, params).as_dict(), "note": "dry run; rate limits not applied"}

    def audit_events(self, request_id: str | None = None, agent_id: str | None = None, limit: int = 200) -> list[dict]:
        with self.sessions() as s:
            q = select(AuditEvent).order_by(AuditEvent.seq.desc()).limit(min(limit, 1000))
            if request_id:
                q = q.where(AuditEvent.request_id == request_id)
            if agent_id:
                q = q.where(AuditEvent.agent_id == agent_id)
            return [e.as_dict() for e in s.execute(q).scalars()]

    def verify_audit(self) -> dict:
        with self._lock, self.sessions() as s:
            return audit.verify(s)

    def stats(self) -> dict:
        since = utcnow() - dt.timedelta(hours=24)
        with self._lock, self.sessions() as s:
            self._expire_overdue(s)
            s.commit()
            rows = s.execute(select(ActionRequest.status, ActionRequest.decision).where(ActionRequest.created_at >= since)).all()
            pending = s.execute(select(ActionRequest.id).where(ActionRequest.status == "pending_approval")).all()
            agents = s.execute(select(Agent.status)).scalars().all()
        return {
            "window": "24h",
            "actions": len(rows),
            "by_status": dict(Counter(r[0] for r in rows)),
            "by_decision": dict(Counter(r[1] for r in rows)),
            "pending_approvals": len(pending),
            "agents": {"total": len(agents), "paused": sum(1 for a in agents if a == "paused")},
        }

    # ----------------------------------------------------------------- helpers

    def _agent_or_404(self, s: Session, agent_id: str) -> Agent:
        agent = s.get(Agent, agent_id)
        if agent is None:
            raise GatewayError(404, f"agent {agent_id!r} not found")
        return agent

    def _redact(self, value: Any) -> Any:
        return audit.redact(value, self._redact_keys)

    def _serialize(self, r: ActionRequest) -> dict:
        return {
            "id": r.id,
            "agent_id": r.agent_id,
            "action": r.action,
            "params": self._redact(r.params),
            "run_id": r.run_id,
            "context": self._redact(r.context),
            "idempotency_key": r.idempotency_key,
            "decision": r.decision,
            "rule_id": r.rule_id,
            "reason": r.reason,
            "status": r.status,
            "result": self._redact(r.result) if r.result else None,
            "error": r.error,
            "reviewer": r.reviewer,
            "review_note": r.review_note,
            "created_at": iso(r.created_at),
            "decided_at": iso(r.decided_at),
            "executed_at": iso(r.executed_at),
            "expires_at": iso(r.expires_at),
            "duration_ms": r.duration_ms,
            "terminal": r.status in TERMINAL,
        }

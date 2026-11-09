"""Tamper-evident audit log.

hash_n = sha256(prev_hash || canonical_json(seq, ts, actor, event_type, request_id, agent_id, data))

Callers must hold the gateway write lock while appending and committing, so
sequence numbers are assigned without gaps or races (single-process MVP; a
multi-node deployment would use a database advisory lock instead).
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from agentguard.server.db import AuditEvent, iso, utcnow

GENESIS = "0" * 64
REDACTED = "***redacted***"


def redact(value: Any, keys: set[str]) -> Any:
    if not keys:
        return value
    if isinstance(value, dict):
        return {k: (REDACTED if k in keys else redact(v, keys)) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v, keys) for v in value]
    return value


def _digest(prev_hash: str, ev: AuditEvent) -> str:
    payload = json.dumps(
        {
            "seq": ev.seq,
            "ts": iso(ev.ts),
            "actor": ev.actor,
            "event_type": ev.event_type,
            "request_id": ev.request_id,
            "agent_id": ev.agent_id,
            "data": ev.data,
        },
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256((prev_hash + payload).encode()).hexdigest()


def append(
    session: Session,
    *,
    actor: str,
    event_type: str,
    data: dict[str, Any] | None = None,
    request_id: str | None = None,
    agent_id: str | None = None,
) -> AuditEvent:
    last = session.execute(
        select(AuditEvent.seq, AuditEvent.hash).order_by(AuditEvent.seq.desc()).limit(1)
    ).first()
    seq, prev = (last[0] + 1, last[1]) if last else (1, GENESIS)
    # Round-trip data through JSON so the hashed form equals what the DB returns later.
    clean = json.loads(json.dumps(data or {}, default=str))
    ev = AuditEvent(
        seq=seq,
        ts=utcnow(),
        actor=actor,
        event_type=event_type,
        request_id=request_id,
        agent_id=agent_id,
        data=clean,
        prev_hash=prev,
    )
    # Millisecond precision is what iso() serializes; truncate so verification is stable.
    ev.ts = ev.ts.replace(microsecond=(ev.ts.microsecond // 1000) * 1000)
    ev.hash = _digest(prev, ev)
    session.add(ev)
    session.flush()
    return ev


def verify(session: Session) -> dict[str, Any]:
    prev = GENESIS
    expected_seq = 1
    count = 0
    for ev in session.execute(select(AuditEvent).order_by(AuditEvent.seq)).scalars():
        if ev.seq != expected_seq:
            return {"valid": False, "events": count, "broken_at": ev.seq, "problem": f"gap: expected seq {expected_seq}"}
        if ev.prev_hash != prev:
            return {"valid": False, "events": count, "broken_at": ev.seq, "problem": "prev_hash does not link to previous event"}
        if _digest(prev, ev) != ev.hash:
            return {"valid": False, "events": count, "broken_at": ev.seq, "problem": "event contents do not match its hash"}
        prev = ev.hash
        expected_seq += 1
        count += 1
    total = session.execute(select(func.count()).select_from(AuditEvent)).scalar_one()
    return {"valid": True, "events": count, "total": total, "head": prev}

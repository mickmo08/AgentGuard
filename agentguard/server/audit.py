"""Tamper-evident audit log, one hash chain per organization.

hash_n = sha256(prev_hash || canonical_json(org_id, seq, ts, actor, event_type, request_id, agent_id, data))

The caller must hold the org row lock (see db.py) so seq and head advance
atomically with the event insert. Editing, deleting or reordering any event
breaks verification from that point on; the org row stores the current head,
so truncating the tail is detected too.
"""
from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from agentguard.server.db import GENESIS, AuditEvent, Organization, iso, utcnow

REDACTED = "***redacted***"


def redact(value: Any, keys: set[str]) -> Any:
    if not keys:
        return value
    if isinstance(value, dict):
        return {k: (REDACTED if k.lower() in keys else redact(v, keys)) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v, keys) for v in value]
    return value


def _digest(prev_hash: str, ev: AuditEvent) -> str:
    payload = json.dumps(
        {
            "org_id": ev.org_id,
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
    org: Organization,
    *,
    actor: str,
    event_type: str,
    data: dict[str, Any] | None = None,
    request_id: str | None = None,
    agent_id: str | None = None,
) -> AuditEvent:
    ts = utcnow()
    ts = ts.replace(microsecond=(ts.microsecond // 1000) * 1000)  # iso() serializes milliseconds
    ev = AuditEvent(
        org_id=org.id,
        seq=org.audit_seq + 1,
        ts=ts,
        actor=actor,
        event_type=event_type,
        request_id=request_id,
        agent_id=agent_id,
        data=json.loads(json.dumps(data or {}, default=str)),  # hash what the DB will return
        prev_hash=org.audit_head,
    )
    ev.hash = _digest(org.audit_head, ev)
    org.audit_seq, org.audit_head = ev.seq, ev.hash
    session.add(ev)
    return ev


def serialize(ev: AuditEvent) -> dict[str, Any]:
    return {
        "seq": ev.seq,
        "ts": iso(ev.ts),
        "actor": ev.actor,
        "event_type": ev.event_type,
        "request_id": ev.request_id,
        "agent_id": ev.agent_id,
        "data": ev.data,
        "prev_hash": ev.prev_hash,
        "hash": ev.hash,
    }


def iter_events(session: Session, org_id: str, batch: int = 1000) -> Iterator[AuditEvent]:
    last = 0
    while True:
        rows = session.execute(
            select(AuditEvent).where(AuditEvent.org_id == org_id, AuditEvent.seq > last).order_by(AuditEvent.seq).limit(batch)
        ).scalars().all()
        if not rows:
            return
        yield from rows
        last = rows[-1].seq


def verify(session: Session, org_id: str) -> dict[str, Any]:
    org = session.get(Organization, org_id)
    if org is None:
        return {"valid": False, "events": 0, "problem": "unknown organization"}
    prev, expected, count = GENESIS, 1, 0
    for ev in iter_events(session, org_id):
        if ev.seq != expected:
            return {"valid": False, "events": count, "broken_at": ev.seq, "problem": f"gap: expected event {expected}"}
        if ev.prev_hash != prev:
            return {"valid": False, "events": count, "broken_at": ev.seq, "problem": "event does not link to the previous event"}
        if _digest(prev, ev) != ev.hash:
            return {"valid": False, "events": count, "broken_at": ev.seq, "problem": "event contents do not match its hash"}
        prev, expected, count = ev.hash, expected + 1, count + 1
    if count != org.audit_seq or prev != org.audit_head:
        return {"valid": False, "events": count, "broken_at": count + 1, "problem": "events are missing from the end of the chain"}
    return {"valid": True, "events": count, "head": prev}

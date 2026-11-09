"""Persistence: agents, action requests and the audit chain.

SQLite by default for local development; set AGENTGUARD_DATABASE_URL to a
Postgres URL in production.
"""
from __future__ import annotations

import datetime as dt
from typing import Any

from sqlalchemy import (
    JSON,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    create_engine,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker
from sqlalchemy.pool import StaticPool


def utcnow() -> dt.datetime:
    # Naive UTC everywhere: SQLite drops tzinfo, so mixing aware/naive values breaks comparisons.
    return dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)


def iso(ts: dt.datetime | None) -> str | None:
    return ts.isoformat(timespec="milliseconds") + "Z" if ts else None


class Base(DeclarativeBase):
    pass


class Agent(Base):
    __tablename__ = "agents"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(200))
    owner: Mapped[str] = mapped_column(String(200), default="")
    description: Mapped[str] = mapped_column(Text, default="")
    key_prefix: Mapped[str] = mapped_column(String(16), index=True)
    key_hash: Mapped[str] = mapped_column(String(128))
    status: Mapped[str] = mapped_column(String(16), default="active")  # active | paused
    paused_reason: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "owner": self.owner,
            "description": self.description,
            "status": self.status,
            "paused_reason": self.paused_reason,
            "key_prefix": self.key_prefix,
            "created_at": iso(self.created_at),
        }


class ActionRequest(Base):
    __tablename__ = "action_requests"
    __table_args__ = (
        UniqueConstraint("agent_id", "idempotency_key", name="uq_agent_idempotency"),
        Index("ix_action_agent_created", "agent_id", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    agent_id: Mapped[str] = mapped_column(ForeignKey("agents.id"))
    action: Mapped[str] = mapped_column(String(200), index=True)
    params: Mapped[dict] = mapped_column(JSON)
    idempotency_key: Mapped[str] = mapped_column(String(200))
    run_id: Mapped[str | None] = mapped_column(String(200), nullable=True, index=True)
    context: Mapped[dict] = mapped_column(JSON, default=dict)  # agent-supplied justification, user request, etc.

    decision: Mapped[str] = mapped_column(String(16))  # allow | review | block
    rule_id: Mapped[str | None] = mapped_column(String(200), nullable=True)
    reason: Mapped[str] = mapped_column(Text, default="")
    # pending_approval | executing | executed | failed | blocked | denied | expired
    status: Mapped[str] = mapped_column(String(24), index=True)

    result: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    reviewer: Mapped[str | None] = mapped_column(String(200), nullable=True)
    review_note: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)
    decided_at: Mapped[dt.datetime | None] = mapped_column(DateTime, nullable=True)
    executed_at: Mapped[dt.datetime | None] = mapped_column(DateTime, nullable=True)
    expires_at: Mapped[dt.datetime | None] = mapped_column(DateTime, nullable=True)
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)


class AuditEvent(Base):
    """Append-only, hash-chained log. Each row commits to the previous row's hash,
    so editing or deleting any past event breaks verification from that point on."""

    __tablename__ = "audit_events"

    seq: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=False)
    ts: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)
    actor: Mapped[str] = mapped_column(String(200))  # agent:<id> | human:<name> | system
    event_type: Mapped[str] = mapped_column(String(64), index=True)
    request_id: Mapped[str | None] = mapped_column(String(40), nullable=True, index=True)
    agent_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    data: Mapped[dict] = mapped_column(JSON, default=dict)
    prev_hash: Mapped[str] = mapped_column(String(64))
    hash: Mapped[str] = mapped_column(String(64))

    def as_dict(self) -> dict[str, Any]:
        return {
            "seq": self.seq,
            "ts": iso(self.ts),
            "actor": self.actor,
            "event_type": self.event_type,
            "request_id": self.request_id,
            "agent_id": self.agent_id,
            "data": self.data,
            "prev_hash": self.prev_hash,
            "hash": self.hash,
        }


def make_sessionmaker(database_url: str) -> sessionmaker:
    kwargs: dict[str, Any] = {}
    if database_url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}
        if database_url in ("sqlite://", "sqlite:///:memory:"):
            kwargs["poolclass"] = StaticPool
    engine = create_engine(database_url, **kwargs)
    Base.metadata.create_all(engine)
    return sessionmaker(engine, expire_on_commit=False)

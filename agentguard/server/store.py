"""Transaction helpers shared by every service.

`tx(org_id)` opens a transaction and locks the organization row first, which
is the single lock ordering rule for the whole codebase (see db.py).
"""
from __future__ import annotations

import threading
import uuid
from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from agentguard.server.db import Organization


class ApiError(Exception):
    def __init__(self, status_code: int, message: str, code: str | None = None):
        super().__init__(message)
        self.status_code = status_code
        self.message = message
        self.code = code or {400: "bad_request", 401: "unauthorized", 403: "forbidden", 404: "not_found",
                             409: "conflict", 422: "invalid", 429: "rate_limited"}.get(status_code, "error")


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:24]}"


class Store:
    def __init__(self, sessions: sessionmaker):
        self.sessions = sessions
        dialect = sessions.kw["bind"].dialect.name
        # SQLite allows one writer at a time; serializing in-process avoids "database is locked".
        # Postgres relies on row locks alone, so it scales across processes and replicas.
        self._write_lock: threading.RLock | None = threading.RLock() if dialect == "sqlite" else None

    @contextmanager
    def _writer(self) -> Iterator[None]:
        if self._write_lock is None:
            yield
        else:
            with self._write_lock:
                yield

    @contextmanager
    def tx(self, org_id: str) -> Iterator[tuple[Session, Organization]]:
        with self._writer(), self.sessions() as s:
            org = s.execute(select(Organization).where(Organization.id == org_id).with_for_update()).scalar_one_or_none()
            if org is None:
                raise ApiError(404, "organization not found")
            yield s, org
            s.commit()

    @contextmanager
    def tx_global(self) -> Iterator[Session]:
        """For rows that belong to no single org (users, new organizations)."""
        with self._writer(), self.sessions() as s:
            yield s
            s.commit()

    @contextmanager
    def read(self) -> Iterator[Session]:
        with self.sessions() as s:
            yield s

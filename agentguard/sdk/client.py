"""Python SDK.

    from agentguard import AgentGuard

    guard = AgentGuard("http://localhost:8080", api_key=os.environ["AGENTGUARD_KEY"])
    refund = guard.act("payments.refund", {"customer_id": "cus_alice", "amount": 20})

The agent process holds only its AgentGuard key, never the Stripe/CRM/etc.
credentials. That is what makes enforcement real rather than advisory.
"""
from __future__ import annotations

import contextlib
import contextvars
import time
import uuid
from typing import Any, Callable, Iterator

import httpx

_run_id: contextvars.ContextVar[str | None] = contextvars.ContextVar("agentguard_run_id", default=None)


class AgentGuardError(Exception):
    def __init__(self, message: str, request: dict[str, Any] | None = None):
        super().__init__(message)
        self.request = request or {}

    @property
    def request_id(self) -> str | None:
        return self.request.get("id")


class ActionBlocked(AgentGuardError):
    """Policy blocked the action. It was not executed."""


class ApprovalDenied(AgentGuardError):
    """A human reviewer denied the action."""


class ApprovalExpired(AgentGuardError):
    """Nobody reviewed the action before its approval window closed."""


class ApprovalPending(AgentGuardError):
    """The action is still waiting for a human (wait=False, or wait_timeout elapsed)."""


class ActionFailed(AgentGuardError):
    """Policy allowed the action but the downstream system call failed."""


_TERMINAL_ERRORS = {
    "blocked": ActionBlocked,
    "denied": ApprovalDenied,
    "expired": ApprovalExpired,
    "failed": ActionFailed,
}


def _raise_for_outcome(req: dict[str, Any]) -> None:
    status = req.get("status")
    if status in _TERMINAL_ERRORS:
        detail = req.get("error") if status == "failed" else (req.get("review_note") or req.get("reason"))
        raise _TERMINAL_ERRORS[status](f"{req.get('action')} {status}: {detail}", req)


class AgentGuard:
    def __init__(
        self,
        base_url: str,
        api_key: str,
        timeout: float = 30.0,
        max_retries: int = 2,
        client: httpx.Client | None = None,
    ):
        self._client = client or httpx.Client(base_url=base_url.rstrip("/"), timeout=timeout)
        self._headers = {"Authorization": f"Bearer {api_key}"}
        self._max_retries = max_retries

    # -------------------------------------------------------------- low level

    def _request(self, method: str, path: str, **kwargs: Any) -> Any:
        last_exc: Exception | None = None
        for attempt in range(self._max_retries + 1):
            try:
                resp = self._client.request(method, path, headers=self._headers, **kwargs)
            except httpx.TransportError as exc:  # safe to retry: submissions carry an idempotency key
                last_exc = exc
                time.sleep(min(0.25 * 2**attempt, 2.0))
                continue
            if resp.status_code >= 400:
                try:
                    detail = resp.json().get("detail", resp.text)
                except ValueError:
                    detail = resp.text
                raise AgentGuardError(f"HTTP {resp.status_code}: {detail}")
            return resp.json()
        raise AgentGuardError(f"gateway unreachable: {last_exc}")

    def submit(
        self,
        action: str,
        params: dict[str, Any] | None = None,
        *,
        idempotency_key: str | None = None,
        run_id: str | None = None,
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Submit an action and return the request record without raising on policy outcomes."""
        body = {
            "action": action,
            "params": params or {},
            "idempotency_key": idempotency_key or uuid.uuid4().hex,
            "run_id": run_id or _run_id.get(),
            "context": context or {},
        }
        return self._request("POST", "/v1/actions", json=body)

    def get(self, request_id: str) -> dict[str, Any]:
        return self._request("GET", f"/v1/actions/{request_id}")

    def wait(self, request_id: str, timeout: float = 300.0, poll_interval: float = 1.0) -> dict[str, Any]:
        deadline = time.monotonic() + timeout
        while True:
            req = self.get(request_id)
            if req["terminal"] or time.monotonic() >= deadline:
                return req
            time.sleep(poll_interval)

    def tools(self) -> list[dict[str, Any]]:
        """JSON-schema tool definitions for every action the gateway brokers."""
        return self._request("GET", "/v1/tools")

    # ------------------------------------------------------------- high level

    def act(
        self,
        action: str,
        params: dict[str, Any] | None = None,
        *,
        idempotency_key: str | None = None,
        run_id: str | None = None,
        context: dict[str, Any] | None = None,
        wait: bool = True,
        wait_timeout: float = 300.0,
        poll_interval: float = 1.0,
    ) -> dict[str, Any]:
        """Perform an action and return the downstream result.

        Raises ActionBlocked, ApprovalDenied, ApprovalExpired, ApprovalPending or ActionFailed.
        """
        req = self.submit(action, params, idempotency_key=idempotency_key, run_id=run_id, context=context)
        if req["status"] == "pending_approval":
            if not wait:
                raise ApprovalPending(f"{action} is awaiting approval", req)
            req = self.wait(req["id"], timeout=wait_timeout, poll_interval=poll_interval)
            if req["status"] == "pending_approval":
                raise ApprovalPending(f"{action} still awaiting approval after {wait_timeout}s", req)
        _raise_for_outcome(req)
        return req["result"] or {}

    def handler(self, action: str, *, wait: bool = False) -> Callable[..., dict[str, Any]]:
        """A tool function for an LLM agent loop. It never raises on policy outcomes;
        it returns a dict the model can read and react to (e.g. tell the customer a
        manager will review the refund)."""

        def call(**params: Any) -> dict[str, Any]:
            try:
                return {"ok": True, "status": "executed", "result": self.act(action, params, wait=wait)}
            except ApprovalPending as exc:
                return {"ok": False, "status": "pending_approval", "request_id": exc.request_id,
                        "message": "This action needs human approval. It will run once a reviewer approves it."}
            except AgentGuardError as exc:
                status = exc.request.get("status", "error")
                return {"ok": False, "status": status, "request_id": exc.request_id, "message": str(exc)}

        call.__name__ = action.replace(".", "_")
        call.__doc__ = f"AgentGuard-brokered action {action}"
        return call

    @contextlib.contextmanager
    def run(self, run_id: str | None = None) -> Iterator[str]:
        """Group every action inside the block under one run id (one agent task)."""
        rid = run_id or f"run_{uuid.uuid4().hex[:16]}"
        token = _run_id.set(rid)
        try:
            yield rid
        finally:
            _run_id.reset(token)

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "AgentGuard":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()


class AgentGuardAdmin:
    """Thin operator client (used by the CLI and demo)."""

    def __init__(self, base_url: str, admin_token: str, timeout: float = 30.0, client: httpx.Client | None = None):
        self._client = client or httpx.Client(base_url=base_url.rstrip("/"), timeout=timeout)
        self._headers = {"Authorization": f"Bearer {admin_token}"}

    def _call(self, method: str, path: str, **kwargs: Any) -> Any:
        resp = self._client.request(method, path, headers=self._headers, **kwargs)
        if resp.status_code >= 400:
            raise AgentGuardError(f"HTTP {resp.status_code}: {resp.text}")
        return resp.json()

    def create_agent(self, agent_id: str, name: str = "", owner: str = "", description: str = "") -> dict:
        return self._call("POST", "/v1/admin/agents", json={"id": agent_id, "name": name, "owner": owner, "description": description})

    def approvals(self) -> list[dict]:
        return self._call("GET", "/v1/admin/approvals")

    def approve(self, request_id: str, reviewer: str, note: str = "") -> dict:
        return self._call("POST", f"/v1/admin/approvals/{request_id}/approve", json={"reviewer": reviewer, "note": note})

    def deny(self, request_id: str, reviewer: str, note: str = "") -> dict:
        return self._call("POST", f"/v1/admin/approvals/{request_id}/deny", json={"reviewer": reviewer, "note": note})

    def pause(self, agent_id: str, reason: str = "") -> dict:
        return self._call("POST", f"/v1/admin/agents/{agent_id}/pause", json={"reason": reason})

    def resume(self, agent_id: str) -> dict:
        return self._call("POST", f"/v1/admin/agents/{agent_id}/resume")

    def verify_audit(self) -> dict:
        return self._call("GET", "/v1/admin/audit/verify")

    def simulate(self, agent_id: str, action: str, params: dict) -> dict:
        return self._call("POST", "/v1/admin/policies/simulate", json={"agent_id": agent_id, "action": action, "params": params})

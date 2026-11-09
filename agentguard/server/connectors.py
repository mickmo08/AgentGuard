"""Credential-brokered connectors.

The gateway, not the agent, holds the credentials for downstream systems.
Agents request "<connector>.<action>" with params; if policy allows, the
gateway executes the call with a secret read from its own environment.

Connector types:
  mock_payments  in-memory payments backend (stands in for Stripe in demos/tests)
  mock_email     in-memory outbox
  http           generic REST call with the secret injected as an auth header
"""
from __future__ import annotations

import os
import string
import threading
import uuid
from typing import Any
from urllib.parse import quote

import httpx

from agentguard.server.config import ActionSpec, ConnectorConfig, ParamSpec


class ConnectorError(Exception):
    pass


def _spec(description: str, **params: ParamSpec) -> ActionSpec:
    return ActionSpec(description=description, params=params)


_BUILTINS: dict[str, dict[str, ActionSpec]] = {
    "mock_payments": {
        "refund": _spec(
            "Refund a customer",
            customer_id=ParamSpec(type="string"),
            amount=ParamSpec(type="number", description="Amount in major currency units"),
            currency=ParamSpec(type="string", required=False),
            reason=ParamSpec(type="string", required=False),
        ),
        "get_customer": _spec("Look up a customer", customer_id=ParamSpec(type="string")),
    },
    "mock_email": {
        "send": _spec(
            "Send an email",
            to=ParamSpec(type="string"),
            subject=ParamSpec(type="string"),
            body=ParamSpec(type="string"),
        ),
    },
    "http": {},
}


def builtin_actions(connector_type: str) -> dict[str, ActionSpec]:
    return _BUILTINS.get(connector_type, {})


_TYPE_CHECKS = {
    "string": lambda v: isinstance(v, str),
    "number": lambda v: isinstance(v, (int, float)) and not isinstance(v, bool),
    "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
    "boolean": lambda v: isinstance(v, bool),
    "object": lambda v: isinstance(v, dict),
    "array": lambda v: isinstance(v, list),
}


def validate_params(spec: ActionSpec, params: dict[str, Any]) -> list[str]:
    """Strict validation: required params present, types correct, no unknown params."""
    errors: list[str] = []
    for name, p in spec.params.items():
        if name not in params:
            if p.required:
                errors.append(f"missing required param {name!r}")
            continue
        if not _TYPE_CHECKS[p.type](params[name]):
            errors.append(f"param {name!r} must be of type {p.type}")
    unknown = set(params) - set(spec.params)
    if unknown:
        errors.append(f"unknown params: {sorted(unknown)}")
    return errors


class MockBackends:
    """In-memory downstream systems, so the whole flow runs without real accounts."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.refunds: list[dict[str, Any]] = []
        self.outbox: list[dict[str, Any]] = []
        self.customers: dict[str, dict[str, Any]] = {
            "cus_alice": {"id": "cus_alice", "name": "Alice Chen", "plan": "pro", "lifetime_value": 1840.0},
            "cus_bob": {"id": "cus_bob", "name": "Bob Okafor", "plan": "starter", "lifetime_value": 210.0},
        }


def _resolve_secret(conn: ConnectorConfig, connector_name: str) -> str | None:
    if not conn.secret_env:
        return None
    value = os.environ.get(conn.secret_env)
    if not value:
        raise ConnectorError(
            f"connector {connector_name!r} is missing its credential (env var {conn.secret_env} is not set)"
        )
    return value


class Executor:
    def __init__(self, mocks: MockBackends | None = None, http_client: httpx.Client | None = None):
        self.mocks = mocks or MockBackends()
        self._http = http_client

    def execute(
        self,
        connector_name: str,
        conn: ConnectorConfig,
        action_name: str,
        spec: ActionSpec,
        params: dict[str, Any],
        idempotency_key: str,
    ) -> dict[str, Any]:
        secret = _resolve_secret(conn, connector_name)
        if conn.type == "mock_payments":
            return self._mock_payments(action_name, params, idempotency_key)
        if conn.type == "mock_email":
            return self._mock_email(action_name, params)
        if conn.type == "http":
            return self._http_call(conn, spec, params, secret, idempotency_key)
        raise ConnectorError(f"unsupported connector type {conn.type!r}")

    def _mock_payments(self, action: str, params: dict[str, Any], idem: str) -> dict[str, Any]:
        m = self.mocks
        with m.lock:
            customer = m.customers.get(params["customer_id"])
            if customer is None:
                raise ConnectorError(f"no such customer {params['customer_id']!r}")
            if action == "get_customer":
                return dict(customer)
            if action == "refund":
                for r in m.refunds:  # downstream idempotency, as Stripe does
                    if r["idempotency_key"] == idem:
                        return dict(r)
                refund = {
                    "refund_id": f"re_{uuid.uuid4().hex[:12]}",
                    "customer_id": customer["id"],
                    "amount": params["amount"],
                    "currency": params.get("currency", "usd"),
                    "status": "succeeded",
                    "idempotency_key": idem,
                }
                m.refunds.append(refund)
                return dict(refund)
        raise ConnectorError(f"unsupported action {action!r}")

    def _mock_email(self, action: str, params: dict[str, Any]) -> dict[str, Any]:
        if action != "send":
            raise ConnectorError(f"unsupported action {action!r}")
        msg = {"message_id": f"msg_{uuid.uuid4().hex[:12]}", **params}
        with self.mocks.lock:
            self.mocks.outbox.append(msg)
        return {"message_id": msg["message_id"], "status": "queued"}

    def _http_call(
        self,
        conn: ConnectorConfig,
        spec: ActionSpec,
        params: dict[str, Any],
        secret: str | None,
        idem: str,
    ) -> dict[str, Any]:
        path_fields = {f for _, f, _, _ in string.Formatter().parse(spec.path) if f}
        missing = path_fields - set(params)
        if missing:
            raise ConnectorError(f"path params missing: {sorted(missing)}")
        # Encode path params fully so a value like "../admin" cannot change the route.
        path = spec.path.format(**{k: quote(str(params[k]), safe="") for k in path_fields})
        rest = {k: v for k, v in params.items() if k not in path_fields}
        headers = {"Idempotency-Key": idem}
        if secret:
            headers[conn.auth_header] = f"{conn.auth_scheme} {secret}".strip()
        method = spec.method.upper()
        client = self._http or httpx.Client(timeout=conn.timeout_seconds)
        try:
            resp = client.request(
                method,
                conn.base_url.rstrip("/") + path,  # type: ignore[union-attr]
                headers=headers,
                params=rest if method in ("GET", "DELETE") else None,
                json=rest if method not in ("GET", "DELETE") else None,
            )
        except httpx.HTTPError as exc:
            raise ConnectorError(f"downstream request failed: {exc.__class__.__name__}") from exc
        finally:
            if self._http is None:
                client.close()
        if resp.status_code >= 400:
            raise ConnectorError(f"downstream returned HTTP {resp.status_code}")
        try:
            body: Any = resp.json()
        except ValueError:
            body = {"text": resp.text[:2000]}
        return {"status_code": resp.status_code, "body": body}

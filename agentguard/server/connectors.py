"""Credential-brokered connectors.

The gateway, not the agent, holds downstream credentials. Agents request
"<connector>.<action>" with params; when policy allows, the gateway executes
the call using a secret from the organization's encrypted store.

Connector types:
  stripe         Stripe refunds and payment lookups (real API)
  http           any REST API; secret injected as an auth header
  mock_payments  in-memory payments backend for demos and tests
  mock_email     in-memory outbox for demos and tests
"""
from __future__ import annotations

import ipaddress
import socket
import string
import threading
import uuid
from collections.abc import Callable
from decimal import Decimal, InvalidOperation
from typing import Any
from urllib.parse import quote, urlsplit

import httpx

from agentguard.server.config import ActionSpec, ConnectorConfig, ParamSpec

SecretResolver = Callable[[str], str]


class ConnectorError(Exception):
    """A failure the gateway records on the action and shows to the agent. Never include secrets."""


def _spec(description: str, **params: ParamSpec) -> ActionSpec:
    return ActionSpec(description=description, params=params)


_BUILTINS: dict[str, dict[str, ActionSpec]] = {
    "stripe": {
        "refund": _spec(
            "Refund all or part of a Stripe payment",
            payment_intent=ParamSpec(type="string", description="PaymentIntent id (pi_...)"),
            amount=ParamSpec(type="number", description="Amount to refund in major units, e.g. 12.50"),
            currency=ParamSpec(type="string", description="Three-letter ISO currency code, e.g. usd"),
            reason=ParamSpec(type="string", required=False, enum=["duplicate", "fraudulent", "requested_by_customer"]),
        ),
        "get_payment": _spec(
            "Look up a Stripe PaymentIntent",
            payment_intent=ParamSpec(type="string", description="PaymentIntent id (pi_...)"),
        ),
    },
    "mock_payments": {
        "refund": _spec(
            "Refund a customer (demo backend)",
            customer_id=ParamSpec(type="string"),
            amount=ParamSpec(type="number", description="Amount in major currency units"),
            currency=ParamSpec(type="string", required=False),
            reason=ParamSpec(type="string", required=False),
        ),
        "get_customer": _spec("Look up a customer (demo backend)", customer_id=ParamSpec(type="string")),
    },
    "mock_email": {
        "send": _spec(
            "Send an email (demo backend)",
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
    """Strict: required present, types correct, enums respected, no unknown params."""
    errors: list[str] = []
    for name, p in spec.params.items():
        if name not in params:
            if p.required:
                errors.append(f"missing required param {name!r}")
            continue
        value = params[name]
        if not _TYPE_CHECKS[p.type](value):
            errors.append(f"param {name!r} must be of type {p.type}")
        elif p.enum is not None and value not in p.enum:
            errors.append(f"param {name!r} must be one of {p.enum}")
    unknown = set(params) - set(spec.params)
    if unknown:
        errors.append(f"unknown params: {sorted(unknown)}")
    return errors


# ------------------------------------------------------------------ egress guard


def check_egress(url: str) -> None:
    """Refuse URLs that resolve to private, loopback, link-local or reserved addresses.

    Stops a policy author (or a compromised admin account) from pointing a
    connector or webhook at the cloud metadata service or internal admin APIs.
    Residual risk: DNS rebinding between this check and the request; deployments
    that need stronger guarantees should also restrict egress at the network layer.
    """
    host = urlsplit(url).hostname
    if not host:
        raise ConnectorError("URL has no host")
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        raise ConnectorError(f"cannot resolve host {host!r}") from exc
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified:
            raise ConnectorError(f"host {host!r} resolves to a non-public address; outbound requests to it are blocked")


# ----------------------------------------------------------------- mock backends


class MockBackends:
    """In-memory downstream systems, so the full flow runs without real accounts."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.refunds: list[dict[str, Any]] = []
        self.outbox: list[dict[str, Any]] = []
        self.customers: dict[str, dict[str, Any]] = {
            "cus_alice": {"id": "cus_alice", "name": "Alice Chen", "plan": "pro", "lifetime_value": 1840.0},
            "cus_bob": {"id": "cus_bob", "name": "Bob Okafor", "plan": "starter", "lifetime_value": 210.0},
        }


# Stripe amounts are integers in the currency's minor unit.
_ZERO_DECIMAL = {"bif", "clp", "djf", "gnf", "jpy", "kmf", "krw", "mga", "pyg", "rwf", "ugx", "vnd", "vuv", "xaf", "xof", "xpf"}
_THREE_DECIMAL = {"bhd", "jod", "kwd", "omr", "tnd"}


def to_minor_units(amount: float, currency: str) -> int:
    cur = currency.lower()
    exp = 0 if cur in _ZERO_DECIMAL else 3 if cur in _THREE_DECIMAL else 2
    try:
        minor = Decimal(str(amount)) * (Decimal(10) ** exp)
    except InvalidOperation as exc:
        raise ConnectorError("amount is not a valid number") from exc
    if minor != minor.to_integral_value():
        raise ConnectorError(f"amount {amount} has more decimal places than {cur.upper()} allows")
    if minor <= 0:
        raise ConnectorError("amount must be positive")
    return int(minor)


class Executor:
    def __init__(
        self,
        mocks: MockBackends | None = None,
        http_client: httpx.Client | None = None,
        egress_guard: Callable[[str], None] | None = check_egress,
    ):
        self.mocks = mocks or MockBackends()
        self._http = http_client
        self._egress_guard = egress_guard

    def execute(
        self,
        connector_name: str,
        conn: ConnectorConfig,
        action_name: str,
        spec: ActionSpec,
        params: dict[str, Any],
        idempotency_key: str,
        resolve_secret: SecretResolver,
    ) -> dict[str, Any]:
        secret = resolve_secret(conn.secret) if conn.secret else None
        if conn.type == "mock_payments":
            return self._mock_payments(action_name, params, idempotency_key)
        if conn.type == "mock_email":
            return self._mock_email(action_name, params)
        if conn.type == "http":
            return self._http_call(conn, spec, params, secret, idempotency_key)
        if conn.type == "stripe":
            return self._stripe(conn, action_name, params, secret or "", idempotency_key)
        raise ConnectorError(f"unsupported connector type {conn.type!r}")

    # ------------------------------------------------------------------ mocks

    def _mock_payments(self, action: str, params: dict[str, Any], idem: str) -> dict[str, Any]:
        m = self.mocks
        with m.lock:
            customer = m.customers.get(params["customer_id"])
            if customer is None:
                raise ConnectorError(f"no such customer {params['customer_id']!r}")
            if action == "get_customer":
                return dict(customer)
            if action == "refund":
                for r in m.refunds:
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

    # ------------------------------------------------------------------- http

    def _request(self, method: str, url: str, timeout: float, **kwargs: Any) -> httpx.Response:
        if self._egress_guard is not None:
            self._egress_guard(url)
        client = self._http or httpx.Client(timeout=timeout, follow_redirects=False)
        try:
            return client.request(method, url, **kwargs)
        except httpx.HTTPError as exc:
            raise ConnectorError(f"downstream request failed: {exc.__class__.__name__}") from exc
        finally:
            if self._http is None:
                client.close()

    def _http_call(self, conn: ConnectorConfig, spec: ActionSpec, params: dict[str, Any], secret: str | None, idem: str) -> dict[str, Any]:
        path_fields = {f for _, f, _, _ in string.Formatter().parse(spec.path) if f}
        missing = path_fields - set(params)
        if missing:
            raise ConnectorError(f"path params missing: {sorted(missing)}")
        # Encode path params fully so a value like "../admin" cannot change the route.
        path = spec.path.format(**{k: quote(str(params[k]), safe="") for k in path_fields})
        rest = {k: v for k, v in params.items() if k not in path_fields}
        headers = {"Idempotency-Key": idem, "User-Agent": "AgentGuard/0.2"}
        if secret:
            headers[conn.auth_header] = f"{conn.auth_scheme} {secret}".strip()
        body_method = spec.method not in ("GET", "DELETE")
        resp = self._request(
            spec.method,
            conn.base_url.rstrip("/") + path,  # type: ignore[union-attr]
            conn.timeout_seconds,
            headers=headers,
            params=None if body_method else rest,
            json=rest if body_method else None,
        )
        if resp.status_code >= 400:
            raise ConnectorError(f"downstream returned HTTP {resp.status_code}")
        try:
            body: Any = resp.json()
        except ValueError:
            body = {"text": resp.text[:2000]}
        return {"status_code": resp.status_code, "body": body}

    # ----------------------------------------------------------------- stripe

    def _stripe(self, conn: ConnectorConfig, action: str, params: dict[str, Any], secret: str, idem: str) -> dict[str, Any]:
        base = (conn.base_url or "https://api.stripe.com").rstrip("/")
        headers = {"Authorization": f"Bearer {secret}", "User-Agent": "AgentGuard/0.2"}
        if action == "refund":
            form = {
                "payment_intent": params["payment_intent"],
                "amount": str(to_minor_units(params["amount"], params["currency"])),
                "metadata[source]": "agentguard",
            }
            if params.get("reason"):
                form["reason"] = params["reason"]
            resp = self._request("POST", f"{base}/v1/refunds", conn.timeout_seconds, headers={**headers, "Idempotency-Key": idem}, data=form)
        elif action == "get_payment":
            resp = self._request("GET", f"{base}/v1/payment_intents/{quote(params['payment_intent'], safe='')}", conn.timeout_seconds, headers=headers)
        else:
            raise ConnectorError(f"unsupported stripe action {action!r}")
        try:
            body = resp.json()
        except ValueError:
            body = {}
        if resp.status_code >= 400:
            err = body.get("error", {}) if isinstance(body, dict) else {}
            raise ConnectorError(f"Stripe error ({resp.status_code}): {err.get('message') or err.get('code') or 'request failed'}")
        keep = ("id", "object", "status", "amount", "amount_received", "currency", "payment_intent", "reason", "created")
        return {k: body.get(k) for k in keep if k in body}

"""Policy documents: the YAML an organization writes to govern its agents.

A document declares connectors (the systems the gateway brokers), rules,
rate limits and approval requirements. Documents are stored as immutable,
numbered versions; exactly one is active per organization.

Credentials never appear in a document. A connector names a secret
(`secret: stripe_live_key`) that lives encrypted in the org's secret store.
"""
from __future__ import annotations

from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

Decision = Literal["allow", "review", "block"]
DECISION_RANK: dict[str, int] = {"allow": 0, "review": 1, "block": 2}
ROLES = ("owner", "admin", "approver", "viewer")
APPROVER_ROLES_DEFAULT = ["owner", "admin", "approver"]
PARAM_TYPES = {"string", "number", "integer", "boolean", "object", "array"}
MAX_POLICY_BYTES = 256 * 1024


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")  # typos in policy keys are errors, not silent no-ops


class ParamSpec(_Strict):
    type: str = "string"
    required: bool = True
    description: str = ""
    enum: list[Any] | None = None

    @field_validator("type")
    @classmethod
    def _known_type(cls, v: str) -> str:
        if v not in PARAM_TYPES:
            raise ValueError(f"unknown param type {v!r}; expected one of {sorted(PARAM_TYPES)}")
        return v


class ActionSpec(_Strict):
    description: str = ""
    params: dict[str, ParamSpec] = Field(default_factory=dict)
    method: str = "POST"  # http connector only
    path: str = "/"  # http connector only

    @field_validator("method")
    @classmethod
    def _method(cls, v: str) -> str:
        v = v.upper()
        if v not in ("GET", "POST", "PUT", "PATCH", "DELETE"):
            raise ValueError("method must be GET, POST, PUT, PATCH or DELETE")
        return v


class ConnectorConfig(_Strict):
    type: Literal["http", "stripe", "mock_payments", "mock_email"]
    description: str = ""
    secret: str | None = None  # name in the org secret store, or env:NAME when self-hosted allows it
    base_url: str | None = None
    auth_header: str = "Authorization"
    auth_scheme: str = "Bearer"
    timeout_seconds: float = Field(default=10.0, gt=0, le=60)
    actions: dict[str, ActionSpec] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _checks(self) -> ConnectorConfig:
        if self.type == "http":
            if not self.base_url:
                raise ValueError("http connectors require base_url")
            if not self.base_url.startswith("https://") and not self.base_url.startswith("http://"):
                raise ValueError("base_url must start with https:// or http://")
        if self.type == "stripe" and not self.secret:
            raise ValueError("stripe connectors require secret (the name of a stored Stripe API key)")
        return self


class ApprovalSpec(_Strict):
    min: int = Field(default=1, ge=1, le=5)
    roles: list[str] = Field(default_factory=lambda: list(APPROVER_ROLES_DEFAULT))

    @field_validator("roles")
    @classmethod
    def _roles(cls, v: list[str]) -> list[str]:
        bad = [r for r in v if r not in ROLES or r == "viewer"]
        if bad or not v:
            raise ValueError(f"approver roles must be a non-empty subset of owner, admin, approver (got {v})")
        return v


def _action_alias(data: Any) -> Any:
    if isinstance(data, dict) and "action" in data and "actions" not in data:
        data = dict(data)
        data["actions"] = [data.pop("action")]
    return data


class Rule(_Strict):
    id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$")
    description: str = ""
    agents: list[str] = Field(default_factory=lambda: ["*"])
    actions: list[str] = Field(default_factory=lambda: ["*"])
    when: dict[str, dict[str, Any]] = Field(default_factory=dict)
    decision: Decision
    reason: str = ""
    approvals: ApprovalSpec = Field(default_factory=ApprovalSpec)

    @model_validator(mode="before")
    @classmethod
    def _alias(cls, data: Any) -> Any:
        return _action_alias(data)


class RateLimit(_Strict):
    id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$")
    description: str = ""
    agents: list[str] = Field(default_factory=lambda: ["*"])
    actions: list[str] = Field(default_factory=lambda: ["*"])
    max: int = Field(gt=0)
    window_seconds: int = Field(gt=0, le=7 * 86400)
    pause_agent: bool = False

    @model_validator(mode="before")
    @classmethod
    def _alias(cls, data: Any) -> Any:
        return _action_alias(data)


class PolicyConfig(_Strict):
    default: Decision = "block"
    rules: list[Rule] = Field(default_factory=list)
    rate_limits: list[RateLimit] = Field(default_factory=list)

    @model_validator(mode="after")
    def _unique_ids(self) -> PolicyConfig:
        ids = [r.id for r in self.rules] + [r.id for r in self.rate_limits]
        dupes = sorted({i for i in ids if ids.count(i) > 1})
        if dupes:
            raise ValueError(f"duplicate rule ids: {dupes}")
        return self


class PolicyDocument(_Strict):
    description: str = ""
    connectors: dict[str, ConnectorConfig] = Field(default_factory=dict)
    policies: PolicyConfig = Field(default_factory=PolicyConfig)
    approval_ttl_seconds: int = Field(default=24 * 3600, ge=60, le=30 * 86400)
    redact_params: list[str] = Field(default_factory=list)

    @field_validator("connectors")
    @classmethod
    def _connector_names(cls, v: dict[str, ConnectorConfig]) -> dict[str, ConnectorConfig]:
        for name in v:
            if not name.replace("_", "").replace("-", "").isalnum() or "." in name:
                raise ValueError(f"connector name {name!r} may only contain letters, digits, '-' and '_'")
        return v

    @field_validator("redact_params")
    @classmethod
    def _lower(cls, v: list[str]) -> list[str]:
        return [k.lower() for k in v]

    def action_spec(self, action: str) -> tuple[str, ConnectorConfig, str, ActionSpec] | None:
        from agentguard.server.connectors import builtin_actions

        connector_name, _, action_name = action.partition(".")
        conn = self.connectors.get(connector_name)
        if conn is None:
            return None
        spec = conn.actions.get(action_name) or builtin_actions(conn.type).get(action_name)
        if spec is None:
            return None
        return connector_name, conn, action_name, spec

    def all_actions(self) -> dict[str, ActionSpec]:
        from agentguard.server.connectors import builtin_actions

        out: dict[str, ActionSpec] = {}
        for cname, conn in self.connectors.items():
            for aname, spec in {**builtin_actions(conn.type), **conn.actions}.items():
                out[f"{cname}.{aname}"] = spec
        return out


class PolicyError(ValueError):
    def __init__(self, errors: list[str]):
        super().__init__("; ".join(errors))
        self.errors = errors


def _format_errors(exc: ValidationError) -> list[str]:
    out = []
    for e in exc.errors():
        loc = ".".join(str(p) for p in e["loc"] if not str(p).startswith("function-"))
        msg = e["msg"].removeprefix("Value error, ")
        out.append(f"{loc}: {msg}" if loc else msg)
    return out


def parse_policy(source: str) -> PolicyDocument:
    """Parse and fully validate a YAML policy document. Raises PolicyError with readable messages."""
    if len(source.encode()) > MAX_POLICY_BYTES:
        raise PolicyError([f"policy is larger than {MAX_POLICY_BYTES // 1024} KB"])
    try:
        raw = yaml.safe_load(source) or {}
    except yaml.YAMLError as exc:
        raise PolicyError([f"invalid YAML: {exc}"]) from exc
    if not isinstance(raw, dict):
        raise PolicyError(["policy must be a YAML mapping"])
    try:
        doc = PolicyDocument.model_validate(raw)
    except ValidationError as exc:
        raise PolicyError(_format_errors(exc)) from exc
    from agentguard.server.policy import validate_rule_conditions

    errors = []
    for rule in doc.policies.rules:
        try:
            validate_rule_conditions(rule)
        except ValueError as exc:
            errors.append(str(exc))
    if errors:
        raise PolicyError(errors)
    return doc


def load_policy_file(path: str) -> PolicyDocument:
    with open(path, encoding="utf-8") as fh:
        return parse_policy(fh.read())

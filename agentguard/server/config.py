"""Gateway configuration (policy-as-code).

A single YAML file declares the connectors the gateway brokers, the policy
rules evaluated on every action, and rate limits. Secrets are never written in
the file: connectors reference environment variables, and the gateway resolves
them at execution time so agents never see them.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field, field_validator, model_validator

Decision = Literal["allow", "review", "block"]
DECISION_RANK: dict[str, int] = {"allow": 0, "review": 1, "block": 2}

PARAM_TYPES = {"string", "number", "integer", "boolean", "object", "array"}


class ParamSpec(BaseModel):
    type: str = "string"
    required: bool = True
    description: str = ""

    @field_validator("type")
    @classmethod
    def _known_type(cls, v: str) -> str:
        if v not in PARAM_TYPES:
            raise ValueError(f"unknown param type {v!r}; expected one of {sorted(PARAM_TYPES)}")
        return v


class ActionSpec(BaseModel):
    description: str = ""
    params: dict[str, ParamSpec] = Field(default_factory=dict)
    # Only used by the generic `http` connector.
    method: str = "POST"
    path: str = "/"


class ConnectorConfig(BaseModel):
    type: Literal["mock_payments", "mock_email", "http"]
    description: str = ""
    # Name of the env var holding the credential. The gateway reads it; agents never do.
    secret_env: str | None = None
    # http connector only
    base_url: str | None = None
    auth_header: str = "Authorization"
    auth_scheme: str = "Bearer"
    timeout_seconds: float = 10.0
    actions: dict[str, ActionSpec] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _http_needs_base_url(self) -> "ConnectorConfig":
        if self.type == "http" and not self.base_url:
            raise ValueError("http connectors require base_url")
        return self


class Rule(BaseModel):
    id: str
    description: str = ""
    agents: list[str] = Field(default_factory=lambda: ["*"])  # glob patterns on agent id
    actions: list[str] = Field(default_factory=lambda: ["*"])  # glob patterns on "<connector>.<action>"
    when: dict[str, dict[str, Any]] = Field(default_factory=dict)  # param path -> {op: value}
    decision: Decision
    reason: str = ""

    @model_validator(mode="before")
    @classmethod
    def _single_action_alias(cls, data: Any) -> Any:
        # Allow `action: payments.refund` as shorthand for `actions: [payments.refund]`.
        if isinstance(data, dict) and "action" in data and "actions" not in data:
            data = dict(data)
            data["actions"] = [data.pop("action")]
        return data


class RateLimit(BaseModel):
    id: str
    description: str = ""
    agents: list[str] = Field(default_factory=lambda: ["*"])
    actions: list[str] = Field(default_factory=lambda: ["*"])
    max: int = Field(gt=0)
    window_seconds: int = Field(gt=0)
    pause_agent: bool = False  # kill switch: pause the agent when the limit trips

    @model_validator(mode="before")
    @classmethod
    def _single_action_alias(cls, data: Any) -> Any:
        if isinstance(data, dict) and "action" in data and "actions" not in data:
            data = dict(data)
            data["actions"] = [data.pop("action")]
        return data


class PolicyConfig(BaseModel):
    default: Decision = "block"  # fail closed
    rules: list[Rule] = Field(default_factory=list)
    rate_limits: list[RateLimit] = Field(default_factory=list)

    @model_validator(mode="after")
    def _unique_ids(self) -> "PolicyConfig":
        ids = [r.id for r in self.rules] + [r.id for r in self.rate_limits]
        dupes = {i for i in ids if ids.count(i) > 1}
        if dupes:
            raise ValueError(f"duplicate rule ids: {sorted(dupes)}")
        return self


class GatewayConfig(BaseModel):
    connectors: dict[str, ConnectorConfig] = Field(default_factory=dict)
    policies: PolicyConfig = Field(default_factory=PolicyConfig)
    approval_ttl_seconds: int = 24 * 3600
    # Param keys whose values are masked in the audit log and API responses.
    redact_params: list[str] = Field(default_factory=list)

    def action_spec(self, action: str) -> tuple[str, ConnectorConfig, str, ActionSpec] | None:
        connector_name, _, action_name = action.partition(".")
        conn = self.connectors.get(connector_name)
        if conn is None:
            return None
        spec = conn.actions.get(action_name)
        if spec is None:
            from agentguard.server.connectors import builtin_actions

            spec = builtin_actions(conn.type).get(action_name)
        if spec is None:
            return None
        return connector_name, conn, action_name, spec

    def all_actions(self) -> dict[str, ActionSpec]:
        from agentguard.server.connectors import builtin_actions

        out: dict[str, ActionSpec] = {}
        for cname, conn in self.connectors.items():
            merged = {**builtin_actions(conn.type), **conn.actions}
            for aname, spec in merged.items():
                out[f"{cname}.{aname}"] = spec
        return out


def load_config(path: str | Path) -> GatewayConfig:
    with open(path, "r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh) or {}
    return GatewayConfig.model_validate(raw)

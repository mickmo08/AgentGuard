"""Runtime settings, read from environment variables.

Everything an operator configures lives here, so a deployment is fully
described by its environment (12-factor). See docs/configuration.md.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field


def _bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    return int(raw) if raw else default


@dataclass
class Settings:
    database_url: str = "sqlite:///agentguard.db"
    # Fernet keys, comma-separated. The first encrypts; all decrypt (key rotation).
    encryption_keys: list[str] = field(default_factory=list)
    public_url: str = "http://127.0.0.1:8080"
    allow_signup: bool = False
    # Self-hosted only: let connector configs reference process env vars (`env:NAME`).
    # Never enable on a multi-tenant deployment: any org could read the host's env.
    allow_env_secrets: bool = False
    session_ttl_hours: int = 12
    invitation_ttl_hours: int = 72
    worker_enabled: bool = True
    worker_interval_seconds: float = 5.0
    stuck_after_seconds: int = 300
    max_body_bytes: int = 1_000_000
    auto_migrate: bool = True
    log_json: bool = True
    # Outbound HTTP to connectors/webhooks: block private networks unless explicitly allowed (SSRF).
    allow_private_network_egress: bool = False

    @classmethod
    def from_env(cls) -> Settings:
        keys = [k.strip() for k in os.environ.get("AGENTGUARD_ENCRYPTION_KEYS", "").split(",") if k.strip()]
        return cls(
            database_url=os.environ.get("AGENTGUARD_DATABASE_URL", cls.database_url),
            encryption_keys=keys,
            public_url=os.environ.get("AGENTGUARD_PUBLIC_URL", cls.public_url).rstrip("/"),
            allow_signup=_bool("AGENTGUARD_ALLOW_SIGNUP", False),
            allow_env_secrets=_bool("AGENTGUARD_ALLOW_ENV_SECRETS", False),
            session_ttl_hours=_int("AGENTGUARD_SESSION_TTL_HOURS", 12),
            invitation_ttl_hours=_int("AGENTGUARD_INVITATION_TTL_HOURS", 72),
            worker_enabled=_bool("AGENTGUARD_WORKER_ENABLED", True),
            worker_interval_seconds=float(os.environ.get("AGENTGUARD_WORKER_INTERVAL_SECONDS", "5")),
            stuck_after_seconds=_int("AGENTGUARD_STUCK_AFTER_SECONDS", 300),
            max_body_bytes=_int("AGENTGUARD_MAX_BODY_BYTES", 1_000_000),
            auto_migrate=_bool("AGENTGUARD_AUTO_MIGRATE", True),
            log_json=_bool("AGENTGUARD_LOG_JSON", True),
            allow_private_network_egress=_bool("AGENTGUARD_ALLOW_PRIVATE_EGRESS", False),
        )

    def validate(self) -> None:
        if not self.encryption_keys:
            raise RuntimeError(
                "AGENTGUARD_ENCRYPTION_KEYS is required. Generate one with: agentguard gen-key"
            )

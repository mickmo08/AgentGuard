"""Agent API keys.

Format: ag_<prefix>_<secret>. Only the prefix (for lookup) and a SHA-256 of the
full key are stored. The keys are random with 256 bits of entropy, so a fast
hash is appropriate (a password KDF only matters for low-entropy secrets).
"""
from __future__ import annotations

import hashlib
import hmac
import secrets


def generate_key() -> tuple[str, str, str]:
    prefix = secrets.token_hex(4)
    key = f"ag_{prefix}_{secrets.token_urlsafe(32)}"
    return key, prefix, hash_key(key)


def hash_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def parse_prefix(key: str) -> str | None:
    parts = key.split("_", 2)
    if len(parts) != 3 or parts[0] != "ag" or not parts[1]:
        return None
    return parts[1]


def constant_time_equal(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())

"""Credentials: password hashing and opaque tokens.

Token formats (the prefix tells the server what kind of credential it is):
  ag_<prefix>_<secret>    agent key
  agt_<prefix>_<secret>   API token (automation, scoped to an org and role)
  ags_<secret>            dashboard session
  agi_<secret>            invitation
Only SHA-256 digests are stored. These are 256-bit random secrets, so a fast
hash is appropriate; passwords use scrypt.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets

_SCRYPT_N, _SCRYPT_R, _SCRYPT_P = 2**15, 8, 1
MIN_PASSWORD_LENGTH = 12


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, maxmem=64 * 1024 * 1024)
    b64 = lambda b: base64.b64encode(b).decode()  # noqa: E731
    return f"scrypt${_SCRYPT_N}${_SCRYPT_R}${_SCRYPT_P}${b64(salt)}${b64(dk)}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, n, r, p, salt_b64, dk_b64 = stored.split("$")
        if algo != "scrypt":
            return False
        expected = base64.b64decode(dk_b64)
        dk = hashlib.scrypt(password.encode(), salt=base64.b64decode(salt_b64), n=int(n), r=int(r), p=int(p),
                            maxmem=64 * 1024 * 1024, dklen=len(expected))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(dk, expected)


# Spend the same time on unknown emails as on wrong passwords (no user enumeration by timing).
DUMMY_PASSWORD_HASH = hash_password(secrets.token_urlsafe(16))


def password_problems(password: str) -> list[str]:
    problems = []
    if len(password) < MIN_PASSWORD_LENGTH:
        problems.append(f"password must be at least {MIN_PASSWORD_LENGTH} characters")
    if len(password) > 256:
        problems.append("password must be at most 256 characters")
    return problems


def digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def new_prefixed(kind: str) -> tuple[str, str, str]:
    """Returns (token, prefix, digest) for prefix-indexed credentials (agent keys, API tokens)."""
    prefix = secrets.token_hex(4)
    token = f"{kind}_{prefix}_{secrets.token_urlsafe(32)}"
    return token, prefix, digest(token)


def new_opaque(kind: str) -> tuple[str, str]:
    token = f"{kind}_{secrets.token_urlsafe(32)}"
    return token, digest(token)


def token_kind(token: str) -> str | None:
    head = token.split("_", 1)[0]
    return head if head in ("ag", "agt", "ags", "agi") else None


def parse_prefix(token: str) -> str | None:
    parts = token.split("_", 2)
    if len(parts) != 3 or not parts[1]:
        return None
    return parts[1]


def constant_time_equal(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())

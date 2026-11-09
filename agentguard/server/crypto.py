"""Encryption at rest for secrets and action params.

Fernet (AES-128-CBC + HMAC-SHA256, authenticated) via MultiFernet so keys can
be rotated: put the new key first in AGENTGUARD_ENCRYPTION_KEYS, keep the old
ones after it, run `agentguard rotate-keys`, then drop the old keys.
"""
from __future__ import annotations

import json
from typing import Any

from cryptography.fernet import Fernet, InvalidToken, MultiFernet


class DecryptionError(Exception):
    pass


def generate_key() -> str:
    return Fernet.generate_key().decode()


class Vault:
    def __init__(self, keys: list[str]):
        if not keys:
            raise ValueError("at least one encryption key is required")
        try:
            self._f = MultiFernet([Fernet(k.encode() if isinstance(k, str) else k) for k in keys])
        except (ValueError, TypeError) as exc:
            raise ValueError("invalid encryption key; generate one with `agentguard gen-key`") from exc

    def encrypt(self, plaintext: str) -> str:
        return self._f.encrypt(plaintext.encode()).decode()

    def decrypt(self, token: str) -> str:
        try:
            return self._f.decrypt(token.encode()).decode()
        except InvalidToken as exc:
            raise DecryptionError("ciphertext could not be decrypted with the configured keys") from exc

    def encrypt_json(self, value: Any) -> str:
        return self.encrypt(json.dumps(value, separators=(",", ":"), sort_keys=True))

    def decrypt_json(self, token: str) -> Any:
        return json.loads(self.decrypt(token))

    def rotate(self, token: str) -> str:
        """Re-encrypt under the primary key."""
        try:
            return self._f.rotate(token.encode()).decode()
        except InvalidToken as exc:
            raise DecryptionError("ciphertext could not be decrypted with the configured keys") from exc

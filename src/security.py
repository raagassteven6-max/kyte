"""Cryptographic building blocks: key derivation, token vault, signed cookies.

One master secret (KYTE_SECRET_KEY) feeds everything, but each purpose gets
its own derived key, so a value made for one purpose is useless for another.
"""

import base64
from collections.abc import Mapping
from typing import Any

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from itsdangerous import BadData, URLSafeTimedSerializer


class VaultError(Exception):
    """Raised when stored ciphertext cannot be decrypted."""


def derive_key(secret: str, purpose: str) -> bytes:
    """Derive a 32-byte key for ``purpose`` from the master secret (HKDF)."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=f"kyte/{purpose}".encode(),
    ).derive(secret.encode())


class TokenVault:
    """Authenticated encryption (Fernet) for secrets stored at rest."""

    def __init__(self, secret: str) -> None:
        key = base64.urlsafe_b64encode(derive_key(secret, "token-vault"))
        self._fernet = Fernet(key)

    def encrypt(self, plaintext: str) -> bytes:
        return self._fernet.encrypt(plaintext.encode())

    def decrypt(self, blob: bytes) -> str:
        """Return the plaintext, or raise VaultError if it cannot be trusted."""
        try:
            return self._fernet.decrypt(blob).decode()
        except (InvalidToken, ValueError, TypeError) as exc:
            raise VaultError("Could not decrypt the stored value.") from exc


class CookieSigner:
    """Signed, expiring cookie values bound to one purpose.

    The value is signed, not encrypted: anyone holding the cookie can read
    it, but no one can alter it or reuse it for a different purpose.
    """

    def __init__(self, secret: str, purpose: str, max_age_seconds: int) -> None:
        key = derive_key(secret, f"cookie/{purpose}").hex()
        self._serializer = URLSafeTimedSerializer(key, salt=f"kyte-{purpose}")
        self._max_age = max_age_seconds

    def dumps(self, payload: Mapping[str, Any]) -> str:
        return self._serializer.dumps(dict(payload))

    def loads(self, value: str | None) -> dict[str, Any] | None:
        """Return the payload, or None if missing, forged or expired."""
        if not value:
            return None
        try:
            data = self._serializer.loads(value, max_age=self._max_age)
        except BadData:
            return None
        return data if isinstance(data, dict) else None

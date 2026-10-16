"""Encrypted storage for the owner's Gmail refresh token.

Kyte has exactly one owner, so there is exactly one credentials row. The
refresh token is encrypted before it touches the database.
"""

import sqlite3
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path

from kyte.security import TokenVault, VaultError
from kyte.store import prepare_db_file


class CredentialError(Exception):
    """Raised when stored credentials exist but cannot be read."""


class CredentialStore:
    """SQLite-backed holder of the encrypted refresh token."""

    def __init__(self, path: Path, vault: TokenVault) -> None:
        self._path = path
        self._vault = vault
        prepare_db_file(path)
        with closing(self._connect()) as conn, conn:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS credentials ("
                "id INTEGER PRIMARY KEY CHECK (id = 1), "
                "refresh_token BLOB NOT NULL, email TEXT NOT NULL, "
                "scope TEXT NOT NULL, updated_at TEXT NOT NULL)"
            )

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self._path, timeout=5.0)

    def save(self, refresh_token: str, *, email: str, scope: str) -> None:
        """Store (or replace) the refresh token, encrypted."""
        if not refresh_token:
            raise ValueError("refresh_token must not be empty.")
        with closing(self._connect()) as conn, conn:
            conn.execute(
                "INSERT OR REPLACE INTO credentials "
                "(id, refresh_token, email, scope, updated_at) "
                "VALUES (1, ?, ?, ?, ?)",
                (
                    self._vault.encrypt(refresh_token),
                    email,
                    scope,
                    datetime.now(UTC).isoformat(),
                ),
            )

    def load(self) -> str | None:
        """Return the refresh token, or None if Gmail is not connected.

        Raises:
            CredentialError: if a token is stored but cannot be decrypted,
                for example because KYTE_SECRET_KEY changed.
        """
        with closing(self._connect()) as conn:
            row = conn.execute(
                "SELECT refresh_token FROM credentials WHERE id = 1"
            ).fetchone()
        if row is None:
            return None
        try:
            return self._vault.decrypt(row[0])
        except VaultError as exc:
            raise CredentialError(
                "Stored Gmail credentials cannot be read. "
                "Was KYTE_SECRET_KEY changed? Reconnect Gmail."
            ) from exc

    def is_connected(self) -> bool:
        with closing(self._connect()) as conn:
            row = conn.execute("SELECT 1 FROM credentials WHERE id = 1").fetchone()
        return row is not None

    def clear(self) -> None:
        """Forget the stored credentials."""
        with closing(self._connect()) as conn, conn:
            conn.execute("DELETE FROM credentials")

"""Persistent state: which cards the owner has dismissed.

Only opaque Gmail message ids are stored, never senders, subjects or
snippets. The database file is created owner-readable only.
"""

import os
import re
import sqlite3
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path

_VALID_ID = re.compile(r"[A-Za-z0-9_-]{1,64}")


def prepare_db_file(path: Path) -> None:
    """Create the database file (and parents) readable by the owner only."""
    path.parent.mkdir(parents=True, exist_ok=True)
    os.close(os.open(path, os.O_CREAT | os.O_WRONLY, 0o600))
    os.chmod(path, 0o600)


class InvalidEmailId(ValueError):
    """Raised for ids that could not be a Gmail message id."""


class DismissedStore:
    """SQLite-backed set of dismissed message ids.

    A short-lived connection is opened per operation, so the store is safe
    to call from FastAPI's worker threads.
    """

    def __init__(self, path: Path) -> None:
        self._path = path
        prepare_db_file(path)
        with closing(self._connect()) as conn, conn:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS dismissed ("
                "email_id TEXT PRIMARY KEY, dismissed_at TEXT NOT NULL)"
            )

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self._path, timeout=5.0)

    def dismiss(self, email_id: str) -> None:
        """Hide a card for good. Dismissing twice is harmless.

        Raises:
            InvalidEmailId: if ``email_id`` is not 1-64 characters of
                letters, digits, underscore or hyphen.
        """
        if not _VALID_ID.fullmatch(email_id):
            raise InvalidEmailId("Not a valid message id.")
        with closing(self._connect()) as conn, conn:
            conn.execute(
                "INSERT OR IGNORE INTO dismissed (email_id, dismissed_at) "
                "VALUES (?, ?)",
                (email_id, datetime.now(UTC).isoformat()),
            )

    def dismissed_ids(self) -> set[str]:
        """Return a fresh set of every dismissed message id."""
        with closing(self._connect()) as conn:
            rows = conn.execute("SELECT email_id FROM dismissed").fetchall()
        return {row[0] for row in rows}

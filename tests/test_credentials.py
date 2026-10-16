"""Task 6 tests: encrypted refresh-token storage."""

import sqlite3
import stat
import sys
import tempfile
import unittest
from pathlib import Path

from kyte.credentials import CredentialError, CredentialStore
from kyte.security import TokenVault

SECRET = "k" * 40
TOKEN = "1//refresh-token-PLAINTEXT-marker"


class CredentialStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.path = Path(tmp.name) / "kyte.db"
        self.store = CredentialStore(self.path, TokenVault(SECRET))

    def test_starts_disconnected(self) -> None:
        self.assertFalse(self.store.is_connected())
        self.assertIsNone(self.store.load())

    def test_save_and_load(self) -> None:
        self.store.save(TOKEN, email="me@example.com", scope="a b")
        self.assertTrue(self.store.is_connected())
        self.assertEqual(self.store.load(), TOKEN)

    def test_second_save_replaces_the_first(self) -> None:
        self.store.save("old", email="me@example.com", scope="s")
        self.store.save("new", email="me@example.com", scope="s")
        self.assertEqual(self.store.load(), "new")
        with sqlite3.connect(self.path) as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM credentials").fetchone()[0], 1)

    def test_token_is_never_stored_in_plaintext(self) -> None:
        self.store.save(TOKEN, email="me@example.com", scope="s")
        self.assertNotIn(TOKEN.encode(), self.path.read_bytes())
        with sqlite3.connect(self.path) as conn:
            dump = "\n".join(conn.iterdump())
        self.assertNotIn("PLAINTEXT-marker", dump)

    def test_clear_disconnects(self) -> None:
        self.store.save(TOKEN, email="me@example.com", scope="s")
        self.store.clear()
        self.assertFalse(self.store.is_connected())
        self.assertIsNone(self.store.load())

    def test_wrong_secret_raises_credential_error(self) -> None:
        self.store.save(TOKEN, email="me@example.com", scope="s")
        other = CredentialStore(self.path, TokenVault("z" * 40))
        with self.assertRaises(CredentialError):
            other.load()

    def test_empty_token_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self.store.save("", email="me@example.com", scope="s")

    @unittest.skipIf(sys.platform == "win32", "POSIX permissions only")
    def test_file_is_owner_only(self) -> None:
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)

    def test_shares_a_file_with_the_dismissed_store(self) -> None:
        from kyte.store import DismissedStore

        DismissedStore(self.path).dismiss("abc")
        self.store.save(TOKEN, email="me@example.com", scope="s")
        self.assertEqual(DismissedStore(self.path).dismissed_ids(), {"abc"})
        self.assertEqual(self.store.load(), TOKEN)


if __name__ == "__main__":
    unittest.main()

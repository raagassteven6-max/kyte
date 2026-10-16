"""Task 4 tests: persistent dismissed-card state in SQLite."""

import stat
import sys
import tempfile
import threading
import unittest
from pathlib import Path

from kyte.store import DismissedStore, InvalidEmailId


class StoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.path = Path(self._tmp.name) / "kyte.db"
        self.store = DismissedStore(self.path)

    def test_starts_empty(self) -> None:
        self.assertEqual(self.store.dismissed_ids(), set())

    def test_dismiss_then_listed(self) -> None:
        self.store.dismiss("abc123")
        self.assertEqual(self.store.dismissed_ids(), {"abc123"})

    def test_dismiss_is_idempotent(self) -> None:
        self.store.dismiss("abc123")
        self.store.dismiss("abc123")
        self.assertEqual(self.store.dismissed_ids(), {"abc123"})

    def test_persists_across_instances(self) -> None:
        self.store.dismiss("abc123")
        reopened = DismissedStore(self.path)
        self.assertEqual(reopened.dismissed_ids(), {"abc123"})

    def test_creates_missing_parent_directories(self) -> None:
        nested = Path(self._tmp.name) / "a" / "b" / "kyte.db"
        DismissedStore(nested).dismiss("x1")
        self.assertTrue(nested.exists())

    def test_returned_set_is_a_copy(self) -> None:
        self.store.dismiss("abc123")
        self.store.dismissed_ids().add("other")
        self.assertEqual(self.store.dismissed_ids(), {"abc123"})

    def test_invalid_ids_are_rejected(self) -> None:
        bad = ["", " ", "a" * 65, "../x", "a b", "x'); DROP TABLE dismissed;--"]
        for value in bad:
            with self.subTest(value=value), self.assertRaises(InvalidEmailId):
                self.store.dismiss(value)
        self.assertEqual(self.store.dismissed_ids(), set())

    def test_typical_gmail_ids_are_accepted(self) -> None:
        for value in ("18b4f2a9c3d1e7f0", "thread-m01", "A_b-9"):
            self.store.dismiss(value)
        self.assertEqual(len(self.store.dismissed_ids()), 3)

    def test_concurrent_dismissals_are_all_kept(self) -> None:
        ids = [f"id{n}" for n in range(20)]
        threads = [threading.Thread(target=self.store.dismiss, args=(i,)) for i in ids]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(self.store.dismissed_ids(), set(ids))

    @unittest.skipIf(sys.platform == "win32", "POSIX permissions only")
    def test_database_file_is_owner_only(self) -> None:
        self.store.dismiss("abc123")
        mode = stat.S_IMODE(self.path.stat().st_mode)
        self.assertEqual(mode, 0o600)


if __name__ == "__main__":
    unittest.main()

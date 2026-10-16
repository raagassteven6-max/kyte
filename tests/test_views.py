"""Task 3 tests: filters, card JSON, mock source and the list service."""

import json
import unittest
from datetime import UTC, datetime, timedelta
from zoneinfo import ZoneInfo

from kyte.emails import SNIPPET_LIMIT, Email
from kyte.service import list_cards
from kyte.sources import MockSource
from kyte.views import FILTER_MODES, email_to_card, filter_emails, gmail_link

NOW = datetime(2026, 10, 13, 15, 0, tzinfo=UTC)
NY = ZoneInfo("America/New_York")


def mk(id_: str, when: datetime | None, unread: bool = True) -> Email:
    return Email(
        id=id_, thread_id=f"t-{id_}", sender_name="Ada",
        sender_address="ada@example.com", subject=f"subject {id_}",
        snippet="snip", received_at=when, unread=unread,
    )


class FilterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.emails = [
            mk("old-read", NOW - timedelta(days=2), unread=False),
            mk("recent-unread", NOW - timedelta(minutes=5)),
            mk("recent-read", NOW - timedelta(hours=1), unread=False),
            mk("undated", None),
        ]

    def ids(self, mode: str, **kw: object) -> list[str]:
        out = filter_emails(
            self.emails, mode, now=NOW, tz=UTC, **kw  # type: ignore[arg-type]
        )
        return [e.id for e in out]

    def test_all_includes_everything_newest_first_undated_last(self) -> None:
        self.assertEqual(
            self.ids("all"),
            ["recent-unread", "recent-read", "old-read", "undated"],
        )

    def test_unread_only(self) -> None:
        self.assertEqual(self.ids("unread"), ["recent-unread", "undated"])

    def test_today_only_same_local_date_and_never_undated(self) -> None:
        self.assertEqual(self.ids("today"), ["recent-unread", "recent-read"])

    def test_dismissed_are_excluded_in_every_mode(self) -> None:
        for mode in FILTER_MODES:
            shown = self.ids(mode, dismissed={"recent-unread"})
            self.assertNotIn("recent-unread", shown)

    def test_today_respects_the_users_timezone(self) -> None:
        # 02:00 UTC on Oct 13 is still the evening of Oct 12 in New York.
        early = mk("early", datetime(2026, 10, 13, 2, 0, tzinfo=UTC))
        in_utc = filter_emails([early], "today", now=NOW, tz=UTC)
        in_ny = filter_emails([early], "today", now=NOW, tz=NY)
        self.assertEqual(len(in_utc), 1)
        self.assertEqual(in_ny, [])

    def test_local_midnight_counts_as_today(self) -> None:
        midnight_ny = datetime(2026, 10, 13, 0, 0, tzinfo=NY)
        out = filter_emails([mk("m", midnight_ny)], "today", now=NOW, tz=NY)
        self.assertEqual(len(out), 1)

    def test_unknown_mode_raises(self) -> None:
        with self.assertRaises(ValueError):
            filter_emails(
                self.emails, "bogus", now=NOW, tz=UTC  # type: ignore[arg-type]
            )

    def test_input_list_is_not_mutated(self) -> None:
        before = list(self.emails)
        filter_emails(self.emails, "all", now=NOW, tz=UTC)
        self.assertEqual(self.emails, before)


class CardTests(unittest.TestCase):
    def test_card_has_only_display_fields(self) -> None:
        card = email_to_card(mk("a1", NOW), "me@example.com")
        self.assertEqual(
            set(card),
            {"id", "sender", "sender_address", "subject", "snippet",
             "received_at", "unread", "gmail_url"},
        )
        self.assertEqual(card["received_at"], "2026-10-13T15:00:00+00:00")
        self.assertEqual(card["sender"], "Ada")
        self.assertIs(card["unread"], True)

    def test_card_with_no_date(self) -> None:
        self.assertIsNone(email_to_card(mk("a", None), "me@example.com")["received_at"])

    def test_card_is_json_serialisable(self) -> None:
        json.dumps(email_to_card(mk("a", NOW), "me@example.com"))

    def test_gmail_link_quotes_its_parts(self) -> None:
        url = gmail_link("t 1/x", "me+tag@example.com")
        self.assertTrue(url.startswith("https://mail.google.com/mail/"))
        self.assertIn("authuser=me%2Btag%40example.com", url)
        self.assertNotIn(" ", url)
        self.assertTrue(url.endswith("#all/t%201%2Fx"))


class MockSourceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.emails = MockSource(now=NOW).fetch_recent()

    def test_enough_varied_samples(self) -> None:
        self.assertGreaterEqual(len(self.emails), 8)
        self.assertEqual(len({e.id for e in self.emails}), len(self.emails))
        self.assertTrue(any(e.unread for e in self.emails))
        self.assertTrue(any(not e.unread for e in self.emails))

    def test_covers_ui_edge_cases(self) -> None:
        self.assertTrue(any(e.subject == "(no subject)" for e in self.emails))
        self.assertTrue(any(len(e.subject) > 100 for e in self.emails))
        self.assertTrue(any(e.sender_label == "Unknown sender" or "@" in e.sender_label
                            for e in self.emails))

    def test_snippets_respect_the_limit(self) -> None:
        self.assertTrue(all(len(e.snippet) <= SNIPPET_LIMIT for e in self.emails))

    def test_has_both_today_and_older_mail(self) -> None:
        today = filter_emails(self.emails, "today", now=NOW, tz=UTC)
        self.assertTrue(0 < len(today) < len(self.emails))

    def test_deterministic_for_a_fixed_clock(self) -> None:
        self.assertEqual(self.emails, MockSource(now=NOW).fetch_recent())


class ListCardsTests(unittest.TestCase):
    def test_end_to_end_with_mock(self) -> None:
        cards = list_cards(
            MockSource(now=NOW), mode="unread", now=NOW, tz=UTC,
            owner_email="me@example.com", dismissed=frozenset(),
        )
        self.assertTrue(cards)
        self.assertTrue(all(c["unread"] for c in cards))

    def test_dismissed_ids_are_hidden(self) -> None:
        source = MockSource(now=NOW)
        first = source.fetch_recent()[0].id
        cards = list_cards(source, mode="all", now=NOW, tz=UTC,
                           owner_email="me@example.com", dismissed={first})
        self.assertNotIn(first, [c["id"] for c in cards])


class BuildSourceTests(unittest.TestCase):
    def setUp(self) -> None:
        from kyte.config import Settings

        self.settings = Settings.from_env(
            {"KYTE_SECRET_KEY": "s" * 32, "KYTE_OWNER_EMAIL": "me@example.com",
             "KYTE_MOCK": "1"}
        )

    def test_mock_mode_gives_the_mock_source(self) -> None:
        from kyte.sources import build_source

        self.assertIsInstance(build_source(self.settings), MockSource)

    def test_real_mode_needs_credentials_and_a_google_client(self) -> None:
        import dataclasses

        from kyte.sources import build_source

        real = dataclasses.replace(self.settings, mock_mode=False)
        with self.assertRaises(ValueError):
            build_source(real)

    def test_real_mode_gives_the_gmail_source(self) -> None:
        import dataclasses
        import tempfile
        from pathlib import Path

        from kyte.credentials import CredentialStore
        from kyte.gmail import GmailSource
        from kyte.security import TokenVault
        from kyte.sources import build_source

        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        creds = CredentialStore(Path(tmp.name) / "k.db", TokenVault("s" * 32))
        real = dataclasses.replace(self.settings, mock_mode=False)
        source = build_source(real, creds=creds, google=object())  # type: ignore[arg-type]
        self.assertIsInstance(source, GmailSource)


if __name__ == "__main__":
    unittest.main()

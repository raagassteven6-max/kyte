"""Task 2 tests: turning Gmail metadata messages into Email cards."""

import dataclasses
import unittest
from datetime import UTC, datetime
from email.header import Header

from kyte.emails import (
    Email,
    EmailParseError,
    clean_snippet,
    parse_message,
    parse_sender,
)

MS = 1697000000000
WHEN = datetime.fromtimestamp(MS / 1000, UTC)


def message(**over: object) -> dict:
    msg: dict = {
        "id": "m1",
        "threadId": "t1",
        "labelIds": ["INBOX", "UNREAD"],
        "snippet": "Lunch at noon?",
        "internalDate": str(MS),
        "payload": {
            "headers": [
                {"name": "From", "value": "Ada Lovelace <ada@example.com>"},
                {"name": "Subject", "value": "Lunch"},
                {"name": "Date", "value": "Wed, 11 Oct 2023 04:53:20 +0000"},
            ]
        },
    }
    msg.update(over)
    return msg


def with_headers(*pairs: tuple[str, str]) -> dict:
    return message(
        payload={"headers": [{"name": n, "value": v} for n, v in pairs]}
    )


class ParseSenderTests(unittest.TestCase):
    def test_name_and_address(self) -> None:
        self.assertEqual(
            parse_sender("Ada Lovelace <ada@example.com>"),
            ("Ada Lovelace", "ada@example.com"),
        )

    def test_bare_address(self) -> None:
        self.assertEqual(parse_sender("ada@example.com"), ("", "ada@example.com"))

    def test_quoted_name_with_comma(self) -> None:
        self.assertEqual(
            parse_sender('"Lovelace, Ada" <ada@example.com>'),
            ("Lovelace, Ada", "ada@example.com"),
        )

    def test_encoded_word_name(self) -> None:
        encoded = Header("Ada Lövelace", "utf-8").encode()
        name, addr = parse_sender(f"{encoded} <ada@example.com>")
        self.assertEqual((name, addr), ("Ada Lövelace", "ada@example.com"))

    def test_empty_header(self) -> None:
        self.assertEqual(parse_sender(""), ("", ""))


class SenderLabelTests(unittest.TestCase):
    def make(self, name: str, addr: str) -> Email:
        return parse_message(with_headers(("From", f'"{name}" <{addr}>')))

    def test_prefers_name(self) -> None:
        self.assertEqual(self.make("Ada", "a@x.com").sender_label, "Ada")

    def test_falls_back_to_address_then_unknown(self) -> None:
        bare = parse_message(with_headers(("From", "a@x.com")))
        self.assertEqual(bare.sender_label, "a@x.com")
        none = parse_message(with_headers(("Subject", "hi")))
        self.assertEqual(none.sender_label, "Unknown sender")

    def test_spoofed_display_name_shows_real_address(self) -> None:
        email = self.make("support@paypal.com", "evil@scam.example")
        self.assertEqual(email.sender_label, "evil@scam.example")


    def test_malformed_from_never_shows_the_spoofed_address(self) -> None:
        # Unquoted "@" in a display name is invalid; lenient parsers return
        # the *spoofed* address, so we must fall back to "Unknown sender".
        email = parse_message(
            with_headers(("From", "support@paypal.com <evil@scam.example>"))
        )
        self.assertEqual(email.sender_label, "Unknown sender")


class CleanSnippetTests(unittest.TestCase):
    def test_unescapes_html_entities(self) -> None:
        self.assertEqual(clean_snippet("It&#39;s 5 &amp; 6"), "It's 5 & 6")

    def test_collapses_whitespace(self) -> None:
        self.assertEqual(clean_snippet("a \n\t  b"), "a b")

    def test_removes_invisible_padding(self) -> None:
        self.assertEqual(clean_snippet("hi\u200c\u200b\u00ad\u034f there"), "hi there")

    def test_short_text_unchanged(self) -> None:
        self.assertEqual(clean_snippet("short", limit=20), "short")

    def test_truncates_on_word_boundary(self) -> None:
        out = clean_snippet("The quick brown fox jumps over the lazy dog", limit=20)
        self.assertEqual(out, "The quick brown fox…")
        self.assertLessEqual(len(out), 20)

    def test_truncates_long_word_hard(self) -> None:
        self.assertEqual(clean_snippet("x" * 50, limit=10), "x" * 9 + "…")

    def test_empty(self) -> None:
        self.assertEqual(clean_snippet(""), "")


class ParseMessageTests(unittest.TestCase):
    def test_full_message(self) -> None:
        email = parse_message(message())
        self.assertEqual(
            email,
            Email(
                id="m1",
                thread_id="t1",
                sender_name="Ada Lovelace",
                sender_address="ada@example.com",
                subject="Lunch",
                snippet="Lunch at noon?",
                received_at=WHEN,
                unread=True,
            ),
        )

    def test_read_message_is_not_unread(self) -> None:
        self.assertFalse(parse_message(message(labelIds=["INBOX"])).unread)

    def test_missing_labels_is_not_unread(self) -> None:
        msg = message()
        del msg["labelIds"]
        self.assertFalse(parse_message(msg).unread)

    def test_header_names_are_case_insensitive(self) -> None:
        email = parse_message(with_headers(("sUbJeCt", "Hello")))
        self.assertEqual(email.subject, "Hello")

    def test_first_duplicate_header_wins(self) -> None:
        email = parse_message(with_headers(("Subject", "One"), ("Subject", "Two")))
        self.assertEqual(email.subject, "One")

    def test_missing_or_blank_subject(self) -> None:
        self.assertEqual(parse_message(with_headers()).subject, "(no subject)")
        blank = parse_message(with_headers(("Subject", "  \n ")))
        self.assertEqual(blank.subject, "(no subject)")

    def test_encoded_subject_decoded(self) -> None:
        encoded = Header("Café menu", "utf-8").encode()
        email = parse_message(with_headers(("Subject", encoded)))
        self.assertEqual(email.subject, "Café menu")

    def test_unknown_charset_in_subject_does_not_crash(self) -> None:
        email = parse_message(with_headers(("Subject", "=?x-nope?q?hi?=")))
        self.assertTrue(email.subject)

    def test_date_header_used_when_internal_date_missing(self) -> None:
        msg = message()
        del msg["internalDate"]
        self.assertEqual(parse_message(msg).received_at, WHEN)

    def test_invalid_internal_date_falls_back_to_header(self) -> None:
        self.assertEqual(parse_message(message(internalDate="abc")).received_at, WHEN)

    def test_no_usable_date_gives_none_not_a_guess(self) -> None:
        msg = with_headers(("Subject", "x"))
        del msg["internalDate"]
        self.assertIsNone(parse_message(msg).received_at)

    def test_absurd_internal_date_is_ignored(self) -> None:
        msg = with_headers(("Subject", "x"))
        msg["internalDate"] = "9" * 30
        self.assertIsNone(parse_message(msg).received_at)

    def test_missing_payload_does_not_crash(self) -> None:
        msg = message()
        del msg["payload"]
        email = parse_message(msg)
        self.assertEqual(email.subject, "(no subject)")
        self.assertEqual(email.sender_label, "Unknown sender")

    def test_missing_id_raises(self) -> None:
        msg = message()
        del msg["id"]
        with self.assertRaises(EmailParseError):
            parse_message(msg)

    def test_thread_id_defaults_to_id(self) -> None:
        msg = message()
        del msg["threadId"]
        self.assertEqual(parse_message(msg).thread_id, "m1")

    def test_email_is_immutable(self) -> None:
        email = parse_message(message())
        with self.assertRaises(dataclasses.FrozenInstanceError):
            email.subject = "changed"  # type: ignore[misc]

    def test_snippet_is_cleaned(self) -> None:
        email = parse_message(message(snippet="It&#39;s  here"))
        self.assertEqual(email.snippet, "It's here")


if __name__ == "__main__":
    unittest.main()

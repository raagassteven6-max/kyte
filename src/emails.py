"""Turn Gmail "metadata" messages into display-ready Email records.

Only headers and Gmail's short snippet are ever read. Message bodies are
never requested or stored. All text fields are plain text, so the UI must
render them with textContent (never innerHTML).
"""

import html
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from email.errors import HeaderParseError
from email.header import decode_header, make_header
from email.utils import parseaddr, parsedate_to_datetime
from typing import Any

SNIPPET_LIMIT = 140
NO_SUBJECT = "(no subject)"
UNKNOWN_SENDER = "Unknown sender"

# Zero-width and padding characters that marketing mail uses to fill previews.
# U+200D (zero-width joiner) is kept on purpose: emoji sequences need it.
_INVISIBLE = dict.fromkeys(
    map(ord, "\u00ad\u034f\u180e\u200b\u200c\u2060\ufeff"), None
)
_WHITESPACE = re.compile(r"\s+")


class EmailParseError(ValueError):
    """Raised when a Gmail message lacks the minimum data to show a card."""


@dataclass(frozen=True, slots=True)
class Email:
    """One email, reduced to what a dashboard card shows."""

    id: str
    thread_id: str
    sender_name: str
    sender_address: str
    subject: str
    snippet: str
    received_at: datetime | None
    unread: bool

    @property
    def sender_label(self) -> str:
        """Name to show for the sender.

        A display name that itself contains "@" is treated as a possible
        spoof of another address, so the real address is shown instead.
        """
        if self.sender_name and "@" not in self.sender_name:
            return self.sender_name
        return self.sender_address or self.sender_name or UNKNOWN_SENDER


def _normalise(text: str) -> str:
    return _WHITESPACE.sub(" ", text.translate(_INVISIBLE)).strip()


def _decode_header_text(value: str) -> str:
    """Decode RFC 2047 encoded words; return the raw text if undecodable."""
    try:
        return str(make_header(decode_header(value)))
    except (HeaderParseError, UnicodeError, LookupError):
        return value


def parse_sender(header: str) -> tuple[str, str]:
    """Split a From header into (display name, address)."""
    name, address = parseaddr(header)
    return _normalise(_decode_header_text(name)), address.strip()


def clean_snippet(snippet: str, limit: int = SNIPPET_LIMIT) -> str:
    """Make a Gmail snippet safe and short enough for a card.

    Unescapes the HTML entities Gmail leaves in snippets, drops invisible
    padding characters, collapses whitespace, and shortens to at most
    ``limit`` characters on a word boundary, ending with an ellipsis.
    """
    text = _normalise(html.unescape(snippet))
    if len(text) <= limit:
        return text
    cut = text[: limit - 1]
    if text[limit - 1] != " " and " " in cut:
        cut = cut.rsplit(" ", 1)[0]
    return cut.rstrip() + "…"


def _headers(message: Mapping[str, Any]) -> dict[str, str]:
    payload = message.get("payload") or {}
    found: dict[str, str] = {}
    for header in payload.get("headers") or []:
        name = str(header.get("name", "")).lower()
        found.setdefault(name, str(header.get("value", "")))
    return found


def _received_at(message: Mapping[str, Any], date_header: str) -> datetime | None:
    """Prefer Gmail's internalDate; fall back to the Date header; else None."""
    try:
        return datetime.fromtimestamp(int(message["internalDate"]) / 1000, UTC)
    except (KeyError, TypeError, ValueError, OverflowError, OSError):
        pass
    if date_header:
        try:
            parsed = parsedate_to_datetime(date_header)
        except (TypeError, ValueError):
            return None
        if parsed.tzinfo is None:  # "-0000" means UTC with unknown local zone
            return parsed.replace(tzinfo=UTC)
        return parsed.astimezone(UTC)
    return None


def parse_message(message: Mapping[str, Any]) -> Email:
    """Build an Email from a Gmail API message fetched with format=metadata.

    Raises:
        EmailParseError: if the message has no id.
    """
    message_id = message.get("id")
    if not message_id:
        raise EmailParseError("Gmail message has no id.")
    headers = _headers(message)
    name, address = parse_sender(headers.get("from", ""))
    subject = _normalise(_decode_header_text(headers.get("subject", "")))
    return Email(
        id=str(message_id),
        thread_id=str(message.get("threadId") or message_id),
        sender_name=name,
        sender_address=address,
        subject=subject or NO_SUBJECT,
        snippet=clean_snippet(str(message.get("snippet", ""))),
        received_at=_received_at(message, headers.get("date", "")),
        unread="UNREAD" in (message.get("labelIds") or []),
    )

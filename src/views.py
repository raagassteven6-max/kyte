"""Pure functions that decide which emails to show and how to present them."""

from collections.abc import Collection, Iterable
from datetime import datetime, tzinfo
from typing import Any, Literal
from urllib.parse import quote, urlencode

from kyte.emails import Email

FilterMode = Literal["all", "unread", "today"]
FILTER_MODES: tuple[FilterMode, ...] = ("all", "unread", "today")


def _newest_first(email: Email) -> tuple[bool, float]:
    when = email.received_at
    return (when is None, -when.timestamp() if when else 0.0)


def filter_emails(
    emails: Iterable[Email],
    mode: FilterMode,
    *,
    now: datetime,
    tz: tzinfo,
    dismissed: Collection[str] = frozenset(),
) -> list[Email]:
    """Return the emails to display, newest first (undated last).

    "Today" means the same calendar date as ``now`` in the user's timezone
    ``tz``, so mail from late last night is not shown as today. Emails with
    no known date are never "today". Dismissed ids are always excluded.

    Raises:
        ValueError: if ``mode`` is not one of FILTER_MODES.
    """
    today = now.astimezone(tz).date()
    visible = (e for e in emails if e.id not in dismissed)
    match mode:
        case "all":
            chosen = list(visible)
        case "unread":
            chosen = [e for e in visible if e.unread]
        case "today":
            chosen = [
                e for e in visible
                if e.received_at and e.received_at.astimezone(tz).date() == today
            ]
        case _:
            raise ValueError(f"Unknown filter mode: {mode!r}")
    return sorted(chosen, key=_newest_first)


def gmail_link(thread_id: str, owner_email: str) -> str:
    """Link that opens a thread in Gmail for the owner's account.

    NOTE: the ``#all/<threadId>`` form is built from Gmail's documented
    thread id but has not been checked against live Gmail yet.
    """
    query = urlencode({"authuser": owner_email}, quote_via=quote)
    return f"https://mail.google.com/mail/?{query}#all/{quote(thread_id, safe='')}"


def email_to_card(email: Email, owner_email: str) -> dict[str, Any]:
    """JSON-ready card data. Plain text only; render with textContent."""
    return {
        "id": email.id,
        "sender": email.sender_label,
        "sender_address": email.sender_address,
        "subject": email.subject,
        "snippet": email.snippet,
        "received_at": email.received_at.isoformat() if email.received_at else None,
        "unread": email.unread,
        "gmail_url": gmail_link(email.thread_id, owner_email),
    }

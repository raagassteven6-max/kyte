"""Where emails come from: a mock for development, Gmail later (Task 7)."""

from datetime import UTC, datetime, timedelta
from email.header import Header
from typing import Any, Protocol

from kyte.config import Settings
from kyte.credentials import CredentialStore
from kyte.emails import Email, parse_message
from kyte.gmail import GmailSource, TokenRefresher


class MailSource(Protocol):
    """Anything that can supply the recent inbox as Email records."""

    def fetch_recent(self) -> list[Email]:
        """Return recent inbox messages, read and unread."""
        ...


class MockSource:
    """Deterministic sample inbox, built through the real parser.

    Includes the awkward cases the UI must survive: no subject, a very long
    subject, emoji, encoded headers, padded newsletter previews, and a
    display-name spoof.
    """

    def __init__(self, now: datetime | None = None) -> None:
        self._now = now or datetime.now(UTC)

    def _msg(
        self, id_: str, ago: timedelta, sender: str, subject: str | None,
        snippet: str, unread: bool = True,
    ) -> dict[str, Any]:
        headers = [{"name": "From", "value": sender}]
        if subject is not None:
            headers.append({"name": "Subject", "value": subject})
        when = self._now - ago
        return {
            "id": id_,
            "threadId": f"thread-{id_}",
            "labelIds": ["INBOX", "UNREAD"] if unread else ["INBOX"],
            "snippet": snippet,
            "internalDate": str(int(when.timestamp() * 1000)),
            "payload": {"headers": headers},
        }

    def fetch_recent(self) -> list[Email]:
        m, h, d = timedelta(minutes=1), timedelta(hours=1), timedelta(days=1)
        pad = "\u200c\u00a0" * 6
        messages = [
            self._msg("m01", 12 * m, "Priya Nair <priya@brightloop.example>",
                      "Design review moved to 3pm",
                      "Hi! Quick heads-up: the review is now at 3pm in the "
                      "blue room. Bring the latest mockups if you have them."),
            self._msg("m02", 45 * m, "GitHub <notifications@github.example>",
                      "[kyte] Pull request #42 merged",
                      "Merged into main. 3 files changed, 2 comments resolved."),
            self._msg("m03", 3 * h, "Marcus Webb <marcus@webbstudio.example>",
                      "Invoice 2026-087 is ready",
                      "Hi, your invoice for October is attached. Payment is "
                      "due within 14 days. Thanks again for the work."),
            self._msg("m04", 1 * h, '"support@paypal.example" <evil@scam.example>',
                      "Verify your account now", "Your account is limited. "
                      "Click here to restore access immediately."),
            self._msg("m05", 5 * h, "Lumen Bank <alerts@lumenbank.example>",
                      "New sign-in from a new device",
                      "We noticed a sign-in from a device we don&#39;t "
                      "recognise. If this was you, no action is needed."),
            self._msg("m06", 8 * h, "Ana Souza <ana@souza.example>",
                      "Re: weekend trip?", "Saturday works for me! Should we "
                      "take the early train or drive up in the afternoon?",
                      unread=False),
            self._msg("m07", 20 * h + 30 * m,
                      "The Weekly Kite <hello@weeklykite.example>",
                      "Seven kites that never fall",
                      f"Don&#39;t miss this week&#39;s issue {pad} on wind, "
                      "string and patience. " + "More inside. " * 20, unread=False),
            self._msg("m08", 26 * h, "noreply@example.org", None, "", unread=False),
            self._msg("m09", 2 * d, "Jo \U0001F388 Park <jo@park.example>",
                      "Thoughts on the quarterly planning doc, the roadmap "
                      "ordering, the risks section and what we should cut first "
                      "if the timeline slips again this year",
                      "Left comments throughout.", unread=True),
            self._msg("m10", 3 * d, "Caf\u00e9 Lumi\u00e8re <hello@lumiere.example>",
                      Header("Menu d\u2019automne", "utf-8").encode(),
                      "Our autumn menu is here.", unread=False),
        ]
        return [parse_message(message) for message in messages]


def build_source(
    settings: Settings,
    *,
    creds: CredentialStore | None = None,
    google: TokenRefresher | None = None,
) -> MailSource:
    """Pick the mail source for the current settings.

    Mock mode serves sample mail. Otherwise Gmail is read through the stored
    credentials.

    Raises:
        ValueError: in real mode without a credential store and Google client.
    """
    if settings.mock_mode:
        return MockSource()
    if creds is None or google is None:
        raise ValueError("Real mode needs a credential store and a Google client.")
    return GmailSource(creds, google)

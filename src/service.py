"""Application logic joining a mail source, filters and card formatting."""

from collections.abc import Collection
from datetime import datetime, tzinfo
from typing import Any

from kyte.sources import MailSource
from kyte.views import FilterMode, email_to_card, filter_emails


def list_cards(
    source: MailSource,
    *,
    mode: FilterMode,
    now: datetime,
    tz: tzinfo,
    owner_email: str,
    dismissed: Collection[str],
) -> list[dict[str, Any]]:
    """Fetch recent mail and return the cards for the chosen filter."""
    emails = filter_emails(
        source.fetch_recent(), mode, now=now, tz=tz, dismissed=dismissed
    )
    return [email_to_card(email, owner_email) for email in emails]

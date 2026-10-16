"""Read-only Gmail access: the recent inbox as Email records.

Only message metadata (From, Subject, Date) and Gmail's own short snippet are
requested. Message bodies are never fetched. Read/unread state always comes
from Gmail's labels, so it stays current even though message details are
cached in memory.
"""

import http.client
import json
import logging
import random
import re
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from typing import Any, Protocol
from urllib.parse import quote, urlencode

from kyte.credentials import CredentialError, CredentialStore
from kyte.emails import Email, EmailParseError, parse_message
from kyte.oauth import AccessToken, GoogleError, require_secure_url

log = logging.getLogger("kyte.gmail")

API_BASE = "https://gmail.googleapis.com/gmail/v1"
LOOKBACK_DAYS = 14
TOKEN_SAFETY_MARGIN = 60  # refresh this many seconds before expiry
MAX_RETRY_WAIT = 30.0
_MAX_RESPONSE_BYTES = 2_000_000
_VALID_ID = re.compile(r"[A-Za-z0-9_-]{1,64}")
_RATE_LIMIT_REASONS = {"rateLimitExceeded", "userRateLimitExceeded"}
_PERMISSION_REASONS = {"insufficientPermissions"}  # not yet checked against live Gmail
_RETRYABLE_STATUSES = {0, 429, 500, 502, 503, 504}  # 0 = network failure


class MailError(Exception):
    """Base class for mail problems. ``code`` is stable and safe to show."""

    code = "mail_error"

    def __init__(self, message: str = "") -> None:
        super().__init__(message or self.code)


class NotConnected(MailError):
    """Gmail has not been connected yet."""

    code = "not_connected"


class ReconnectRequired(MailError):
    """Google no longer honours the stored credentials; sign in again."""

    code = "reconnect_required"


class MailUnavailable(MailError):
    """Gmail could not be read right now (busy, down or unreachable)."""

    code = "mail_unavailable"


class _MessageGone(Exception):
    """The message was deleted between listing and fetching."""


class TokenRefresher(Protocol):
    def refresh_access_token(self, refresh_token: str) -> AccessToken: ...


@dataclass(frozen=True, slots=True)
class _CachedToken:
    value: str
    expires_at: float


def _error_reason(raw: bytes) -> str:
    """Pull Google's error reason out of an error body, if there is one."""
    try:
        error = json.loads(raw).get("error")
        if isinstance(error, dict):
            errors = error.get("errors")
            if isinstance(errors, list) and errors and isinstance(errors[0], dict):
                return str(errors[0].get("reason", ""))
            return str(error.get("status", ""))
    except (ValueError, AttributeError):
        pass
    return ""


class GmailSource:
    """Mail source backed by the Gmail REST API."""

    def __init__(
        self,
        creds: CredentialStore,
        google: TokenRefresher,
        *,
        api_base: str = API_BASE,
        page_size: int = 50,
        max_messages: int = 60,
        lookback_days: int = LOOKBACK_DAYS,
        workers: int = 8,
        timeout: float = 10.0,
        max_retries: int = 3,
        base_delay: float = 1.0,
        cache_limit: int = 500,
        clock: Callable[[], float] = time.time,
        sleep: Callable[[float], None] = time.sleep,
        rng: Callable[[], float] = random.random,
    ) -> None:
        require_secure_url(api_base)
        self._creds = creds
        self._google = google
        self._api_base = api_base.rstrip("/")
        self._page_size = page_size
        self._max_messages = max_messages
        self._lookback_days = lookback_days
        self._workers = workers
        self._timeout = timeout
        self._max_retries = max_retries
        self._base_delay = base_delay
        self._cache_limit = cache_limit
        self._clock = clock
        self._sleep = sleep
        self._rng = rng
        self._token: _CachedToken | None = None
        self._token_lock = threading.Lock()
        self._cache: dict[str, Email] = {}
        self._cache_lock = threading.Lock()

    # ---- access tokens -------------------------------------------------

    def _refresh_token(self) -> str:
        try:
            token = self._creds.load()
        except CredentialError as exc:
            raise ReconnectRequired("Stored Gmail credentials are unreadable.") from exc
        if token is None:
            raise NotConnected("Gmail is not connected.")
        return token

    def _access_token(self) -> str:
        with self._token_lock:
            cached = self._token
            if cached and cached.expires_at - TOKEN_SAFETY_MARGIN > self._clock():
                return cached.value
            try:
                fresh = self._google.refresh_access_token(self._refresh_token())
            except GoogleError as exc:
                if exc.code == "invalid_grant":
                    raise ReconnectRequired(
                        "Google no longer accepts this login."
                    ) from exc
                raise MailUnavailable("Could not get Gmail access.") from exc
            self._token = _CachedToken(fresh.token, self._clock() + fresh.expires_in)
            return fresh.token

    def _drop_token(self, rejected: str) -> None:
        """Forget the cached token, but only if it is the one that failed."""
        with self._token_lock:
            if self._token and self._token.value == rejected:
                self._token = None

    # ---- HTTP with retries --------------------------------------------

    def _http_get(self, url: str, token: str) -> tuple[int, Mapping[str, str], bytes]:
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
        request = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=self._timeout) as response:
                body = response.read(_MAX_RESPONSE_BYTES)
                return response.status, response.headers, body
        except urllib.error.HTTPError as err:
            try:
                return err.code, err.headers, err.read(_MAX_RESPONSE_BYTES)
            finally:
                err.close()
        except (
            urllib.error.URLError, TimeoutError, OSError, http.client.HTTPException
        ):
            return 0, {}, b""

    def _delay(self, attempt: int, headers: Mapping[str, str]) -> float:
        """Seconds to wait: Retry-After if given, else jittered exponential."""
        retry_after = headers.get("Retry-After")
        if retry_after:
            try:
                return min(max(float(retry_after), 0.0), MAX_RETRY_WAIT)
            except ValueError:
                pass
        jitter = 0.5 + 0.5 * self._rng()
        return min(self._base_delay * 2**attempt * jitter, MAX_RETRY_WAIT)

    def _get_json(self, path: str, params: Mapping[str, Any]) -> dict[str, Any]:
        url = f"{self._api_base}{path}?{urlencode(params, doseq=True)}"
        attempt = 0
        refreshed = False
        while True:
            token = self._access_token()
            status, headers, raw = self._http_get(url, token)
            if status == 200:
                try:
                    data = json.loads(raw)
                except ValueError:
                    raise MailUnavailable("Gmail sent an unreadable reply.") from None
                if not isinstance(data, dict):
                    raise MailUnavailable("Gmail sent an unexpected reply.")
                return data
            if status == 401:
                if refreshed:
                    raise ReconnectRequired("Gmail rejected the saved login.")
                refreshed = True
                self._drop_token(token)
                continue
            reason = _error_reason(raw)
            if status == 403 and reason in _PERMISSION_REASONS:
                raise ReconnectRequired("Gmail permission is missing.")
            if status == 404:
                raise _MessageGone
            rate_limited = status == 403 and reason in _RATE_LIMIT_REASONS
            if status in _RETRYABLE_STATUSES or rate_limited:
                if attempt >= self._max_retries:
                    raise MailUnavailable("Gmail is busy or unreachable.")
                log.info("gmail retry %d (status %s)", attempt + 1, status)
                self._sleep(self._delay(attempt, headers))
                attempt += 1
                continue
            # Short Google reason codes (e.g. "accessNotConfigured" when the
            # Gmail API isn't enabled) help diagnose first-run problems.
            log.warning("gmail error status=%s reason=%s", status, reason[:60])
            raise MailUnavailable(f"Gmail returned an error ({status}).")

    # ---- the mail itself ------------------------------------------------

    def _list_ids(self, *, unread_only: bool) -> list[str]:
        labels = ["INBOX", "UNREAD"] if unread_only else ["INBOX"]
        ids: list[str] = []
        page_token: str | None = None
        while len(ids) < self._max_messages:
            params: dict[str, Any] = {
                "labelIds": labels,
                "q": f"newer_than:{self._lookback_days}d",
                "maxResults": min(self._page_size, self._max_messages - len(ids)),
            }
            if page_token:
                params["pageToken"] = page_token
            data = self._get_json("/users/me/messages", params)
            for item in data.get("messages") or []:
                message_id = item.get("id") if isinstance(item, dict) else None
                if isinstance(message_id, str) and _VALID_ID.fullmatch(message_id):
                    ids.append(message_id)
            next_token = data.get("nextPageToken")
            if not isinstance(next_token, str) or not next_token:
                break
            page_token = next_token
        return ids[: self._max_messages]

    def _fetch_one(self, message_id: str) -> Email | None:
        try:
            data = self._get_json(
                f"/users/me/messages/{quote(message_id, safe='')}",
                {"format": "metadata", "metadataHeaders": ["From", "Subject", "Date"]},
            )
        except _MessageGone:
            return None
        try:
            email = parse_message(data)
        except EmailParseError:
            return None
        return email if email.id == message_id else None

    def _remember(self, fetched: list[Email]) -> None:
        with self._cache_lock:
            for email in fetched:
                self._cache[email.id] = email
            while len(self._cache) > self._cache_limit:
                del self._cache[next(iter(self._cache))]  # oldest first

    def fetch_recent(self) -> list[Email]:
        """Return the recent inbox, newest first, read and unread.

        Raises:
            NotConnected: Gmail has not been connected.
            ReconnectRequired: Google no longer accepts the saved login.
            MailUnavailable: Gmail is busy, down or unreachable.
        """
        ids = self._list_ids(unread_only=False)
        unread = set(self._list_ids(unread_only=True))
        with self._cache_lock:
            missing = [i for i in ids if i not in self._cache]
        if missing:
            workers = min(self._workers, len(missing))
            with ThreadPoolExecutor(max_workers=workers) as pool:
                fetched = [e for e in pool.map(self._fetch_one, missing) if e]
            self._remember(fetched)
        with self._cache_lock:
            return [
                replace(self._cache[i], unread=i in unread)
                for i in ids
                if i in self._cache
            ]

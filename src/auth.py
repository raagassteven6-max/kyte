"""Sign-in orchestration: owner-only access to the dashboard.

Only the person whose address is KYTE_OWNER_EMAIL can sign in. Everyone else
is refused, and the Google grant they just made is revoked.
"""

import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Protocol
from urllib.parse import urlparse

from kyte.config import Settings
from kyte.credentials import CredentialError, CredentialStore
from kyte.oauth import (
    GMAIL_SCOPE, AuthError, FlowState, GoogleError, Tokens, build_auth_url,
    callback_code, check_owner, id_token_claims, new_flow,
)
from kyte.security import CookieSigner

FLOW_SECONDS = 10 * 60
SESSION_SECONDS = 7 * 24 * 3600


class GoogleClient(Protocol):
    """The two Google calls the sign-in flow needs."""

    def exchange_code(self, code: str, verifier: str, redirect_uri: str) -> Tokens: ...

    def revoke(self, token: str) -> bool: ...


@dataclass(frozen=True, slots=True)
class LoginStart:
    """Where to send the browser, and the cookie that remembers the attempt."""

    url: str
    flow_cookie: str


def origin_allowed(origin: str | None, base_url: str) -> bool:
    """True only if ``origin`` is exactly this app's own origin.

    Used on state-changing requests as a second line of defence against
    cross-site forgery. A missing Origin header is refused.
    """
    if not origin:
        return False
    parsed = urlparse(base_url)
    return origin == f"{parsed.scheme}://{parsed.netloc}"


class AuthService:
    """Starts and finishes sign-in, issues sessions, handles disconnect."""

    def __init__(
        self,
        settings: Settings,
        google: GoogleClient,
        creds: CredentialStore,
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if not settings.google_client_id:
            raise ValueError("Google sign-in needs GOOGLE_CLIENT_ID.")
        self._settings = settings
        self._google = google
        self._creds = creds
        self._clock = clock
        secret = settings.secret_key
        self._flow_cookie = CookieSigner(secret, "oauth-flow", FLOW_SECONDS)
        self._session_cookie = CookieSigner(secret, "session", SESSION_SECONDS)

    @property
    def redirect_uri(self) -> str:
        """The exact URI to register in the Google Cloud console."""
        return f"{self._settings.base_url}/auth/callback"

    def start_login(self) -> LoginStart:
        flow = new_flow()
        url = build_auth_url(
            client_id=self._settings.google_client_id or "",
            redirect_uri=self.redirect_uri,
            flow=flow,
        )
        cookie = self._flow_cookie.dumps(
            {"state": flow.state, "nonce": flow.nonce, "verifier": flow.verifier}
        )
        return LoginStart(url=url, flow_cookie=cookie)

    def finish_login(self, query: Mapping[str, str], flow_cookie: str | None) -> str:
        """Complete sign-in and return a new session cookie value.

        Raises:
            AuthError: if anything about the attempt is wrong. Nothing is
                stored unless every check passes.
        """
        data = self._flow_cookie.loads(flow_cookie)
        if data is None:
            raise AuthError("expired")
        state, nonce, verifier = (data.get(k) for k in ("state", "nonce", "verifier"))
        if not all(isinstance(v, str) for v in (state, nonce, verifier)):
            raise AuthError("invalid")
        flow = FlowState(state=state, nonce=nonce, verifier=verifier)

        code = callback_code(query, flow)
        try:
            tokens = self._google.exchange_code(code, flow.verifier, self.redirect_uri)
        except GoogleError as exc:
            raise AuthError("google") from exc

        grant = tokens.refresh_token or tokens.access_token
        try:
            claims = id_token_claims(tokens.id_token)
            check_owner(
                claims,
                client_id=self._settings.google_client_id or "",
                nonce=flow.nonce,
                owner_email=self._settings.owner_email,
                now=self._clock(),
            )
        except AuthError:
            self._google.revoke(grant)  # don't leave a stranger's grant behind
            raise
        if GMAIL_SCOPE not in tokens.scope.split():
            self._google.revoke(grant)
            raise AuthError("scope")
        if not tokens.refresh_token:
            self._google.revoke(grant)
            raise AuthError("no_refresh_token")

        self._creds.save(
            tokens.refresh_token,
            email=self._settings.owner_email,
            scope=tokens.scope,
        )
        return self.issue_session(self._settings.owner_email)

    def issue_session(self, email: str) -> str:
        return self._session_cookie.dumps({"email": email.strip().lower()})

    def owner_from_session(self, cookie: str | None) -> str | None:
        """The owner's address if the session is genuine, current and theirs."""
        data = self._session_cookie.loads(cookie)
        email = data.get("email") if data else None
        if isinstance(email, str) and email == self._settings.owner_email:
            return email
        return None

    def disconnect(self) -> bool:
        """Revoke the stored token at Google and forget it locally.

        Returns True if Google confirmed the revocation. The local copy is
        removed either way.
        """
        try:
            token = self._creds.load()
        except CredentialError:
            token = None
        revoked = self._google.revoke(token) if token else False
        self._creds.clear()
        return revoked

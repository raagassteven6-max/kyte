"""Google OAuth 2.0 / OpenID Connect pieces, kept free of web-framework code.

Flow: authorization code + PKCE (S256), offline access, read-only Gmail.
Google is called with the standard library so the logic runs and tests
without extra dependencies.
"""

import base64
import binascii
import hashlib
import hmac
import json
import re
import secrets
import urllib.error
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Literal
from urllib.parse import urlencode, urlparse

AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_URL = "https://oauth2.googleapis.com/token"
REVOKE_URL = "https://oauth2.googleapis.com/revoke"
GMAIL_SCOPE = "https://www.googleapis.com/auth/gmail.readonly"
SCOPES = ("openid", "email", GMAIL_SCOPE)
ISSUERS = ("https://accounts.google.com", "accounts.google.com")
_MAX_RESPONSE_BYTES = 1_000_000
_ERROR_CODE = re.compile(r"[a-z_]{1,40}")

type Reason = Literal[
    "denied", "invalid", "expired", "not_owner", "google",
    "no_refresh_token", "scope",
]


class AuthError(Exception):
    """A sign-in attempt failed. ``reason`` is a short, safe-to-show code."""

    def __init__(self, reason: Reason) -> None:
        super().__init__(reason)
        self.reason: Reason = reason


class GoogleError(Exception):
    """Google could not be reached or answered unusably.

    Never contains codes, tokens or secrets.
    """

    def __init__(self, message: str, code: str | None = None) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class FlowState:
    """Per-login secrets that must match when Google calls back."""

    state: str
    nonce: str
    verifier: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class Tokens:
    """What Google returns for a successful code exchange."""

    access_token: str = field(repr=False)
    refresh_token: str | None = field(repr=False)
    id_token: str = field(repr=False)
    scope: str


@dataclass(frozen=True, slots=True)
class AccessToken:
    """A short-lived Gmail access token and its lifetime in seconds."""

    token: str = field(repr=False)
    expires_in: int


def _safe_error_code(body: Any) -> str | None:
    """Google's short error code (like "invalid_grant") if it looks safe."""
    error = body.get("error") if isinstance(body, dict) else None
    if isinstance(error, str) and _ERROR_CODE.fullmatch(error):
        return error
    return None


def new_flow() -> FlowState:
    return FlowState(
        state=secrets.token_urlsafe(32),
        nonce=secrets.token_urlsafe(32),
        verifier=secrets.token_urlsafe(64),
    )


def pkce_challenge(verifier: str) -> str:
    """RFC 7636 S256 code challenge for a code verifier."""
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def build_auth_url(
    *, client_id: str, redirect_uri: str, flow: FlowState, endpoint: str = AUTH_URL
) -> str:
    """URL that sends the owner to Google's consent screen."""
    params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": " ".join(SCOPES),
        "state": flow.state,
        "nonce": flow.nonce,
        "code_challenge": pkce_challenge(flow.verifier),
        "code_challenge_method": "S256",
        # Offline access plus a forced consent screen, so Google reliably
        # returns a refresh token.
        "access_type": "offline",
        "prompt": "consent",
    }
    return f"{endpoint}?{urlencode(params)}"


def callback_code(query: Mapping[str, str], flow: FlowState) -> str:
    """Validate Google's redirect and return the authorization code.

    Raises:
        AuthError: on a state mismatch (possible CSRF), a user denial, a
            Google error, or a missing code.
    """
    given = query.get("state", "")
    if not hmac.compare_digest(given.encode(), flow.state.encode()):
        raise AuthError("invalid")
    error = query.get("error")
    if error:
        raise AuthError("denied" if error == "access_denied" else "invalid")
    code = query.get("code")
    if not code:
        raise AuthError("invalid")
    return code


def id_token_claims(id_token: str) -> dict[str, Any]:
    """Decode the claims of an ID token received directly from Google.

    The signature is deliberately not checked: per OpenID Connect Core
    (3.1.3.7), a token received straight from the token endpoint over TLS
    may rely on that TLS channel instead. Never use this on a token that
    arrived any other way. Claims are still validated by ``check_owner``.
    """
    parts = id_token.split(".")
    if len(parts) != 3:
        raise AuthError("invalid")
    segment = parts[1]
    try:
        raw = base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
        claims = json.loads(raw)
    except (ValueError, binascii.Error):
        raise AuthError("invalid") from None
    if not isinstance(claims, dict):
        raise AuthError("invalid")
    return claims


def check_owner(
    claims: Mapping[str, Any],
    *,
    client_id: str,
    nonce: str,
    owner_email: str,
    now: float,
) -> None:
    """Confirm the ID token is for this app, this login, and the owner.

    Raises:
        AuthError: with reason "invalid", "expired" or "not_owner".
    """
    if claims.get("iss") not in ISSUERS:
        raise AuthError("invalid")
    aud = claims.get("aud")
    audiences = aud if isinstance(aud, list) else [aud]
    if client_id not in audiences:
        raise AuthError("invalid")
    exp = claims.get("exp")
    if isinstance(exp, bool) or not isinstance(exp, int | float):
        raise AuthError("invalid")
    if exp <= now:
        raise AuthError("expired")
    token_nonce = claims.get("nonce")
    if not isinstance(token_nonce, str) or not hmac.compare_digest(
        token_nonce.encode(), nonce.encode()
    ):
        raise AuthError("invalid")
    email = claims.get("email")
    if not isinstance(email, str):
        raise AuthError("invalid")
    if claims.get("email_verified") not in (True, "true"):
        raise AuthError("invalid")
    if email.strip().lower() != owner_email.strip().lower():
        raise AuthError("not_owner")


def require_secure_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme == "https":
        return
    if parsed.scheme == "http" and parsed.hostname in ("127.0.0.1", "localhost"):
        return
    raise ValueError("Google endpoints must use https (loopback excepted for tests).")


class GoogleOAuth:
    """Calls Google's token and revocation endpoints."""

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        *,
        token_url: str = TOKEN_URL,
        revoke_url: str = REVOKE_URL,
        timeout: float = 10.0,
    ) -> None:
        require_secure_url(token_url)
        require_secure_url(revoke_url)
        self._client_id = client_id
        self._client_secret = client_secret
        self._token_url = token_url
        self._revoke_url = revoke_url
        self._timeout = timeout

    def __repr__(self) -> str:
        return f"GoogleOAuth(client_id={self._client_id!r})"

    def _post(self, url: str, fields: Mapping[str, str]) -> tuple[int, Any]:
        request = urllib.request.Request(
            url,
            data=urlencode(fields).encode(),
            method="POST",
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=self._timeout) as response:
                status, raw = response.status, response.read(_MAX_RESPONSE_BYTES)
        except urllib.error.HTTPError as err:
            try:
                status, raw = err.code, err.read(_MAX_RESPONSE_BYTES)
            finally:
                err.close()
        except (urllib.error.URLError, TimeoutError, OSError):
            raise GoogleError("Could not reach Google.") from None
        try:
            return status, json.loads(raw)
        except ValueError:
            return status, None

    def exchange_code(self, code: str, verifier: str, redirect_uri: str) -> Tokens:
        """Trade an authorization code (plus PKCE verifier) for tokens.

        Raises:
            GoogleError: if Google refuses or answers unusably.
        """
        status, body = self._post(
            self._token_url,
            {
                "grant_type": "authorization_code",
                "code": code,
                "code_verifier": verifier,
                "client_id": self._client_id,
                "client_secret": self._client_secret,
                "redirect_uri": redirect_uri,
            },
        )
        if status != 200 or not isinstance(body, dict):
            raise GoogleError(
                "Google rejected the sign-in request.", code=_safe_error_code(body)
            )
        access, id_token = body.get("access_token"), body.get("id_token")
        if not (isinstance(access, str) and access):
            raise GoogleError("Google's response was incomplete.")
        if not (isinstance(id_token, str) and id_token):
            raise GoogleError("Google's response was incomplete.")
        refresh = body.get("refresh_token")
        scope = body.get("scope")
        return Tokens(
            access_token=access,
            refresh_token=refresh if isinstance(refresh, str) and refresh else None,
            id_token=id_token,
            scope=scope if isinstance(scope, str) else "",
        )

    def refresh_access_token(self, refresh_token: str) -> AccessToken:
        """Trade the stored refresh token for a fresh access token.

        Raises:
            GoogleError: if Google refuses (``code`` is "invalid_grant" when
                the token was revoked or has expired) or answers unusably.
        """
        status, body = self._post(
            self._token_url,
            {
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "client_id": self._client_id,
                "client_secret": self._client_secret,
            },
        )
        if status != 200 or not isinstance(body, dict):
            raise GoogleError(
                "Google rejected the token refresh.", code=_safe_error_code(body)
            )
        access = body.get("access_token")
        if not (isinstance(access, str) and access):
            raise GoogleError("Google's response was incomplete.")
        lifetime = body.get("expires_in")
        valid = isinstance(lifetime, int) and not isinstance(lifetime, bool)
        return AccessToken(access, lifetime if valid and lifetime > 0 else 300)

    def revoke(self, token: str) -> bool:
        """Ask Google to invalidate a token. Returns False if that failed."""
        try:
            status, _ = self._post(self._revoke_url, {"token": token})
        except GoogleError:
            return False
        return status == 200

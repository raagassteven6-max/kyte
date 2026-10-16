"""Task 6 tests: the sign-in flow end to end, with Google replaced by a fake."""

import base64
import json
import tempfile
import unittest
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from kyte.auth import AuthService, origin_allowed
from kyte.config import Settings
from kyte.credentials import CredentialStore
from kyte.oauth import AuthError, GoogleError, Tokens
from kyte.security import TokenVault

NOW = 1_800_000_000
SECRET = "k" * 40
CID = "client-123.apps.googleusercontent.com"
GMAIL = "https://www.googleapis.com/auth/gmail.readonly"
REFRESH = "1//refresh-PLAINTEXT-marker"


def b64(obj: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()


def id_token(nonce: str, **over: object) -> str:
    claims = {"iss": "https://accounts.google.com", "aud": CID, "exp": NOW + 3600,
              "email": "me@example.com", "email_verified": True, "nonce": nonce}
    claims.update(over)
    return f"{b64({'alg': 'RS256'})}.{b64(claims)}.sig"


class FakeGoogle:
    def __init__(self) -> None:
        self.exchanges: list[tuple[str, str, str]] = []
        self.revoked: list[str] = []
        self.make_tokens = lambda nonce: Tokens(
            access_token="at", refresh_token=REFRESH,
            id_token=id_token(nonce), scope=f"openid email {GMAIL}")
        self.exchange_error: Exception | None = None
        self.revoke_result = True
        self.nonce = ""

    def exchange_code(self, code: str, verifier: str, redirect_uri: str) -> Tokens:
        self.exchanges.append((code, verifier, redirect_uri))
        if self.exchange_error:
            raise self.exchange_error
        return self.make_tokens(self.nonce)

    def revoke(self, token: str) -> bool:
        self.revoked.append(token)
        return self.revoke_result


class AuthServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.path = Path(tmp.name) / "kyte.db"
        self.settings = Settings.from_env({
            "KYTE_SECRET_KEY": SECRET, "KYTE_OWNER_EMAIL": "Me@Example.com",
            "KYTE_BASE_URL": "https://kyte.example.com", "KYTE_MOCK": "0",
            "GOOGLE_CLIENT_ID": CID, "GOOGLE_CLIENT_SECRET": "cs"})
        self.google = FakeGoogle()
        self.creds = CredentialStore(self.path, TokenVault(SECRET))
        self.svc = AuthService(self.settings, self.google, self.creds, clock=lambda: NOW)

    def begin(self) -> tuple[str, dict[str, str]]:
        start = self.svc.start_login()
        q = {k: v[0] for k, v in parse_qs(urlparse(start.url).query).items()}
        self.google.nonce = q["nonce"]
        return start.flow_cookie, q

    def finish(self, cookie: str | None, query: dict) -> str:
        return self.svc.finish_login(query, cookie)

    def reason(self, cookie: str | None, query: dict) -> str:
        with self.assertRaises(AuthError) as ctx:
            self.finish(cookie, query)
        return ctx.exception.reason

    def assert_nothing_saved(self) -> None:
        self.assertFalse(self.creds.is_connected())

    # --- starting ---
    def test_start_builds_a_google_url_for_our_callback(self) -> None:
        cookie, q = self.begin()
        self.assertEqual(q["redirect_uri"], "https://kyte.example.com/auth/callback")
        self.assertEqual(q["client_id"], CID)
        self.assertTrue(cookie)

    # --- happy path ---
    def test_successful_login_stores_encrypted_token_and_returns_session(self) -> None:
        cookie, q = self.begin()
        session = self.finish(cookie, {"state": q["state"], "code": "good-code"})
        self.assertEqual(self.svc.owner_from_session(session), "me@example.com")
        self.assertEqual(self.creds.load(), REFRESH)
        self.assertNotIn(REFRESH.encode(), self.path.read_bytes())
        code, verifier, redirect = self.google.exchanges[0]
        self.assertEqual((code, redirect), ("good-code", "https://kyte.example.com/auth/callback"))
        self.assertTrue(verifier)

    # --- CSRF / state ---
    def test_state_mismatch_is_rejected_before_calling_google(self) -> None:
        cookie, _ = self.begin()
        self.assertEqual(self.reason(cookie, {"state": "forged", "code": "c"}), "invalid")
        self.assertEqual(self.google.exchanges, [])
        self.assert_nothing_saved()

    def test_missing_tampered_or_foreign_flow_cookie_is_rejected(self) -> None:
        cookie, q = self.begin()
        query = {"state": q["state"], "code": "c"}
        for bad in (None, "", "garbage", cookie[:-2] + "xx"):
            self.assertEqual(self.reason(bad, query), "expired")
        session_like = self.svc.issue_session("me@example.com")
        self.assertEqual(self.reason(session_like, query), "expired")
        self.assertEqual(self.google.exchanges, [])

    def test_user_denial_is_reported(self) -> None:
        cookie, q = self.begin()
        self.assertEqual(self.reason(cookie, {"state": q["state"], "error": "access_denied"}), "denied")
        self.assertEqual(self.google.exchanges, [])

    # --- owner-only ---
    def test_a_stranger_cannot_sign_in_and_their_grant_is_revoked(self) -> None:
        cookie, q = self.begin()
        self.google.make_tokens = lambda nonce: Tokens(
            "at", "stranger-refresh", id_token(nonce, email="intruder@evil.example"),
            f"openid email {GMAIL}")
        self.assertEqual(self.reason(cookie, {"state": q["state"], "code": "c"}), "not_owner")
        self.assert_nothing_saved()
        self.assertIn("stranger-refresh", self.google.revoked)

    def test_unverified_email_is_refused(self) -> None:
        cookie, q = self.begin()
        self.google.make_tokens = lambda nonce: Tokens(
            "at", REFRESH, id_token(nonce, email_verified=False), f"openid email {GMAIL}")
        self.assertEqual(self.reason(cookie, {"state": q["state"], "code": "c"}), "invalid")
        self.assert_nothing_saved()

    def test_id_token_for_another_flow_is_refused(self) -> None:
        cookie, q = self.begin()
        self.google.nonce = "nonce-from-another-login"
        self.assertEqual(self.reason(cookie, {"state": q["state"], "code": "c"}), "invalid")
        self.assert_nothing_saved()

    # --- google problems ---
    def test_google_rejecting_the_code(self) -> None:
        cookie, q = self.begin()
        self.google.exchange_error = GoogleError("rejected")
        self.assertEqual(self.reason(cookie, {"state": q["state"], "code": "c"}), "google")
        self.assert_nothing_saved()

    def test_no_refresh_token_is_a_failure_not_a_silent_half_login(self) -> None:
        cookie, q = self.begin()
        self.google.make_tokens = lambda nonce: Tokens(
            "at", None, id_token(nonce), f"openid email {GMAIL}")
        self.assertEqual(self.reason(cookie, {"state": q["state"], "code": "c"}), "no_refresh_token")
        self.assert_nothing_saved()

    def test_declining_the_gmail_permission_is_refused(self) -> None:
        cookie, q = self.begin()
        self.google.make_tokens = lambda nonce: Tokens(
            "at", REFRESH, id_token(nonce), "openid email")
        self.assertEqual(self.reason(cookie, {"state": q["state"], "code": "c"}), "scope")
        self.assert_nothing_saved()

    # --- sessions ---
    def test_session_rules(self) -> None:
        good = self.svc.issue_session("me@example.com")
        self.assertEqual(self.svc.owner_from_session(good), "me@example.com")
        for bad in (None, "", "garbage", good[:-2] + "xx"):
            self.assertIsNone(self.svc.owner_from_session(bad))
        stranger = self.svc.issue_session("someone@else.example")
        self.assertIsNone(self.svc.owner_from_session(stranger))

    def test_flow_cookie_is_not_a_session(self) -> None:
        cookie, _ = self.begin()
        self.assertIsNone(self.svc.owner_from_session(cookie))

    # --- disconnect ---
    def test_disconnect_revokes_and_forgets(self) -> None:
        self.creds.save(REFRESH, email="me@example.com", scope="s")
        self.assertTrue(self.svc.disconnect())
        self.assertEqual(self.google.revoked, [REFRESH])
        self.assert_nothing_saved()

    def test_disconnect_forgets_even_if_google_revoke_fails(self) -> None:
        self.creds.save(REFRESH, email="me@example.com", scope="s")
        self.google.revoke_result = False
        self.assertFalse(self.svc.disconnect())
        self.assert_nothing_saved()

    def test_disconnect_when_never_connected_is_harmless(self) -> None:
        self.assertFalse(self.svc.disconnect())
        self.assertEqual(self.google.revoked, [])

    def test_disconnect_with_unreadable_token_still_clears_it(self) -> None:
        self.creds.save(REFRESH, email="me@example.com", scope="s")
        other = AuthService(self.settings, self.google,
                            CredentialStore(self.path, TokenVault("z" * 40)), clock=lambda: NOW)
        other.disconnect()
        self.assert_nothing_saved()


class OriginTests(unittest.TestCase):
    BASE = "https://kyte.example.com"

    def test_same_origin_allowed(self) -> None:
        self.assertTrue(origin_allowed("https://kyte.example.com", self.BASE))
        self.assertTrue(origin_allowed("https://kyte.example.com", self.BASE + "/"))

    def test_everything_else_refused(self) -> None:
        for origin in (None, "", "null", "https://evil.example", "http://kyte.example.com",
                       "https://kyte.example.com.evil.example", "https://kyte.example.com:8443",
                       "https://kyte.example.com/path"):
            self.assertFalse(origin_allowed(origin, self.BASE), str(origin))

    def test_localhost_with_port(self) -> None:
        self.assertTrue(origin_allowed("http://localhost:8000", "http://localhost:8000"))
        self.assertFalse(origin_allowed("http://localhost:9000", "http://localhost:8000"))


if __name__ == "__main__":
    unittest.main()

"""Task 3/4 tests: HTTP API wiring (needs fastapi + httpx)."""

import tempfile
import unittest
from urllib.parse import parse_qs, urlparse
from datetime import UTC, datetime
from pathlib import Path

from kyte.config import Settings
from kyte.sources import MockSource
from kyte.auth import AuthService
from kyte.credentials import CredentialStore
from kyte.security import TokenVault
from kyte.store import DismissedStore
from tests.test_auth import GMAIL, FakeGoogle, id_token

try:
    from fastapi.testclient import TestClient

    from kyte.app import create_app

    HAVE_WEB = True
except ImportError:
    HAVE_WEB = False

NOW = datetime(2026, 10, 13, 15, 0, tzinfo=UTC)
ENV = {"KYTE_SECRET_KEY": "s" * 32, "KYTE_OWNER_EMAIL": "me@example.com",
       "KYTE_MOCK": "1"}


@unittest.skipUnless(HAVE_WEB, "fastapi/httpx not installed")
class ApiTests(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.store = DismissedStore(Path(tmp.name) / "kyte.db")
        app = create_app(
            Settings.from_env(ENV), source=MockSource(now=NOW),
            store=self.store, clock=lambda: NOW,
        )
        self.client = TestClient(app)

    def test_lists_cards_newest_first(self) -> None:
        r = self.client.get("/api/emails")
        self.assertEqual(r.status_code, 200)
        cards = r.json()
        self.assertGreaterEqual(len(cards), 8)
        self.assertEqual(cards[0]["id"], "m01")

    def test_unread_filter(self) -> None:
        cards = self.client.get("/api/emails", params={"filter": "unread"}).json()
        self.assertTrue(cards and all(c["unread"] for c in cards))

    def test_unknown_filter_is_422(self) -> None:
        r = self.client.get("/api/emails", params={"filter": "bogus"})
        self.assertEqual(r.status_code, 422)

    def test_dismiss_hides_the_card_and_persists(self) -> None:
        self.assertEqual(self.client.post("/api/emails/m01/dismiss").status_code, 204)
        ids = [c["id"] for c in self.client.get("/api/emails").json()]
        self.assertNotIn("m01", ids)
        self.assertEqual(self.store.dismissed_ids(), {"m01"})

    def test_dismiss_is_idempotent(self) -> None:
        for _ in range(2):
            self.assertEqual(
                self.client.post("/api/emails/m01/dismiss").status_code, 204
            )

    def test_dismiss_rejects_bad_ids(self) -> None:
        r = self.client.post("/api/emails/" + "a" * 65 + "/dismiss")
        self.assertEqual(r.status_code, 422)


REAL_ENV = {
    "KYTE_SECRET_KEY": "k" * 40, "KYTE_OWNER_EMAIL": "me@example.com",
    "KYTE_BASE_URL": "https://kyte.example.com", "KYTE_MOCK": "0",
    "GOOGLE_CLIENT_ID": "client-123.apps.googleusercontent.com",
    "GOOGLE_CLIENT_SECRET": "cs",
}
ORIGIN = {"Origin": "https://kyte.example.com"}


@unittest.skipUnless(HAVE_WEB, "fastapi/httpx not installed")
class AuthApiTests(unittest.TestCase):
    """Real mode: sign-in required, with Google replaced by a fake."""

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / "kyte.db"
        env = {**REAL_ENV, "KYTE_DB_PATH": str(path)}
        settings = Settings.from_env(env)
        self.google = FakeGoogle()
        self.creds = CredentialStore(path, TokenVault(settings.secret_key))
        self.auth = AuthService(settings, self.google, self.creds)
        app = create_app(settings, source=MockSource(now=NOW),
                         store=DismissedStore(path), clock=lambda: NOW,
                         auth=self.auth, creds=self.creds)
        self.client = TestClient(app, base_url="https://kyte.example.com",
                                 follow_redirects=False)

    def sign_in_cookie(self) -> None:
        self.client.cookies.set("kyte_session", self.auth.issue_session("me@example.com"))

    def login_params(self) -> dict[str, str]:
        r = self.client.get("/auth/login")
        self.assertEqual(r.status_code, 302)
        q = {k: v[0] for k, v in parse_qs(urlparse(r.headers["location"]).query).items()}
        self.google.nonce = q["nonce"]
        return q

    def test_api_requires_a_session(self) -> None:
        self.assertEqual(self.client.get("/api/emails").status_code, 401)
        r = self.client.post("/api/emails/m01/dismiss", headers=ORIGIN)
        self.assertEqual(r.status_code, 401)

    def test_forged_or_foreign_session_cookie_is_refused(self) -> None:
        self.client.cookies.set("kyte_session", "forged")
        self.assertEqual(self.client.get("/api/emails").status_code, 401)
        self.client.cookies.set("kyte_session", self.auth.issue_session("other@evil.example"))
        self.assertEqual(self.client.get("/api/emails").status_code, 401)

    def test_session_endpoint_reports_state(self) -> None:
        self.assertEqual(self.client.get("/api/session").json(),
                         {"mock": False, "authenticated": False, "connected": False, "owner": None})
        self.sign_in_cookie()
        self.assertFalse(self.client.get("/api/session").json()["connected"])
        self.creds.save("rt", email="me@example.com", scope=GMAIL)
        body = self.client.get("/api/session").json()
        self.assertEqual((body["authenticated"], body["connected"], body["owner"]),
                         (True, True, "me@example.com"))

    def test_signed_in_owner_can_list_and_dismiss(self) -> None:
        self.sign_in_cookie()
        self.assertEqual(self.client.get("/api/emails").status_code, 200)
        r = self.client.post("/api/emails/m01/dismiss", headers=ORIGIN)
        self.assertEqual(r.status_code, 204)

    def test_state_changing_calls_need_the_apps_own_origin(self) -> None:
        self.sign_in_cookie()
        for headers in ({}, {"Origin": "https://evil.example"}, {"Origin": "null"}):
            r = self.client.post("/api/emails/m01/dismiss", headers=headers)
            self.assertEqual(r.status_code, 403, headers)
        self.assertEqual(self.client.post("/auth/disconnect").status_code, 403)

    def test_login_redirects_to_google_with_a_locked_down_cookie(self) -> None:
        r = self.client.get("/auth/login")
        self.assertEqual(r.status_code, 302)
        self.assertTrue(r.headers["location"].startswith(
            "https://accounts.google.com/o/oauth2/v2/auth?"))
        cookie = r.headers["set-cookie"].lower()
        for part in ("kyte_flow=", "httponly", "secure", "samesite=lax", "path=/auth"):
            self.assertIn(part, cookie)
        self.assertEqual(r.headers["cache-control"], "no-store")

    def test_full_sign_in_then_api_access(self) -> None:
        q = self.login_params()
        r = self.client.get("/auth/callback", params={"state": q["state"], "code": "c"})
        self.assertEqual((r.status_code, r.headers["location"]), (303, "/"))
        cookies = " ".join(r.headers.get_list("set-cookie")).lower()
        self.assertIn("kyte_session=", cookies)
        self.assertIn("httponly", cookies)
        self.assertEqual(self.client.get("/api/emails").status_code, 200)
        self.assertTrue(self.creds.is_connected())

    def test_failed_sign_ins_redirect_with_a_reason_and_no_session(self) -> None:
        q = self.login_params()
        r = self.client.get("/auth/callback", params={"state": "forged", "code": "c"})
        self.assertEqual(r.headers["location"], "/?auth_error=invalid")
        self.assertNotIn("kyte_session=", r.headers.get("set-cookie", "").lower())
        fresh = TestClient(self.client.app, base_url="https://kyte.example.com",
                           follow_redirects=False)
        r = fresh.get("/auth/callback", params={"state": q["state"], "code": "c"})
        self.assertEqual(r.headers["location"], "/?auth_error=expired")
        self.assertEqual(self.client.get("/api/emails").status_code, 401)

    def test_a_stranger_is_turned_away(self) -> None:
        q = self.login_params()
        self.google.make_tokens = lambda nonce: __import__("kyte.oauth", fromlist=["Tokens"]).Tokens(
            "at", "stranger-rt", id_token(nonce, email="intruder@evil.example"), f"openid email {GMAIL}")
        r = self.client.get("/auth/callback", params={"state": q["state"], "code": "c"})
        self.assertEqual(r.headers["location"], "/?auth_error=not_owner")
        self.assertFalse(self.creds.is_connected())
        self.assertEqual(self.client.get("/api/emails").status_code, 401)

    def test_disconnect_revokes_forgets_and_signs_out(self) -> None:
        self.sign_in_cookie()
        self.creds.save("rt-1", email="me@example.com", scope=GMAIL)
        r = self.client.post("/auth/disconnect", headers=ORIGIN)
        self.assertEqual(r.status_code, 204)
        self.assertEqual(self.google.revoked, ["rt-1"])
        self.assertFalse(self.creds.is_connected())
        self.assertEqual(self.client.get("/api/emails").status_code, 401)

    def test_logout_clears_the_session_but_keeps_gmail_connected(self) -> None:
        self.sign_in_cookie()
        self.creds.save("rt-1", email="me@example.com", scope=GMAIL)
        self.assertEqual(self.client.post("/auth/logout", headers=ORIGIN).status_code, 204)
        self.assertEqual(self.client.get("/api/emails").status_code, 401)
        self.assertTrue(self.creds.is_connected())


@unittest.skipUnless(HAVE_WEB, "fastapi/httpx not installed")
class MockModeAuthTests(unittest.TestCase):
    def test_no_sign_in_routes_and_no_login_needed(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        env = {**ENV, "KYTE_DB_PATH": str(Path(tmp.name) / "kyte.db")}
        client = TestClient(create_app(Settings.from_env(env), source=MockSource(now=NOW),
                                       clock=lambda: NOW), follow_redirects=False)
        self.assertEqual(client.get("/auth/login").status_code, 404)
        self.assertEqual(client.get("/api/emails").status_code, 200)
        self.assertEqual(client.post("/api/emails/m01/dismiss").status_code, 204)
        self.assertTrue(client.get("/api/session").json()["mock"])


if __name__ == "__main__":
    unittest.main()

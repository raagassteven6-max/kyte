"""Task 6 tests: PKCE, authorization URL, callback and ID-token checks, and
the Google HTTP client (run against a local stand-in for Google)."""

import base64
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from kyte.oauth import (
    SCOPES, AccessToken, AuthError, FlowState, GoogleError, GoogleOAuth, build_auth_url,
    callback_code, check_owner, id_token_claims, new_flow, pkce_challenge,
)

NOW = 1_800_000_000
CID = "client-123.apps.googleusercontent.com"


def b64(obj: dict) -> str:
    raw = json.dumps(obj).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def make_id_token(**claims: object) -> str:
    return f"{b64({'alg': 'RS256'})}.{b64(dict(claims))}.sig"


def good_claims(**over: object) -> dict:
    claims = {"iss": "https://accounts.google.com", "aud": CID, "exp": NOW + 3600,
              "email": "Me@Example.com", "email_verified": True, "nonce": "n1"}
    claims.update(over)
    return claims


class PkceTests(unittest.TestCase):
    def test_rfc7636_appendix_b_vector(self) -> None:
        verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        self.assertEqual(pkce_challenge(verifier),
                         "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")

    def test_new_flow_values_are_unique_and_long_enough(self) -> None:
        a, b = new_flow(), new_flow()
        self.assertNotEqual(a, b)
        self.assertGreaterEqual(len(a.verifier), 43)
        self.assertLessEqual(len(a.verifier), 128)
        self.assertEqual(len({a.state, a.nonce, a.verifier}), 3)


class AuthUrlTests(unittest.TestCase):
    def setUp(self) -> None:
        self.flow = FlowState(state="st", nonce="no", verifier="v" * 50)
        url = build_auth_url(client_id=CID, redirect_uri="https://k.example/auth/callback",
                             flow=self.flow)
        self.parts = urlparse(url)
        self.q = {k: v[0] for k, v in parse_qs(self.parts.query).items()}

    def test_endpoint_and_core_params(self) -> None:
        self.assertEqual(f"{self.parts.scheme}://{self.parts.netloc}{self.parts.path}",
                         "https://accounts.google.com/o/oauth2/v2/auth")
        self.assertEqual(self.q["client_id"], CID)
        self.assertEqual(self.q["response_type"], "code")
        self.assertEqual(self.q["redirect_uri"], "https://k.example/auth/callback")
        self.assertEqual(self.q["state"], "st")
        self.assertEqual(self.q["nonce"], "no")

    def test_pkce_and_offline_access(self) -> None:
        self.assertEqual(self.q["code_challenge_method"], "S256")
        self.assertEqual(self.q["code_challenge"], pkce_challenge(self.flow.verifier))
        self.assertNotIn(self.flow.verifier, self.parts.query)
        self.assertEqual(self.q["access_type"], "offline")
        self.assertEqual(self.q["prompt"], "consent")

    def test_requests_read_only_gmail_and_nothing_broader(self) -> None:
        scopes = self.q["scope"].split()
        self.assertEqual(tuple(scopes), SCOPES)
        self.assertIn("https://www.googleapis.com/auth/gmail.readonly", scopes)
        self.assertFalse(any("modify" in s or "send" in s or "mail.google.com" in s
                             for s in scopes))


class CallbackCodeTests(unittest.TestCase):
    flow = FlowState(state="st", nonce="no", verifier="v")

    def reason(self, query: dict) -> str:
        with self.assertRaises(AuthError) as ctx:
            callback_code(query, self.flow)
        return ctx.exception.reason

    def test_valid(self) -> None:
        self.assertEqual(callback_code({"state": "st", "code": "c1"}, self.flow), "c1")

    def test_state_mismatch_or_missing(self) -> None:
        self.assertEqual(self.reason({"state": "other", "code": "c1"}), "invalid")
        self.assertEqual(self.reason({"code": "c1"}), "invalid")

    def test_missing_code(self) -> None:
        self.assertEqual(self.reason({"state": "st"}), "invalid")

    def test_user_denied(self) -> None:
        self.assertEqual(self.reason({"state": "st", "error": "access_denied"}), "denied")

    def test_other_google_error(self) -> None:
        self.assertEqual(self.reason({"state": "st", "error": "server_error"}), "invalid")


class IdTokenTests(unittest.TestCase):
    def test_claims_are_decoded(self) -> None:
        self.assertEqual(id_token_claims(make_id_token(email="a@b.c"))["email"], "a@b.c")

    def test_garbage_is_rejected(self) -> None:
        for bad in ("", "x", "a.b", "a.!!!.c", f"a.{b64({})[:-3]}.c"):
            with self.subTest(bad=bad), self.assertRaises(AuthError):
                id_token_claims(bad)

    def test_non_object_payload_rejected(self) -> None:
        payload = base64.urlsafe_b64encode(b"[1,2]").decode()
        with self.assertRaises(AuthError):
            id_token_claims(f"a.{payload}.c")


class CheckOwnerTests(unittest.TestCase):
    def check(self, claims: dict) -> str:
        with self.assertRaises(AuthError) as ctx:
            check_owner(claims, client_id=CID, nonce="n1",
                        owner_email="me@example.com", now=NOW)
        return ctx.exception.reason

    def test_owner_accepted_case_insensitively(self) -> None:
        check_owner(good_claims(), client_id=CID, nonce="n1",
                    owner_email="me@example.com", now=NOW)

    def test_both_google_issuer_forms_accepted(self) -> None:
        check_owner(good_claims(iss="accounts.google.com"), client_id=CID,
                    nonce="n1", owner_email="me@example.com", now=NOW)

    def test_stranger_is_not_the_owner(self) -> None:
        self.assertEqual(self.check(good_claims(email="x@evil.example")), "not_owner")

    def test_lookalike_addresses_are_not_the_owner(self) -> None:
        for email in ("me@example.com.evil.example", "xme@example.com", "me@example.co"):
            self.assertEqual(self.check(good_claims(email=email)), "not_owner", email)

    def test_unverified_email(self) -> None:
        self.assertEqual(self.check(good_claims(email_verified=False)), "invalid")
        self.assertEqual(self.check(good_claims(email_verified="false")), "invalid")

    def test_wrong_audience_issuer_nonce_and_expiry(self) -> None:
        self.assertEqual(self.check(good_claims(aud="someone-else")), "invalid")
        self.assertEqual(self.check(good_claims(iss="https://evil.example")), "invalid")
        self.assertEqual(self.check(good_claims(nonce="replayed")), "invalid")
        self.assertEqual(self.check(good_claims(exp=NOW - 1)), "expired")

    def test_missing_claims_rejected(self) -> None:
        for name in ("iss", "aud", "exp", "email", "email_verified", "nonce"):
            claims = good_claims()
            del claims[name]
            self.assertIn(self.check(claims), {"invalid", "expired"}, name)

    def test_audience_may_be_a_list_containing_the_client(self) -> None:
        check_owner(good_claims(aud=[CID]), client_id=CID, nonce="n1",
                    owner_email="me@example.com", now=NOW)


class _FakeGoogle(BaseHTTPRequestHandler):
    server_version = "FakeGoogle"
    def log_message(self, *a: object) -> None: pass
    def do_POST(self) -> None:
        body = self.rfile.read(int(self.headers["Content-Length"])).decode()
        self.server.seen.append((self.path, parse_qs(body), self.headers["Content-Type"]))
        status, payload = self.server.reply
        raw = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


class GoogleOAuthTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _FakeGoogle)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self) -> None:
        self.server.seen = []
        self.server.reply = (200, {})
        self.google = GoogleOAuth(CID, "client-secret-XYZ", token_url=self.base + "/token",
                                  revoke_url=self.base + "/revoke", timeout=5)

    def test_exchange_sends_the_right_form_and_parses_tokens(self) -> None:
        self.server.reply = (200, {"access_token": "at", "refresh_token": "rt",
                                   "id_token": "idt", "scope": "s1 s2", "expires_in": 3599})
        tokens = self.google.exchange_code("code-1", "verif", "https://k.example/auth/callback")
        path, form, ctype = self.server.seen[0]
        self.assertEqual(path, "/token")
        self.assertIn("application/x-www-form-urlencoded", ctype)
        self.assertEqual({k: v[0] for k, v in form.items()}, {
            "grant_type": "authorization_code", "code": "code-1", "code_verifier": "verif",
            "client_id": CID, "client_secret": "client-secret-XYZ",
            "redirect_uri": "https://k.example/auth/callback"})
        self.assertEqual((tokens.access_token, tokens.refresh_token, tokens.id_token,
                          tokens.scope), ("at", "rt", "idt", "s1 s2"))

    def test_refresh_token_is_optional_in_the_response(self) -> None:
        self.server.reply = (200, {"access_token": "at", "id_token": "idt", "scope": "s"})
        self.assertIsNone(self.google.exchange_code("c", "v", "r").refresh_token)

    def test_rejected_code_raises_without_leaking_secrets(self) -> None:
        self.server.reply = (400, {"error": "invalid_grant", "error_description": "Bad code"})
        with self.assertRaises(GoogleError) as ctx:
            self.google.exchange_code("code-LEAK", "verif-LEAK", "r")
        text = str(ctx.exception)
        for secret in ("code-LEAK", "verif-LEAK", "client-secret-XYZ"):
            self.assertNotIn(secret, text)

    def test_malformed_or_incomplete_responses_raise(self) -> None:
        for reply in ((200, b"<html>nope</html>"), (200, {"access_token": "at"}),
                      (200, [1, 2]), (500, b"")):
            self.server.reply = reply
            with self.subTest(reply=reply), self.assertRaises(GoogleError):
                self.google.exchange_code("c", "v", "r")

    def test_unreachable_google_raises(self) -> None:
        dead = GoogleOAuth(CID, "s", token_url="http://127.0.0.1:1/token", timeout=2)
        with self.assertRaises(GoogleError):
            dead.exchange_code("c", "v", "r")

    def test_revoke_posts_the_token_and_reports_success(self) -> None:
        self.assertTrue(self.google.revoke("rt-1"))
        path, form, _ = self.server.seen[0]
        self.assertEqual((path, form["token"]), ("/revoke", ["rt-1"]))

    def test_revoke_failure_is_reported_not_raised(self) -> None:
        self.server.reply = (400, {"error": "invalid_token"})
        self.assertFalse(self.google.revoke("rt-1"))
        dead = GoogleOAuth(CID, "s", revoke_url="http://127.0.0.1:1/revoke", timeout=2)
        self.assertFalse(dead.revoke("rt-1"))

    def test_plain_http_to_a_remote_host_is_refused(self) -> None:
        with self.assertRaises(ValueError):
            GoogleOAuth(CID, "s", token_url="http://oauth.example.com/token")


class RefreshTests(GoogleOAuthTests):
    """Refreshing an access token (reuses the local fake Google)."""

    def test_refresh_sends_the_right_form_and_parses(self) -> None:
        self.server.reply = (200, {"access_token": "at-9", "expires_in": 3599})
        token = self.google.refresh_access_token("refresh-1")
        _, form, _ = self.server.seen[0]
        self.assertEqual({k: v[0] for k, v in form.items()}, {
            "grant_type": "refresh_token", "refresh_token": "refresh-1",
            "client_id": CID, "client_secret": "client-secret-XYZ"})
        self.assertEqual((token.token, token.expires_in), ("at-9", 3599))

    def test_missing_expiry_gets_a_short_safe_default(self) -> None:
        self.server.reply = (200, {"access_token": "at-9"})
        self.assertEqual(self.google.refresh_access_token("r").expires_in, 300)

    def test_invalid_grant_is_exposed_as_a_code_without_secrets(self) -> None:
        self.server.reply = (400, {"error": "invalid_grant"})
        with self.assertRaises(GoogleError) as ctx:
            self.google.refresh_access_token("refresh-LEAK")
        self.assertEqual(ctx.exception.code, "invalid_grant")
        for secret in ("refresh-LEAK", "client-secret-XYZ"):
            self.assertNotIn(secret, str(ctx.exception))

    def test_bad_replies_raise(self) -> None:
        for reply in ((200, {}), (200, [1]), (200, b"nope"), (500, b"")):
            self.server.reply = reply
            with self.subTest(reply=reply), self.assertRaises(GoogleError):
                self.google.refresh_access_token("r")

    def test_access_token_repr_hides_the_token(self) -> None:
        self.assertNotIn("secret-token", repr(AccessToken("secret-token", 10)))


if __name__ == "__main__":
    unittest.main()

"""Task 7 tests: the Gmail source, against a local stand-in for Google."""

import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from kyte.credentials import CredentialStore
from kyte.gmail import (
    GmailSource, MailError, MailUnavailable, NotConnected, ReconnectRequired,
)
from kyte.oauth import GoogleOAuth
from kyte.security import TokenVault

SECRET = "k" * 40
API = "/gmail/v1/users/me/messages"


def message(id_: str, subject: str = "Hello", sender: str = "Ada <ada@example.com>",
            snippet: str = "snippet text") -> dict:
    return {
        "id": id_, "threadId": f"t-{id_}",
        "labelIds": ["INBOX", "UNREAD"],  # deliberately stale: the source must not trust it
        "snippet": snippet, "internalDate": "1800000000000",
        "payload": {"headers": [{"name": "From", "value": sender},
                                {"name": "Subject", "value": subject}]},
    }


class FakeGoogle(BaseHTTPRequestHandler):
    def log_message(self, *a: object) -> None: pass

    def _reply(self, status: int, body: object, headers: dict | None = None) -> None:
        raw = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(raw)

    def do_POST(self) -> None:
        s = self.server
        form = {k: v[0] for k, v in parse_qs(
            self.rfile.read(int(self.headers["Content-Length"])).decode()).items()}
        with s.lock:
            s.token_calls.append(form)
            if s.token_script:
                status, body = s.token_script.pop(0)
            else:
                token = f"at-{len(s.token_calls)}"
                s.valid_tokens.add(token)
                status, body = 200, {"access_token": token, "expires_in": 3600}
        self._reply(status, body)

    def do_GET(self) -> None:
        s = self.server
        url = urlparse(self.path)
        q = parse_qs(url.query)
        with s.lock:
            s.requests.append((url.path, q, self.headers.get("Authorization")))
            auth = (self.headers.get("Authorization") or "").removeprefix("Bearer ")
            if auth not in s.valid_tokens:
                return self._reply(401, {"error": {"code": 401, "status": "UNAUTHENTICATED"}})
            for i, (prefix, status, body, headers) in enumerate(s.faults):
                if url.path.startswith(prefix) and (prefix != API or True):
                    s.faults.pop(i)
                    return self._reply(status, body, headers)
            if url.path == API:
                ids = [i for i in s.order if "UNREAD" not in q.get("labelIds", []) or i in s.unread]
                start = int(q.get("pageToken", ["0"])[0])
                size = 1000 if s.ignore_max else int(q.get("maxResults", ["100"])[0])
                page = ids[start:start + size]
                body: dict = {"resultSizeEstimate": len(ids)}
                if page:
                    body["messages"] = [{"id": i, "threadId": f"t-{i}"} for i in page]
                if start + size < len(ids):
                    body["nextPageToken"] = str(start + size)
                return self._reply(200, body)
            msg_id = url.path.removeprefix(API + "/")
            if msg_id in s.messages:
                return self._reply(200, s.messages[msg_id])
            return self._reply(404, {"error": {"code": 404}})


class GmailSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), FakeGoogle)
        cls.server.lock = threading.Lock()
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self) -> None:
        s = self.server
        s.messages, s.order, s.unread = {}, [], set()
        s.token_calls, s.token_script, s.valid_tokens = [], [], set()
        s.requests, s.faults, s.ignore_max = [], [], False
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.creds = CredentialStore(Path(tmp.name) / "k.db", TokenVault(SECRET))
        self.creds.save("refresh-1", email="me@example.com", scope="s")
        self.now = [1000.0]
        self.sleeps: list[float] = []
        self.google = GoogleOAuth("cid", "csecret", token_url=self.base + "/token",
                                  revoke_url=self.base + "/revoke", timeout=5)
        self.make_source()

    def make_source(self, **kw: object) -> None:
        opts = dict(api_base=self.base + "/gmail/v1", clock=lambda: self.now[0],
                    sleep=self.sleeps.append, rng=lambda: 1.0, page_size=50,
                    max_messages=60, timeout=5)
        opts.update(kw)
        self.source = GmailSource(self.creds, self.google, **opts)  # type: ignore[arg-type]

    def add(self, *ids: str, unread: tuple[str, ...] = ()) -> None:
        for i in ids:
            self.server.messages[i] = message(i)
            self.server.order.append(i)
        self.server.unread.update(unread)

    def get_requests(self) -> list:
        return [r for r in self.server.requests if r[0].startswith(API + "/")]

    # --- connection state ---
    def test_not_connected_makes_no_requests(self) -> None:
        self.creds.clear()
        with self.assertRaises(NotConnected):
            self.source.fetch_recent()
        self.assertEqual(self.server.requests + self.server.token_calls, [])

    def test_unreadable_stored_token_is_a_reconnect(self) -> None:
        other = CredentialStore(self.creds._path, TokenVault("z" * 40))
        self.make_source()
        self.source._creds = other  # type: ignore[attr-defined]
        with self.assertRaises(ReconnectRequired):
            self.source.fetch_recent()

    # --- what is requested ---
    def test_returns_parsed_emails_in_gmail_order(self) -> None:
        self.add("a", "b", "c")
        self.server.messages["b"] = message("b", "Lunch?", "Ana <ana@example.org>", "At noon")
        emails = self.source.fetch_recent()
        self.assertEqual([e.id for e in emails], ["a", "b", "c"])
        b = emails[1]
        self.assertEqual((b.sender_label, b.subject, b.snippet), ("Ana", "Lunch?", "At noon"))

    def test_only_metadata_is_ever_requested(self) -> None:
        self.add("a", "b")
        self.source.fetch_recent()
        gets = self.get_requests()
        self.assertEqual(len(gets), 2)
        for path, q, auth in gets:
            self.assertEqual(q["format"], ["metadata"])
            self.assertEqual(sorted(q["metadataHeaders"]), ["Date", "From", "Subject"])
            self.assertTrue(auth.startswith("Bearer at-"))

    def test_lists_the_inbox_over_a_recent_window(self) -> None:
        self.add("a")
        self.source.fetch_recent()
        lists = [r for r in self.server.requests if r[0] == API]
        self.assertTrue(lists)
        for _, q, _ in lists:
            self.assertIn("INBOX", q["labelIds"])
            self.assertRegex(q["q"][0], r"newer_than:\d+d")

    # --- read/unread state ---
    def test_unread_comes_from_labels_not_the_cached_message(self) -> None:
        self.add("a", "b", unread=("b",))
        by_id = {e.id: e for e in self.source.fetch_recent()}
        self.assertFalse(by_id["a"].unread)
        self.assertTrue(by_id["b"].unread)

    def test_read_state_updates_without_refetching_the_message(self) -> None:
        self.add("a", "b", unread=("a", "b"))
        self.source.fetch_recent()
        self.server.unread.discard("a")  # user read it in Gmail
        by_id = {e.id: e for e in self.source.fetch_recent()}
        self.assertFalse(by_id["a"].unread)
        self.assertTrue(by_id["b"].unread)
        self.assertEqual(len(self.get_requests()), 2)  # still just the first two

    def test_only_new_messages_are_fetched_on_refresh(self) -> None:
        self.add("a", "b")
        self.source.fetch_recent()
        self.server.order.insert(0, "c")
        self.server.messages["c"] = message("c")
        emails = self.source.fetch_recent()
        self.assertEqual([e.id for e in emails], ["c", "a", "b"])
        self.assertEqual(sorted(p for p, *_ in self.get_requests()),
                         sorted(f"{API}/{i}" for i in "abc"))

    # --- paging ---
    def test_follows_pages_up_to_the_cap(self) -> None:
        ids = [f"m{n:03d}" for n in range(120)]
        self.add(*ids)
        self.make_source(page_size=50, max_messages=75)
        emails = self.source.fetch_recent()
        self.assertEqual([e.id for e in emails], ids[:75])
        sizes = [q["maxResults"] for p, q, _ in self.server.requests
                 if p == API and "UNREAD" not in q["labelIds"]]
        self.assertEqual(sizes, [["50"], ["25"]])

    def test_cap_holds_even_if_the_server_ignores_maxresults(self) -> None:
        ids = [f"m{n:03d}" for n in range(120)]
        self.add(*ids)
        self.server.ignore_max = True
        self.make_source(max_messages=75)
        self.assertEqual([e.id for e in self.source.fetch_recent()], ids[:75])

    def test_empty_inbox(self) -> None:
        self.assertEqual(self.source.fetch_recent(), [])

    # --- access tokens ---
    def test_access_token_is_reused_until_near_expiry(self) -> None:
        self.add("a")
        self.source.fetch_recent()
        self.source.fetch_recent()
        self.assertEqual(len(self.server.token_calls), 1)
        self.assertEqual(self.server.token_calls[0]["grant_type"], "refresh_token")
        self.assertEqual(self.server.token_calls[0]["refresh_token"], "refresh-1")
        self.now[0] += 3600 - 30  # inside the 60 s safety margin
        self.source.fetch_recent()
        self.assertEqual(len(self.server.token_calls), 2)

    def test_a_rejected_token_is_refreshed_once_and_retried(self) -> None:
        self.add("a")
        self.source.fetch_recent()
        self.server.valid_tokens.clear()  # Google invalidated it early
        self.assertEqual([e.id for e in self.source.fetch_recent()], ["a"])
        self.assertEqual(len(self.server.token_calls), 2)

    def test_persistent_401_means_reconnect(self) -> None:
        self.add("a")
        self.server.token_script = [(200, {"access_token": "never-valid", "expires_in": 3600})] * 2
        with self.assertRaises(ReconnectRequired):
            self.source.fetch_recent()

    def test_revoked_or_expired_grant_means_reconnect(self) -> None:
        self.server.token_script = [(400, {"error": "invalid_grant"})]
        with self.assertRaises(ReconnectRequired) as ctx:
            self.source.fetch_recent()
        self.assertNotIn("refresh-1", str(ctx.exception))
        self.assertTrue(self.creds.is_connected())  # we do not delete on a guess

    def test_token_endpoint_trouble_is_unavailable_not_reconnect(self) -> None:
        self.server.token_script = [(500, b"")]
        with self.assertRaises(MailUnavailable):
            self.source.fetch_recent()

    # --- rate limits and transient failures ---
    def test_429_is_retried_with_exponential_backoff(self) -> None:
        self.add("a")
        self.server.faults = [(API, 429, {"error": {}}, {})] * 2
        self.assertEqual([e.id for e in self.source.fetch_recent()], ["a"])
        self.assertEqual(self.sleeps, [1.0, 2.0])

    def test_retry_after_is_honoured_and_capped(self) -> None:
        self.add("a")
        self.server.faults = [(API, 429, {}, {"Retry-After": "7"})]
        self.source.fetch_recent()
        self.assertEqual(self.sleeps, [7.0])
        self.sleeps.clear()
        self.server.faults = [(API, 429, {}, {"Retry-After": "9999"})]
        self.source.fetch_recent()
        self.assertEqual(self.sleeps, [30.0])

    def test_gives_up_after_the_retry_budget(self) -> None:
        self.add("a")
        self.server.faults = [(API, 503, {}, {})] * 10
        with self.assertRaises(MailUnavailable):
            self.source.fetch_recent()
        self.assertEqual(len(self.sleeps), 3)

    def test_403_rate_limit_reasons_are_retried(self) -> None:
        self.add("a")
        body = {"error": {"errors": [{"reason": "userRateLimitExceeded"}]}}
        self.server.faults = [(API, 403, body, {})]
        self.assertEqual(len(self.source.fetch_recent()), 1)
        self.assertEqual(len(self.sleeps), 1)

    def test_403_insufficient_permissions_means_reconnect(self) -> None:
        body = {"error": {"errors": [{"reason": "insufficientPermissions"}]}}
        self.server.faults = [(API, 403, body, {})]
        with self.assertRaises(ReconnectRequired):
            self.source.fetch_recent()

    def test_other_403_is_not_retried(self) -> None:
        self.server.faults = [(API, 403, {"error": {"errors": [{"reason": "forbidden"}]}}, {})]
        with self.assertRaises(MailUnavailable):
            self.source.fetch_recent()
        self.assertEqual(self.sleeps, [])

    def test_unreachable_server_is_unavailable(self) -> None:
        self.make_source(api_base="http://127.0.0.1:1/gmail/v1", timeout=2)
        with self.assertRaises(MailUnavailable):
            self.source.fetch_recent()
        self.assertEqual(len(self.sleeps), 3)  # retried before giving up

    def test_non_json_reply_is_unavailable(self) -> None:
        self.server.faults = [(API, 200, b"<html>captive portal</html>", {})]
        with self.assertRaises(MailUnavailable):
            self.source.fetch_recent()

    # --- bad individual messages ---
    def test_a_message_deleted_after_listing_is_skipped(self) -> None:
        self.add("a", "gone", "c")
        del self.server.messages["gone"]
        self.assertEqual([e.id for e in self.source.fetch_recent()], ["a", "c"])

    def test_a_malformed_message_is_skipped_not_fatal(self) -> None:
        self.add("a", "bad", "c")
        self.server.messages["bad"] = {"threadId": "x"}  # no id
        self.assertEqual([e.id for e in self.source.fetch_recent()], ["a", "c"])

    def test_a_reply_for_a_different_message_is_ignored_and_not_cached(self) -> None:
        self.add("a", "b")
        self.server.messages["b"] = message("zzz", subject="Impostor")
        self.assertEqual([e.id for e in self.source.fetch_recent()], ["a"])
        # When zzz really shows up later, it must be fetched fresh, not the impostor.
        self.server.messages["zzz"] = message("zzz", subject="Real")
        self.server.order.append("zzz")
        by_id = {e.id: e for e in self.source.fetch_recent()}
        self.assertEqual(by_id["zzz"].subject, "Real")

    def test_suspicious_ids_from_the_server_are_ignored(self) -> None:
        self.add("a", "../../etc", "c")
        emails = self.source.fetch_recent()
        self.assertEqual([e.id for e in emails], ["a", "c"])

    def test_all_errors_share_a_base_class_with_a_stable_code(self) -> None:
        for cls, code in ((NotConnected, "not_connected"),
                          (ReconnectRequired, "reconnect_required"),
                          (MailUnavailable, "mail_unavailable")):
            self.assertTrue(issubclass(cls, MailError))
            self.assertEqual(cls().code, code)


if __name__ == "__main__":
    unittest.main()

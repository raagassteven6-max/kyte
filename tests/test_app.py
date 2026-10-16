"""Task 1 tests: app factory and /health (needs fastapi + httpx)."""

import tempfile
import unittest
from pathlib import Path

from kyte.config import Settings

try:
    from fastapi.testclient import TestClient

    from kyte.app import create_app

    HAVE_WEB = True
except ImportError:  # dependencies not installed in this environment
    HAVE_WEB = False

ENV = {
    "KYTE_SECRET_KEY": "s" * 32,
    "KYTE_OWNER_EMAIL": "me@example.com",
    "KYTE_MOCK": "1",
}


@unittest.skipUnless(HAVE_WEB, "fastapi/httpx not installed")
class AppTests(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        env = {**ENV, "KYTE_DB_PATH": str(Path(tmp.name) / "kyte.db")}
        self.client = TestClient(create_app(Settings.from_env(env)))

    def test_health_ok(self) -> None:
        r = self.client.get("/health")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json(), {"status": "ok"})

    def test_health_leaks_nothing(self) -> None:
        self.assertNotIn("s" * 32, self.client.get("/health").text)

    def test_index_serves_the_dashboard(self) -> None:
        r = self.client.get("/")
        self.assertEqual(r.status_code, 200)
        self.assertIn("text/html", r.headers["content-type"])
        self.assertIn("<title>Kyte", r.text)

    def test_static_assets_are_served(self) -> None:
        for name in ("kyte.css", "kyte.js", "format.js"):
            self.assertEqual(self.client.get(f"/static/{name}").status_code, 200)

    def test_security_headers_present(self) -> None:
        h = self.client.get("/").headers
        self.assertIn("script-src 'self'", h["content-security-policy"])
        self.assertEqual(h["x-content-type-options"], "nosniff")
        self.assertIn("frame-ancestors 'none'", h["content-security-policy"])

    def test_api_responses_are_not_cacheable(self) -> None:
        r = self.client.get("/api/emails")
        self.assertEqual(r.headers["cache-control"], "no-store")

    def test_api_docs_are_not_exposed(self) -> None:
        for path in ("/docs", "/redoc", "/openapi.json"):
            self.assertEqual(self.client.get(path).status_code, 404, path)


if __name__ == "__main__":
    unittest.main()

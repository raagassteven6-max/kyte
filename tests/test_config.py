"""Task 1 tests: environment configuration."""

import unittest
from pathlib import Path

from kyte.config import ConfigError, Settings

SECRET = "s" * 32
BASE = {
    "KYTE_SECRET_KEY": SECRET,
    "KYTE_OWNER_EMAIL": "Me@Example.com",
    "KYTE_MOCK": "1",
}
GOOGLE = {
    "GOOGLE_CLIENT_ID": "client-id",
    "GOOGLE_CLIENT_SECRET": "client-secret-value",
}


class SettingsTests(unittest.TestCase):
    def test_mock_mode_needs_no_google_credentials(self) -> None:
        s = Settings.from_env(BASE)
        self.assertTrue(s.mock_mode)
        self.assertIsNone(s.google_client_id)
        self.assertIsNone(s.google_client_secret)

    def test_defaults_and_normalisation(self) -> None:
        s = Settings.from_env(BASE)
        self.assertEqual(s.owner_email, "me@example.com")
        self.assertEqual(s.base_url, "http://localhost:8000")
        self.assertEqual(s.db_path, Path("kyte.db"))

    def test_overrides(self) -> None:
        env = {**BASE, "KYTE_BASE_URL": "https://kyte.example.com/",
               "KYTE_DB_PATH": "/data/kyte.db"}
        s = Settings.from_env(env)
        self.assertEqual(s.base_url, "https://kyte.example.com")
        self.assertEqual(s.db_path, Path("/data/kyte.db"))

    def test_missing_required_names_every_missing_variable(self) -> None:
        with self.assertRaises(ConfigError) as ctx:
            Settings.from_env({"KYTE_MOCK": "1"})
        msg = str(ctx.exception)
        self.assertIn("KYTE_SECRET_KEY", msg)
        self.assertIn("KYTE_OWNER_EMAIL", msg)

    def test_real_mode_requires_google_credentials(self) -> None:
        env = {**BASE, "KYTE_MOCK": "0"}
        with self.assertRaises(ConfigError) as ctx:
            Settings.from_env(env)
        msg = str(ctx.exception)
        self.assertIn("GOOGLE_CLIENT_ID", msg)
        self.assertIn("GOOGLE_CLIENT_SECRET", msg)

    def test_real_mode_with_credentials(self) -> None:
        s = Settings.from_env({**BASE, "KYTE_MOCK": "0", **GOOGLE})
        self.assertFalse(s.mock_mode)
        self.assertEqual(s.google_client_id, "client-id")

    def test_short_secret_rejected_without_echoing_it(self) -> None:
        with self.assertRaises(ConfigError) as ctx:
            Settings.from_env({**BASE, "KYTE_SECRET_KEY": "tooshort"})
        self.assertIn("KYTE_SECRET_KEY", str(ctx.exception))
        self.assertNotIn("tooshort", str(ctx.exception))

    def test_unrecognised_boolean_is_an_error_not_false(self) -> None:
        with self.assertRaises(ConfigError) as ctx:
            Settings.from_env({**BASE, "KYTE_MOCK": "ture"})
        self.assertIn("KYTE_MOCK", str(ctx.exception))

    def test_bad_base_url_scheme(self) -> None:
        with self.assertRaises(ConfigError):
            Settings.from_env({**BASE, "KYTE_BASE_URL": "ftp://example.com"})

    def test_owner_email_must_look_like_an_address(self) -> None:
        with self.assertRaises(ConfigError):
            Settings.from_env({**BASE, "KYTE_OWNER_EMAIL": "not-an-email"})

    def test_repr_does_not_leak_secrets(self) -> None:
        s = Settings.from_env({**BASE, "KYTE_MOCK": "0", **GOOGLE})
        text = repr(s)
        self.assertNotIn(SECRET, text)
        self.assertNotIn("client-secret-value", text)


class TimezoneTests(unittest.TestCase):
    def test_default_is_utc(self) -> None:
        self.assertEqual(str(Settings.from_env(BASE).timezone), "UTC")

    def test_valid_timezone(self) -> None:
        env = {**BASE, "KYTE_TIMEZONE": "America/New_York"}
        self.assertEqual(str(Settings.from_env(env).timezone), "America/New_York")

    def test_invalid_timezone_is_an_error(self) -> None:
        with self.assertRaises(ConfigError) as ctx:
            Settings.from_env({**BASE, "KYTE_TIMEZONE": "Mars/Olympus"})
        self.assertIn("KYTE_TIMEZONE", str(ctx.exception))

if __name__ == "__main__":
    unittest.main()

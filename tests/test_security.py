"""Task 6 tests: key derivation, token vault, signed cookies."""

import unittest

from kyte.security import CookieSigner, TokenVault, VaultError, derive_key

SECRET = "k" * 40
OTHER = "z" * 40


class DeriveKeyTests(unittest.TestCase):
    def test_deterministic_and_32_bytes(self) -> None:
        key = derive_key(SECRET, "vault")
        self.assertEqual(key, derive_key(SECRET, "vault"))
        self.assertEqual(len(key), 32)

    def test_purposes_and_secrets_are_separated(self) -> None:
        self.assertNotEqual(derive_key(SECRET, "vault"), derive_key(SECRET, "cookie"))
        self.assertNotEqual(derive_key(SECRET, "vault"), derive_key(OTHER, "vault"))


class TokenVaultTests(unittest.TestCase):
    def test_round_trip(self) -> None:
        vault = TokenVault(SECRET)
        self.assertEqual(vault.decrypt(vault.encrypt("rt-123/abc")), "rt-123/abc")

    def test_ciphertext_hides_plaintext_and_is_randomised(self) -> None:
        vault = TokenVault(SECRET)
        a, b = vault.encrypt("super-secret-token"), vault.encrypt("super-secret-token")
        self.assertNotIn(b"super-secret-token", a)
        self.assertNotEqual(a, b)

    def test_wrong_key_tampering_and_garbage_fail(self) -> None:
        blob = TokenVault(SECRET).encrypt("t")
        with self.assertRaises(VaultError):
            TokenVault(OTHER).decrypt(blob)
        with self.assertRaises(VaultError):
            TokenVault(SECRET).decrypt(blob[:-2] + b"xx")
        with self.assertRaises(VaultError):
            TokenVault(SECRET).decrypt(b"not a token")


class CookieSignerTests(unittest.TestCase):
    def test_round_trip(self) -> None:
        s = CookieSigner(SECRET, "session", 60)
        self.assertEqual(s.loads(s.dumps({"email": "me@example.com"})),
                         {"email": "me@example.com"})

    def test_tampered_wrong_secret_and_wrong_purpose_rejected(self) -> None:
        s = CookieSigner(SECRET, "session", 60)
        value = s.dumps({"email": "me@example.com"})
        self.assertIsNone(s.loads(value[:-2] + "xx"))
        self.assertIsNone(CookieSigner(OTHER, "session", 60).loads(value))
        # A cookie minted for one purpose must not work for another.
        self.assertIsNone(CookieSigner(SECRET, "oauth-flow", 60).loads(value))

    def test_expired_rejected(self) -> None:
        s = CookieSigner(SECRET, "session", -1)
        self.assertIsNone(s.loads(s.dumps({"a": 1})))

    def test_missing_or_garbage_gives_none(self) -> None:
        s = CookieSigner(SECRET, "session", 60)
        for value in (None, "", "garbage", "a.b.c"):
            self.assertIsNone(s.loads(value))


if __name__ == "__main__":
    unittest.main()

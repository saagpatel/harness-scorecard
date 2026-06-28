"""Redaction correctness (review findings F5, F6) plus the core redaction guarantees."""

import unittest

from harness_scorecard import redaction
from harness_scorecard.redaction import redact_path, redact_text


class TestRedactPath(unittest.TestCase):
    def setUp(self):
        self._orig_home = redaction._HOME
        redaction._HOME = "/Users/d"

    def tearDown(self):
        redaction._HOME = self._orig_home

    def test_home_collapses_to_tilde(self):
        self.assertEqual(redact_path("/Users/d/.claude"), "~/.claude")

    def test_exact_home_collapses(self):
        self.assertEqual(redact_path("/Users/d"), "~")

    def test_sibling_user_with_shared_prefix_is_untouched(self):
        # F6: /Users/doppelganger starts with /Users/d but must NOT become ~oppelganger.
        self.assertEqual(redact_path("/Users/doppelganger/.claude"), "/Users/doppelganger/.claude")


class TestRedactText(unittest.TestCase):
    def test_emails_are_redacted(self):
        self.assertEqual(redact_text("ping me@example.com ok"), "ping [redacted-email] ok")

    def test_prefixed_secret_redacted(self):
        self.assertIn("[redacted-secret]", redact_text("token sk-abcdef0123456789"))

    def test_token_with_digits_redacted(self):
        # A non-prefixed 24+ char run containing digits is treated as an opaque token.
        self.assertIn("[redacted-token]", redact_text("zzqlapqraz1234abcd5678efgh90"))

    def test_long_path_component_without_digits_is_preserved(self):
        # F5: a long but digit-free identifier (e.g. a harness dir name) is not a secret.
        text = "my-organization-harness-config"
        self.assertEqual(redact_text(text), text)


class TestRedactTextHomePaths(unittest.TestCase):
    def setUp(self):
        self._orig_home = redaction._HOME
        redaction._HOME = "/Users/d"

    def tearDown(self):
        redaction._HOME = self._orig_home

    def test_embedded_home_path_is_collapsed(self):
        # A home path mid-sentence (not the whole string) must still be scrubbed.
        out = redact_text("config lives under /Users/d/.claude/settings.json today")
        self.assertEqual(out, "config lives under ~/.claude/settings.json today")

    def test_embedded_sibling_user_is_preserved(self):
        out = redact_text("see /Users/doppelganger/.claude for the other config")
        self.assertEqual(out, "see /Users/doppelganger/.claude for the other config")


if __name__ == "__main__":
    unittest.main()

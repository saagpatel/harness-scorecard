"""Unknown configuration values cannot supply protective layers."""

import unittest

from harness_scorecard.models import Status
from harness_scorecard.parsing import HookEntry
from tests.test_checks_codex import get_check, make_codex_config


class TestUnknownModes(unittest.TestCase):
    def test_both_unknown_are_unknown(self):
        config = make_codex_config(approval_policy="mystery", sandbox_mode="mystery")
        for cid in ("CDX-D4-01", "CDX-D5-01"):
            with self.subTest(cid=cid):
                result = get_check(cid).run(config)
                self.assertEqual(result.status, Status.UNKNOWN)
                self.assertIn("mystery", result.message)

    def test_one_known_layer(self):
        for approval, sandbox, d5 in (
            ("untrusted", "mystery", Status.UNKNOWN),
            ("mystery", "read-only", Status.PASS),
        ):
            config = make_codex_config(approval_policy=approval, sandbox_mode=sandbox)
            self.assertEqual(get_check("CDX-D4-01").run(config).status, Status.UNKNOWN)
            self.assertEqual(get_check("CDX-D5-01").run(config).status, d5)

    def test_known_bypass_still_fails(self):
        config = make_codex_config(approval_policy="never", sandbox_mode="danger-full-access")
        for cid in ("CDX-D4-01", "CDX-D5-01"):
            self.assertEqual(get_check(cid).run(config).status, Status.FAIL)

    def test_unknown_does_not_override_sufficient_hooks_or_known_exposure(self):
        config = make_codex_config(
            approval_policy="mystery",
            sandbox_mode="read-only",
            hooks=[HookEntry("PreToolUse", "Bash", "git-safety self-protect")],
        )
        for cid in ("CDX-D4-01", "CDX-D5-01"):
            self.assertEqual(get_check(cid).run(config).status, Status.PASS)
        config = make_codex_config(sandbox_mode="mystery", writable_roots=["/"])
        self.assertEqual(get_check("CDX-D5-01").run(config).status, Status.FAIL)

    def test_recognition_helpers(self):
        for value in ("untrusted", "on-failure", "on-request", "never", "granular"):
            self.assertTrue(make_codex_config(approval_policy=value).approval_recognized)
        for value in ("read-only", "workspace-write", "danger-full-access"):
            self.assertTrue(make_codex_config(sandbox_mode=value).sandbox_recognized)
        config = make_codex_config(approval_policy="mystery", sandbox_mode="mystery")
        self.assertFalse(config.approval_recognized)
        self.assertFalse(config.sandbox_recognized)

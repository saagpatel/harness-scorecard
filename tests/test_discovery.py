"""Discovery parses a harness directory into a queryable HarnessConfig."""

import unittest
from pathlib import Path

from harness_scorecard.discovery import load_harness

FIXTURES = Path(__file__).parent / "fixtures"


class TestStrongHarness(unittest.TestCase):
    def setUp(self):
        self.config = load_harness(FIXTURES / "strong_harness")

    def test_detects_claude_code_type(self):
        self.assertEqual(self.config.harness_type, "claude-code")

    def test_reads_default_mode(self):
        self.assertEqual(self.config.default_mode, "acceptEdits")

    def test_not_bypass_so_hard_deny_is_effective(self):
        self.assertFalse(self.config.is_bypass)
        self.assertTrue(self.config.hard_deny_effective)

    def test_parses_deny_globs(self):
        self.assertTrue(self.config.deny_matches("Read(~/.ssh"))
        self.assertTrue(self.config.deny_matches("ListMcpResourcesTool"))

    def test_finds_registered_hook_with_matcher(self):
        self.assertTrue(self.config.has_hook("PreToolUse", "git-safety", matcher="Bash"))
        self.assertTrue(self.config.has_hook("PreToolUse", "detect-secrets", matcher="Write"))
        self.assertTrue(self.config.has_hook("TaskCompleted", "task-completed-verify"))

    def test_missing_hook_returns_false(self):
        self.assertFalse(self.config.has_hook("PreToolUse", "no-such-guard"))

    def test_reads_env_flags(self):
        self.assertTrue(self.config.env_flag_enabled("DISABLE_TELEMETRY"))
        self.assertTrue(self.config.env_flag_enabled("DISABLE_ERROR_REPORTING"))
        self.assertFalse(self.config.env_flag_enabled("NOT_SET"))

    def test_inventories_surfaces(self):
        self.assertIn("sandboxing.md", self.config.rule_files)
        self.assertIn("code-reviewer.md", self.config.agent_files)
        self.assertIn("verify", self.config.skill_dirs)
        self.assertTrue(self.config.has_claude_md)


class TestWeakHarness(unittest.TestCase):
    def setUp(self):
        self.config = load_harness(FIXTURES / "weak_harness")

    def test_bypass_makes_hard_deny_inert(self):
        self.assertTrue(self.config.is_bypass)
        self.assertFalse(self.config.hard_deny_effective)

    def test_empty_deny_and_no_hooks(self):
        self.assertEqual(self.config.deny, [])
        self.assertFalse(self.config.has_hook("PreToolUse", "git-safety"))

    def test_hard_deny_text_is_present_but_inert(self):
        # The block exists (a naive scorer would credit it)...
        self.assertTrue(any("main" in rule for rule in self.config.hard_deny))
        # ...but it is inert under bypass mode.
        self.assertFalse(self.config.hard_deny_effective)


class TestMissingHarness(unittest.TestCase):
    def test_raises_on_missing_settings(self):
        with self.assertRaises(FileNotFoundError):
            load_harness(FIXTURES / "does_not_exist")


if __name__ == "__main__":
    unittest.main()

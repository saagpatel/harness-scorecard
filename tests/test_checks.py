"""D1 and D4 checks behave correctly, including the bypass-aware effective floor."""

import unittest
from pathlib import Path

from harness_scorecard.checks import ALL_CHECKS
from harness_scorecard.discovery import HarnessConfig, HookEntry, load_harness
from harness_scorecard.models import Status

FIXTURES = Path(__file__).parent / "fixtures"


def get_check(check_id: str):
    return next(check for check in ALL_CHECKS if check.id == check_id)


def make_config(**overrides) -> HarnessConfig:
    base = {
        "root": Path("/tmp/harness"),
        "harness_type": "claude-code",
        "default_mode": "default",
        "deny": [],
        "allow": [],
        "env": {},
        "hard_deny": [],
        "hooks": [],
        "rule_files": [],
        "agent_files": [],
        "skill_dirs": [],
        "has_claude_md": False,
        "raw_settings": {},
    }
    base.update(overrides)
    return HarnessConfig(**base)


class TestD1OnFixtures(unittest.TestCase):
    def test_strong_harness_passes_secret_paths_gate(self):
        config = load_harness(FIXTURES / "strong_harness")
        result = get_check("HS-D1-01").run(config)
        self.assertEqual(result.status, Status.PASS)
        self.assertIsNone(result.triggered_gate_cap)

    def test_weak_harness_fails_secret_paths_gate(self):
        config = load_harness(FIXTURES / "weak_harness")
        result = get_check("HS-D1-01").run(config)
        self.assertEqual(result.status, Status.FAIL)
        # The gate must trip and demand a cap at D.
        self.assertEqual(result.triggered_gate_cap.value, "D")

    def test_partial_credit_when_some_paths_covered(self):
        config = make_config(deny=["Read(~/.ssh/**)"])
        result = get_check("HS-D1-01").run(config)
        self.assertEqual(result.status, Status.PARTIAL)
        self.assertIsNone(result.triggered_gate_cap)


class TestD4BypassAwareness(unittest.TestCase):
    """The heart of the moat: hard_deny is only credited when it is effective."""

    def test_hard_deny_only_under_bypass_fails(self):
        config = make_config(
            default_mode="bypassPermissions",
            hard_deny=["Push to main or master"],
        )
        result = get_check("HS-D4-01").run(config)
        self.assertEqual(result.status, Status.FAIL)
        self.assertEqual(result.triggered_gate_cap.value, "C")

    def test_hard_deny_only_when_effective_passes(self):
        # Same rule, but NOT bypass -> hard_deny actually enforces.
        config = make_config(
            default_mode="acceptEdits",
            hard_deny=["Push to main or master"],
        )
        result = get_check("HS-D4-01").run(config)
        self.assertEqual(result.status, Status.PASS)
        self.assertIn("hard_deny", result.evidence)

    def test_real_hook_credited_even_under_bypass(self):
        # Bypass mode, but a real PreToolUse hook realizes the guard -> PASS.
        config = make_config(
            default_mode="bypassPermissions",
            hooks=[HookEntry("PreToolUse", "Bash", "/h/git-safety.sh")],
        )
        result = get_check("HS-D4-01").run(config)
        self.assertEqual(result.status, Status.PASS)
        self.assertIn("hook:git-safety", result.evidence)

    def test_deny_entry_credited(self):
        config = make_config(deny=["Bash(git push origin main)"])
        result = get_check("HS-D4-01").run(config)
        self.assertEqual(result.status, Status.PASS)
        self.assertIn("permissions.deny", result.evidence)


class TestD4OnFixtures(unittest.TestCase):
    def test_strong_harness_blocks_push(self):
        config = load_harness(FIXTURES / "strong_harness")
        self.assertEqual(get_check("HS-D4-01").run(config).status, Status.PASS)

    def test_weak_harness_fails_push_gate(self):
        config = load_harness(FIXTURES / "weak_harness")
        result = get_check("HS-D4-01").run(config)
        self.assertEqual(result.status, Status.FAIL)
        self.assertEqual(result.triggered_gate_cap.value, "C")


if __name__ == "__main__":
    unittest.main()

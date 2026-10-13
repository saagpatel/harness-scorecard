"""A skill gate needs a declared provenance rule for full credit."""

import unittest

from harness_scorecard.models import Status
from harness_scorecard.parsing import HookEntry
from tests.test_checks import get_check, make_config


class TestProvenanceRule(unittest.TestCase):
    def run_check(self, matcher="Edit|Write", rules=(), extra=()):
        hooks = [HookEntry("PreToolUse", matcher, "skill-install")] if matcher else []
        return get_check("HS-D9-01").run(
            make_config(hooks=hooks + list(extra), rule_files=list(rules))
        )

    def test_gate_without_rule_is_partial(self):
        self.assertEqual(self.run_check().status, Status.PARTIAL)

    def test_gate_with_rule_is_declared_pass(self):
        result = self.run_check(rules=["skill-provenance.md"])
        self.assertEqual(result.status, Status.PASS)
        self.assertIn("declared", result.message.lower())
        self.assertIn("not verified", result.message.lower())

    def test_hook_command_can_declare_rule(self):
        self.assertEqual(
            self.run_check(extra=[HookEntry("SessionStart", "", "skill-provenance")]).status,
            Status.PASS,
        )

    def test_rule_without_gate_fails_and_one_lane_is_partial(self):
        self.assertEqual(self.run_check(matcher="", rules=["provenance.md"]).status, Status.FAIL)
        for matcher in ("Write", "Edit"):
            self.assertEqual(
                self.run_check(matcher=matcher, rules=["provenance.md"]).status, Status.PARTIAL
            )

"""D7 - Subagent isolation & governance checks."""

import unittest
from pathlib import Path

from harness_scorecard.discovery import HookEntry, load_harness
from harness_scorecard.models import Status
from tests.test_checks import get_check, make_config

FIXTURES = Path(__file__).parent / "fixtures"


class TestD7OnFixtures(unittest.TestCase):
    def test_strong_passes_every_d7_check(self):
        config = load_harness(FIXTURES / "strong_harness")
        for cid in ("HS-D7-01", "HS-D7-02", "HS-D7-03"):
            self.assertEqual(get_check(cid).run(config).status, Status.PASS, cid)

    def test_weak_fails_governance_checks(self):
        config = load_harness(FIXTURES / "weak_harness")
        self.assertEqual(get_check("HS-D7-01").run(config).status, Status.FAIL)
        self.assertEqual(get_check("HS-D7-03").run(config).status, Status.FAIL)

    def test_weak_has_no_model_pin_so_d7_02_passes(self):
        # Absence of the env pin is the desired state; a blank harness trivially has none.
        config = load_harness(FIXTURES / "weak_harness")
        self.assertEqual(get_check("HS-D7-02").run(config).status, Status.PASS)


class TestD701GlobalGuards(unittest.TestCase):
    def test_one_lane_is_partial(self):
        config = make_config(hooks=[HookEntry("PreToolUse", "Bash", "/h/git-safety.sh")])
        self.assertEqual(get_check("HS-D7-01").run(config).status, Status.PARTIAL)

    def test_no_lanes_fails(self):
        self.assertEqual(get_check("HS-D7-01").run(make_config()).status, Status.FAIL)


class TestD702ModelPin(unittest.TestCase):
    def test_pin_present_fails(self):
        config = make_config(env={"CLAUDE_CODE_SUBAGENT_MODEL": "haiku"})
        self.assertEqual(get_check("HS-D7-02").run(config).status, Status.FAIL)

    def test_pin_absent_passes(self):
        self.assertEqual(get_check("HS-D7-02").run(make_config()).status, Status.PASS)


class TestD703ScopeGovernance(unittest.TestCase):
    def test_linter_only_is_partial(self):
        config = make_config(
            hooks=[HookEntry("PreToolUse", "Agent", "/h/subagent-scope-linter.sh")]
        )
        self.assertEqual(get_check("HS-D7-03").run(config).status, Status.PARTIAL)

    def test_reviewer_only_is_partial(self):
        config = make_config(hooks=[HookEntry("SubagentStop", "", "/h/subagent-quality-gate.sh")])
        self.assertEqual(get_check("HS-D7-03").run(config).status, Status.PARTIAL)

    def test_scope_hook_on_wrong_lane_is_not_credited(self):
        # A subagent-scope hook on the Read lane never fires during Agent dispatch.
        config = make_config(hooks=[HookEntry("PreToolUse", "Read", "/h/subagent-scope-filter.sh")])
        self.assertEqual(get_check("HS-D7-03").run(config).status, Status.FAIL)


if __name__ == "__main__":
    unittest.main()

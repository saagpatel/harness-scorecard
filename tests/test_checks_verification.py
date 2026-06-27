"""D6 - Verification gates checks."""

import unittest
from pathlib import Path

from harness_scorecard.discovery import HookEntry, load_harness
from harness_scorecard.models import Status
from tests.test_checks import get_check, make_config

FIXTURES = Path(__file__).parent / "fixtures"


class TestD6OnFixtures(unittest.TestCase):
    def test_strong_passes_every_d6_check(self):
        config = load_harness(FIXTURES / "strong_harness")
        for cid in ("HS-D6-01", "HS-D6-02"):
            self.assertEqual(get_check(cid).run(config).status, Status.PASS, cid)

    def test_weak_fails_every_d6_check(self):
        config = load_harness(FIXTURES / "weak_harness")
        for cid in ("HS-D6-01", "HS-D6-02"):
            self.assertEqual(get_check(cid).run(config).status, Status.FAIL, cid)


class TestD602StopGate(unittest.TestCase):
    def test_stop_only_is_partial(self):
        config = make_config(hooks=[HookEntry("Stop", "", "/h/stop-gate.sh")])
        self.assertEqual(get_check("HS-D6-02").run(config).status, Status.PARTIAL)

    def test_subagent_only_is_partial(self):
        config = make_config(hooks=[HookEntry("SubagentStop", "", "/h/subagent-quality-gate.sh")])
        self.assertEqual(get_check("HS-D6-02").run(config).status, Status.PARTIAL)

    def test_unrelated_stop_hook_is_not_a_gate(self):
        # "gate" must not match an unrelated Stop hook like a delegate handler.
        config = make_config(hooks=[HookEntry("Stop", "", "/h/delegate.sh")])
        self.assertEqual(get_check("HS-D6-02").run(config).status, Status.FAIL)


if __name__ == "__main__":
    unittest.main()

"""D9 - Memory / provenance hygiene checks."""

import unittest
from pathlib import Path

from harness_scorecard.discovery import HookEntry, load_harness
from harness_scorecard.models import Status
from tests.test_checks import get_check, make_config

FIXTURES = Path(__file__).parent / "fixtures"


class TestD9OnFixtures(unittest.TestCase):
    def test_strong_passes_every_d9_check(self):
        config = load_harness(FIXTURES / "strong_harness")
        for cid in ("HS-D9-01", "HS-D9-02"):
            self.assertEqual(get_check(cid).run(config).status, Status.PASS, cid)

    def test_weak_fails_every_d9_check(self):
        config = load_harness(FIXTURES / "weak_harness")
        for cid in ("HS-D9-01", "HS-D9-02"):
            self.assertEqual(get_check(cid).run(config).status, Status.FAIL, cid)


class TestD901SkillInstallGate(unittest.TestCase):
    def test_gate_on_both_channels_passes(self):
        config = make_config(
            hooks=[HookEntry("PreToolUse", "Edit|Write", "/h/skill-install-gate.sh")]
        )
        self.assertEqual(get_check("HS-D9-01").run(config).status, Status.PASS)

    def test_gate_on_write_only_is_partial(self):
        # Edit can still patch a skill, so guarding only Write is incomplete.
        config = make_config(hooks=[HookEntry("PreToolUse", "Write", "/h/skill-install-gate.sh")])
        self.assertEqual(get_check("HS-D9-01").run(config).status, Status.PARTIAL)


class TestD902CatalogBounds(unittest.TestCase):
    def test_both_settings_pass(self):
        config = make_config(
            raw_settings={"skillListingBudgetFraction": 0.035, "maxSkillDescriptionChars": 512}
        )
        self.assertEqual(get_check("HS-D9-02").run(config).status, Status.PASS)

    def test_one_setting_is_partial(self):
        config = make_config(raw_settings={"skillListingBudgetFraction": 0.035})
        self.assertEqual(get_check("HS-D9-02").run(config).status, Status.PARTIAL)


if __name__ == "__main__":
    unittest.main()

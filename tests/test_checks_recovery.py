"""D8 - Recovery / rollback safety checks."""

import unittest
from pathlib import Path

from harness_scorecard.discovery import HookEntry, load_harness
from harness_scorecard.models import Status
from tests.test_checks import get_check, make_config

FIXTURES = Path(__file__).parent / "fixtures"


class TestD8OnFixtures(unittest.TestCase):
    def test_strong_passes_every_d8_check(self):
        config = load_harness(FIXTURES / "strong_harness")
        for cid in ("HS-D8-01", "HS-D8-02"):
            self.assertEqual(get_check(cid).run(config).status, Status.PASS, cid)

    def test_weak_fails_every_d8_check(self):
        config = load_harness(FIXTURES / "weak_harness")
        for cid in ("HS-D8-01", "HS-D8-02"):
            self.assertEqual(get_check(cid).run(config).status, Status.FAIL, cid)


class TestD801Precompact(unittest.TestCase):
    def test_precompact_backup_passes(self):
        config = make_config(hooks=[HookEntry("PreCompact", "", "/h/precompact-backup.sh")])
        self.assertEqual(get_check("HS-D8-01").run(config).status, Status.PASS)


class TestD802DeferIsolate(unittest.TestCase):
    def test_defer_only_is_partial(self):
        config = make_config(hooks=[HookEntry("PreToolUse", "Bash", "/h/defer-destructive.sh")])
        self.assertEqual(get_check("HS-D8-02").run(config).status, Status.PARTIAL)

    def test_worktree_setting_only_is_partial(self):
        config = make_config(raw_settings={"worktree": {"enabled": True}})
        self.assertEqual(get_check("HS-D8-02").run(config).status, Status.PARTIAL)

    def test_worktree_explicitly_disabled_is_not_credited(self):
        # "worktree": false must not count as isolation just because the key is present.
        config = make_config(raw_settings={"worktree": False})
        self.assertEqual(get_check("HS-D8-02").run(config).status, Status.FAIL)


if __name__ == "__main__":
    unittest.main()

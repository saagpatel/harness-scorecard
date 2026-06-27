"""D5 - Harness self-protection & integrity checks."""

import unittest
from pathlib import Path

from harness_scorecard.checks import ALL_CHECKS
from harness_scorecard.discovery import HookEntry, load_harness
from harness_scorecard.models import Status
from tests.test_checks import get_check, make_config

FIXTURES = Path(__file__).parent / "fixtures"


class TestD5Registered(unittest.TestCase):
    def test_all_three_checks_exist(self):
        ids = {c.id for c in ALL_CHECKS}
        self.assertTrue({"HS-D5-01", "HS-D5-02", "HS-D5-03"} <= ids)


class TestD5OnFixtures(unittest.TestCase):
    def test_strong_passes_every_d5_check(self):
        config = load_harness(FIXTURES / "strong_harness")
        for cid in ("HS-D5-01", "HS-D5-02", "HS-D5-03"):
            self.assertEqual(get_check(cid).run(config).status, Status.PASS, cid)
        self.assertIsNone(get_check("HS-D5-01").run(config).triggered_gate_cap)

    def test_weak_fails_self_protection_gate(self):
        config = load_harness(FIXTURES / "weak_harness")
        result = get_check("HS-D5-01").run(config)
        self.assertEqual(result.status, Status.FAIL)
        self.assertEqual(result.triggered_gate_cap.value, "C")


class TestD501WriteReadParity(unittest.TestCase):
    """Both the read-path and write-path guards must protect the harness config."""

    def test_both_guards_pass(self):
        config = make_config(
            hooks=[
                HookEntry("PreToolUse", "Bash", "/h/protect-claude-writes.sh"),
                HookEntry("PreToolUse", "Read|Edit|Write", "/h/protect-files.sh"),
            ]
        )
        self.assertEqual(get_check("HS-D5-01").run(config).status, Status.PASS)

    def test_write_only_is_partial_not_gated(self):
        config = make_config(hooks=[HookEntry("PreToolUse", "Bash", "/h/protect-claude-writes.sh")])
        result = get_check("HS-D5-01").run(config)
        self.assertEqual(result.status, Status.PARTIAL)
        self.assertIsNone(result.triggered_gate_cap)

    def test_read_only_is_partial(self):
        config = make_config(hooks=[HookEntry("PreToolUse", "Read", "/h/protect-files.sh")])
        self.assertEqual(get_check("HS-D5-01").run(config).status, Status.PARTIAL)

    def test_neither_fails_and_gates_at_c(self):
        result = get_check("HS-D5-01").run(make_config())
        self.assertEqual(result.status, Status.FAIL)
        self.assertEqual(result.triggered_gate_cap.value, "C")

    def test_protect_files_covering_only_write_not_edit_is_not_full(self):
        # A protect-files matcher of Read|Write leaves the Edit tool able to mutate config;
        # it must NOT count as complete write protection (regression for the OR-gap).
        config = make_config(hooks=[HookEntry("PreToolUse", "Read|Write", "/h/protect-files.sh")])
        result = get_check("HS-D5-01").run(config)
        self.assertEqual(result.status, Status.PARTIAL)
        self.assertIsNone(result.triggered_gate_cap)

    def test_protect_files_covering_only_edit_not_write_is_not_full(self):
        config = make_config(hooks=[HookEntry("PreToolUse", "Edit|Read", "/h/protect-files.sh")])
        self.assertEqual(get_check("HS-D5-01").run(config).status, Status.PARTIAL)


class TestD502Integrity(unittest.TestCase):
    def test_verify_and_selfheal_pass(self):
        config = make_config(
            hooks=[
                HookEntry("SessionStart", "", "/h/hook-integrity-verify.sh"),
                HookEntry("SessionStart", "", "/h/harness-self-heal.sh"),
            ]
        )
        self.assertEqual(get_check("HS-D5-02").run(config).status, Status.PASS)

    def test_verify_only_is_partial(self):
        config = make_config(hooks=[HookEntry("SessionStart", "", "/h/hook-integrity-verify.sh")])
        self.assertEqual(get_check("HS-D5-02").run(config).status, Status.PARTIAL)

    def test_self_heal_without_verify_fails(self):
        # Self-heal without integrity verification cannot detect tampering -> no real floor.
        config = make_config(hooks=[HookEntry("SessionStart", "", "/h/harness-self-heal.sh")])
        self.assertEqual(get_check("HS-D5-02").run(config).status, Status.FAIL)


class TestD503SnapshotValidate(unittest.TestCase):
    def test_snapshot_and_validate_pass(self):
        config = make_config(
            hooks=[
                HookEntry("PreToolUse", "Edit|Write", "/h/harness-config-snapshot.sh"),
                HookEntry("PostToolUse", "Edit|Write", "/h/harness-config-validate.sh"),
            ]
        )
        self.assertEqual(get_check("HS-D5-03").run(config).status, Status.PASS)

    def test_snapshot_only_is_partial(self):
        config = make_config(
            hooks=[HookEntry("PreToolUse", "Edit|Write", "/h/harness-config-snapshot.sh")]
        )
        self.assertEqual(get_check("HS-D5-03").run(config).status, Status.PARTIAL)

    def test_neither_fails(self):
        self.assertEqual(get_check("HS-D5-03").run(make_config()).status, Status.FAIL)


if __name__ == "__main__":
    unittest.main()

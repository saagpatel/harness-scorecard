"""D10 - Observability / audit trail checks."""

import unittest
from pathlib import Path

from harness_scorecard.discovery import HookEntry, load_harness
from harness_scorecard.models import Status
from tests.test_checks import get_check, make_config

FIXTURES = Path(__file__).parent / "fixtures"


class TestD10OnFixtures(unittest.TestCase):
    def test_strong_passes_every_d10_check(self):
        config = load_harness(FIXTURES / "strong_harness")
        for cid in ("HS-D10-01", "HS-D10-02"):
            self.assertEqual(get_check(cid).run(config).status, Status.PASS, cid)

    def test_weak_fails_every_d10_check(self):
        config = load_harness(FIXTURES / "weak_harness")
        for cid in ("HS-D10-01", "HS-D10-02"):
            self.assertEqual(get_check(cid).run(config).status, Status.FAIL, cid)


class TestD1001AuditLogging(unittest.TestCase):
    def test_bash_only_is_partial(self):
        config = make_config(hooks=[HookEntry("PostToolUse", "Bash", "/h/bash-audit-log.sh")])
        self.assertEqual(get_check("HS-D10-01").run(config).status, Status.PARTIAL)

    def test_both_lanes_pass(self):
        config = make_config(
            hooks=[
                HookEntry("PostToolUse", "Bash", "/h/bash-audit-log.sh"),
                HookEntry("PostToolUse", "mcp__.*", "/h/mcp-audit-log.sh"),
            ]
        )
        self.assertEqual(get_check("HS-D10-01").run(config).status, Status.PASS)

    def test_mcp_audit_hook_on_bash_lane_does_not_credit_mcp(self):
        # A hook named mcp-audit-log but registered on the Bash lane logs Bash, not MCP.
        config = make_config(hooks=[HookEntry("PostToolUse", "Bash", "/h/mcp-audit-log.sh")])
        self.assertEqual(get_check("HS-D10-01").run(config).status, Status.PARTIAL)


class TestD1002FailureLogging(unittest.TestCase):
    def test_denial_only_is_partial(self):
        config = make_config(
            hooks=[HookEntry("PermissionDenied", "", "/h/permission-denied-log.sh")]
        )
        self.assertEqual(get_check("HS-D10-02").run(config).status, Status.PARTIAL)

    def test_both_categories_pass(self):
        config = make_config(
            hooks=[
                HookEntry("PermissionDenied", "", "/h/permission-denied-log.sh"),
                HookEntry("PostToolUseFailure", "", "/h/tool-failure-log.sh"),
            ]
        )
        self.assertEqual(get_check("HS-D10-02").run(config).status, Status.PASS)

    def test_non_logging_hook_under_event_is_not_credited(self):
        # A hook under the event that does not log/audit is not failure logging.
        config = make_config(
            hooks=[
                HookEntry("PermissionDenied", "", "/h/notify.sh"),
                HookEntry("PostToolUseFailure", "", "/h/notify.sh"),
            ]
        )
        self.assertEqual(get_check("HS-D10-02").run(config).status, Status.FAIL)


if __name__ == "__main__":
    unittest.main()

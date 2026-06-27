"""D2 - Egress / exfiltration control checks."""

import unittest
from pathlib import Path

from harness_scorecard.discovery import HookEntry, load_harness
from harness_scorecard.models import Status
from tests.test_checks import get_check, make_config

FIXTURES = Path(__file__).parent / "fixtures"


class TestD2OnFixtures(unittest.TestCase):
    def test_strong_passes_every_d2_check(self):
        config = load_harness(FIXTURES / "strong_harness")
        for cid in ("HS-D2-01", "HS-D2-02", "HS-D2-03"):
            self.assertEqual(get_check(cid).run(config).status, Status.PASS, cid)

    def test_weak_fails_every_d2_check(self):
        config = load_harness(FIXTURES / "weak_harness")
        for cid in ("HS-D2-01", "HS-D2-02", "HS-D2-03"):
            self.assertEqual(get_check(cid).run(config).status, Status.FAIL, cid)


class TestD201Egress(unittest.TestCase):
    def test_egress_hook_passes(self):
        config = make_config(hooks=[HookEntry("PreToolUse", "Bash", "/h/bash-egress-guard.sh")])
        self.assertEqual(get_check("HS-D2-01").run(config).status, Status.PASS)

    def test_only_wget_deny_is_partial(self):
        config = make_config(deny=["Bash(wget *)"])
        self.assertEqual(get_check("HS-D2-01").run(config).status, Status.PARTIAL)

    def test_neither_fails(self):
        self.assertEqual(get_check("HS-D2-01").run(make_config()).status, Status.FAIL)


class TestD202McpResourceDeny(unittest.TestCase):
    def test_both_denied_pass(self):
        config = make_config(deny=["ListMcpResourcesTool(*)", "ReadMcpResourceTool(*)"])
        self.assertEqual(get_check("HS-D2-02").run(config).status, Status.PASS)

    def test_one_denied_is_partial(self):
        config = make_config(deny=["ListMcpResourcesTool(*)"])
        self.assertEqual(get_check("HS-D2-02").run(config).status, Status.PARTIAL)

    def test_none_denied_fails(self):
        self.assertEqual(get_check("HS-D2-02").run(make_config()).status, Status.FAIL)


class TestD203McpOutputCap(unittest.TestCase):
    def test_cap_set_passes(self):
        config = make_config(env={"MAX_MCP_OUTPUT_TOKENS": "50000"})
        self.assertEqual(get_check("HS-D2-03").run(config).status, Status.PASS)

    def test_unset_fails(self):
        self.assertEqual(get_check("HS-D2-03").run(make_config()).status, Status.FAIL)

    def test_zero_or_nonpositive_cap_fails(self):
        # "0"/"-1"/"unlimited" do not bound output -> must not earn a pass.
        for value in ("0", "-1", "unlimited"):
            config = make_config(env={"MAX_MCP_OUTPUT_TOKENS": value})
            self.assertEqual(get_check("HS-D2-03").run(config).status, Status.FAIL, value)


if __name__ == "__main__":
    unittest.main()

"""D3 - Tool-surface & inbound-injection defense checks."""

import unittest
from pathlib import Path

from harness_scorecard.discovery import HookEntry, load_harness
from harness_scorecard.models import Status
from tests.test_checks import get_check, make_config

FIXTURES = Path(__file__).parent / "fixtures"


class TestD3OnFixtures(unittest.TestCase):
    def test_strong_passes_every_d3_check(self):
        config = load_harness(FIXTURES / "strong_harness")
        for cid in ("HS-D3-01", "HS-D3-02", "HS-D3-03"):
            self.assertEqual(get_check(cid).run(config).status, Status.PASS, cid)

    def test_weak_fails_every_d3_check(self):
        config = load_harness(FIXTURES / "weak_harness")
        for cid in ("HS-D3-01", "HS-D3-02", "HS-D3-03"):
            self.assertEqual(get_check(cid).run(config).status, Status.FAIL, cid)


class TestD301McpGated(unittest.TestCase):
    def test_mcp_matcher_passes(self):
        config = make_config(hooks=[HookEntry("PreToolUse", "mcp__.*", "/h/mcp-guard.sh")])
        self.assertEqual(get_check("HS-D3-01").run(config).status, Status.PASS)

    def test_universal_matcher_covers_mcp(self):
        config = make_config(hooks=[HookEntry("PreToolUse", "", "/h/global-guard.sh")])
        self.assertEqual(get_check("HS-D3-01").run(config).status, Status.PASS)

    def test_bash_only_fails(self):
        config = make_config(hooks=[HookEntry("PreToolUse", "Bash", "/h/git-safety.sh")])
        self.assertEqual(get_check("HS-D3-01").run(config).status, Status.FAIL)

    def test_single_specific_mcp_tool_matcher_does_not_gate_lane(self):
        # A matcher for ONE mcp tool gates only that tool, not the lane -> must FAIL.
        config = make_config(
            hooks=[HookEntry("PreToolUse", "mcp__search_files", "/h/mcp-guard.sh")]
        )
        self.assertEqual(get_check("HS-D3-01").run(config).status, Status.FAIL)


class TestD302Sentinels(unittest.TestCase):
    def test_all_three_pass(self):
        config = make_config(
            hooks=[
                HookEntry("PostToolUse", "mcp__.*", "/h/content-sentinel.sh"),
                HookEntry("PostToolUse", "WebFetch|WebSearch", "/h/webfetch-sentinel.sh"),
                HookEntry("PostToolUse", "Read|Grep", "/h/read-grep-sentinel.sh"),
            ]
        )
        self.assertEqual(get_check("HS-D3-02").run(config).status, Status.PASS)

    def test_two_of_three_is_partial(self):
        config = make_config(
            hooks=[
                HookEntry("PostToolUse", "mcp__.*", "/h/content-sentinel.sh"),
                HookEntry("PostToolUse", "WebFetch|WebSearch", "/h/webfetch-sentinel.sh"),
            ]
        )
        self.assertEqual(get_check("HS-D3-02").run(config).status, Status.PARTIAL)

    def test_none_fails(self):
        self.assertEqual(get_check("HS-D3-02").run(make_config()).status, Status.FAIL)

    def test_sentinel_on_wrong_lane_is_not_credited(self):
        # content-sentinel registered on the Bash lane does not cover MCP output, so only
        # the two correctly-placed sentinels count -> PARTIAL, not PASS.
        config = make_config(
            hooks=[
                HookEntry("PostToolUse", "Bash", "/h/content-sentinel.sh"),
                HookEntry("PostToolUse", "WebFetch|WebSearch", "/h/webfetch-sentinel.sh"),
                HookEntry("PostToolUse", "Read|Grep", "/h/read-grep-sentinel.sh"),
            ]
        )
        self.assertEqual(get_check("HS-D3-02").run(config).status, Status.PARTIAL)


class TestD303MatcherBreadth(unittest.TestCase):
    def test_mcp_and_file_pass(self):
        config = make_config(
            hooks=[
                HookEntry("PreToolUse", "mcp__.*", "/h/mcp-guard.sh"),
                HookEntry("PreToolUse", "Read|Edit|Write", "/h/protect-files.sh"),
            ]
        )
        self.assertEqual(get_check("HS-D3-03").run(config).status, Status.PASS)

    def test_only_one_lane_is_partial(self):
        config = make_config(hooks=[HookEntry("PreToolUse", "mcp__.*", "/h/mcp-guard.sh")])
        self.assertEqual(get_check("HS-D3-03").run(config).status, Status.PARTIAL)

    def test_bash_only_fails(self):
        config = make_config(hooks=[HookEntry("PreToolUse", "Bash", "/h/git-safety.sh")])
        self.assertEqual(get_check("HS-D3-03").run(config).status, Status.FAIL)


if __name__ == "__main__":
    unittest.main()

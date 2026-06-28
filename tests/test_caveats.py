"""Tests for opaque-dispatcher caveat detection and its surfacing in every renderer."""

import json
import tempfile
import unittest
from pathlib import Path

from harness_scorecard.caveats import detect_dispatcher_caveats
from harness_scorecard.discovery import load_harness
from harness_scorecard.htmlreport import render_html
from harness_scorecard.parsing import HookEntry
from harness_scorecard.report import render_console, render_json
from harness_scorecard.sarif import to_sarif
from harness_scorecard.scoring import score_harness


def _hook(event: str, command: str, matcher: str = "") -> HookEntry:
    return HookEntry(event=event, matcher=matcher, command=command)


class TestDispatcherDetection(unittest.TestCase):
    def test_dispatcher_on_pretooluse_is_flagged(self) -> None:
        caveats = detect_dispatcher_caveats(
            [_hook("PreToolUse", "python3 ~/.claude/hooks/pre_tool_use_dispatch.py")]
        )
        self.assertEqual(len(caveats), 1)
        self.assertIn("pre_tool_use_dispatch.py", caveats[0])
        self.assertIn("PreToolUse", caveats[0])

    def test_named_guards_are_not_flagged(self) -> None:
        hooks = [
            _hook("PreToolUse", "bash hooks/git-safety.sh"),
            _hook("PreToolUse", "bash hooks/block-dangerous-cmds.sh"),
            _hook("PreToolUse", "bash hooks/remote-command-guard.sh"),
        ]
        self.assertEqual(detect_dispatcher_caveats(hooks), [])

    def test_event_named_guards_are_not_flagged(self) -> None:
        # A guard *named after* the hook event is not a dispatcher: it carries no dispatch idiom.
        hooks = [
            _hook("PreToolUse", "bash hooks/check_pre_tool_use.sh"),
            _hook("PreToolUse", "bash hooks/enforce_pre_tool_use_permissions.sh"),
            _hook("PreToolUse", "python3 hooks/pretooluse.py"),
        ]
        self.assertEqual(detect_dispatcher_caveats(hooks), [])

    def test_dispatcher_named_after_event_still_flags(self) -> None:
        # ...but the real dispatcher (event name + explicit dispatch token) is still caught.
        caveats = detect_dispatcher_caveats(
            [_hook("PreToolUse", "python3 hooks/pre_tool_use_dispatch.py")]
        )
        self.assertEqual(len(caveats), 1)

    def test_script_name_picks_the_dispatcher_not_a_config_arg(self) -> None:
        caveats = detect_dispatcher_caveats(
            [_hook("PreToolUse", "python3 config.py hooks/dispatch.sh")]
        )
        self.assertEqual(len(caveats), 1)
        self.assertIn("dispatch.sh", caveats[0])
        self.assertNotIn("config.py", caveats[0])

    def test_router_and_run_hooks_tokens_match(self) -> None:
        self.assertEqual(
            len(detect_dispatcher_caveats([_hook("PostToolUse", "node hooks/tool-router.js")])), 1
        )
        self.assertEqual(
            len(detect_dispatcher_caveats([_hook("UserPromptSubmit", "bash hooks/run-hooks.sh")])),
            1,
        )

    def test_dispatcher_on_nonsecurity_event_is_ignored(self) -> None:
        # A dispatcher on SessionStart routes lifecycle chores, not tool guards -> no caveat.
        self.assertEqual(
            detect_dispatcher_caveats([_hook("SessionStart", "bash hooks/dispatch.sh")]), []
        )

    def test_route_substring_does_not_false_positive(self) -> None:
        # "reroute" contains no standalone dispatcher token; bare "route" is deliberately excluded.
        self.assertEqual(
            detect_dispatcher_caveats([_hook("PreToolUse", "bash hooks/reroute-guard.sh")]), []
        )

    def test_duplicate_dispatchers_dedupe(self) -> None:
        hook = _hook("PreToolUse", "python3 hooks/dispatch.py")
        self.assertEqual(len(detect_dispatcher_caveats([hook, hook])), 1)


class TestCaveatsSurfacedEverywhere(unittest.TestCase):
    def _dispatcher_card(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "settings.json").write_text(
                json.dumps(
                    {
                        "permissions": {"defaultMode": "default"},
                        "hooks": {
                            "PreToolUse": [
                                {
                                    "matcher": "",
                                    "hooks": [
                                        {"command": "python3 hooks/pre_tool_use_dispatch.py"}
                                    ],
                                }
                            ]
                        },
                    }
                ),
                encoding="utf-8",
            )
            return score_harness(load_harness(root))

    def test_caveat_appears_in_all_renderers(self) -> None:
        card = self._dispatcher_card()
        self.assertTrue(card.caveats)

        console = render_console(card)
        self.assertIn("Caveats", console)
        self.assertIn("dispatcher", console.lower())

        payload = json.loads(render_json(card))
        self.assertEqual(len(payload["caveats"]), 1)
        self.assertIn("dispatcher", payload["caveats"][0].lower())

        html = render_html(card)
        self.assertIn("Caveats", html)
        self.assertIn("pre_tool_use_dispatch.py", html)

        sarif = to_sarif(card)
        self.assertEqual(len(sarif["runs"][0]["properties"]["caveats"]), 1)

    def test_named_guard_harness_has_no_caveats(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "settings.json").write_text(
                json.dumps(
                    {
                        "permissions": {"defaultMode": "default"},
                        "hooks": {
                            "PreToolUse": [
                                {
                                    "matcher": "Bash",
                                    "hooks": [{"command": "bash hooks/git-safety.sh"}],
                                }
                            ]
                        },
                    }
                ),
                encoding="utf-8",
            )
            card = score_harness(load_harness(root))
        self.assertEqual(card.caveats, [])
        self.assertNotIn("Caveats", render_console(card))


if __name__ == "__main__":
    unittest.main()

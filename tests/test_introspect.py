"""Tests for dispatcher introspection: evidence detection + its credit/suggest application."""

import json
import tempfile
import unittest
from pathlib import Path

from harness_scorecard.checks_codex import CODEX_CHECKS
from harness_scorecard.discovery_codex import load_codex_harness
from harness_scorecard.introspect import Evidence, detect_evidence
from harness_scorecard.models import CheckResult, Grade, Status
from harness_scorecard.parsing import HookEntry
from harness_scorecard.report import _check_line, render_console
from harness_scorecard.scoring import _apply_detection, score_harness

_DISPATCHER = """\
import re

CODEX_SELF_WRITE_RE = re.compile(r"\\.codex/(?:hooks|config)")


def analyze(command):
    if re.search(r"git push --force", command):
        return "deny", "Force push blocked"
    return "allow", ""
"""

_COMMON = """\
HOOK_AUDIT_LOG = "audit.jsonl"


def append_audit(event):
    return event
"""

_PROMPT_DISPATCH = """\
from common import injection_signals


def main(prompt):
    hits = injection_signals(prompt)
    return hits
"""


def _hook(event: str, command: str) -> HookEntry:
    return HookEntry(event=event, matcher="", command=command)


def _result(check_id: str, status: Status = Status.FAIL) -> CheckResult:
    return CheckResult(
        id=check_id,
        dimension=check_id.rsplit("-", 1)[0].replace("CDX-", ""),
        title=check_id,
        status=status,
        weight=2,
        message="",
    )


class TestDetectEvidence(unittest.TestCase):
    def _harness(self, tmp: str) -> Path:
        root = Path(tmp)
        hooks = root / "hooks"
        hooks.mkdir()
        (hooks / "pre_tool_use_dispatch.py").write_text(_DISPATCHER, encoding="utf-8")
        (hooks / "common.py").write_text(_COMMON, encoding="utf-8")
        return root

    def test_finds_guards_in_dispatcher_and_siblings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = self._harness(tmp)
            hooks = [_hook("PreToolUse", "python3 hooks/pre_tool_use_dispatch.py")]
            found = detect_evidence(root, hooks)
        # D4-02 (force-push) + D5-03 (self-write regex) from the dispatcher; D10-01 from common.py.
        self.assertEqual({"CDX-D4-02", "CDX-D5-03", "CDX-D10-01"}, set(found))
        self.assertIn("common.py", found["CDX-D10-01"].location)
        self.assertIn("pre_tool_use_dispatch.py", found["CDX-D5-03"].location)

    def test_comment_only_mention_is_not_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "hooks").mkdir()
            (root / "hooks" / "pre_tool_use_dispatch.py").write_text(
                "# we should call injection_signals(prompt) someday\nx = 1\n", encoding="utf-8"
            )
            found = detect_evidence(
                root, [_hook("PreToolUse", "python3 hooks/pre_tool_use_dispatch.py")]
            )
        self.assertNotIn("CDX-D3-02", found)

    def test_injection_call_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "hooks").mkdir()
            (root / "hooks" / "user_prompt_submit_dispatch.py").write_text(
                _PROMPT_DISPATCH, encoding="utf-8"
            )
            found = detect_evidence(
                root, [_hook("UserPromptSubmit", "python3 hooks/user_prompt_submit_dispatch.py")]
            )
        self.assertIn("CDX-D3-02", found)

    def test_non_dispatcher_hook_scans_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = self._harness(tmp)
            # A named guard (no dispatch idiom) is not introspected, even with guards on disk.
            found = detect_evidence(root, [_hook("PreToolUse", "bash hooks/git-safety.sh")])
        self.assertEqual(found, {})

    def test_path_traversal_token_cannot_escape_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = self._harness(tmp)
            # A "../.." token resolves outside the harness root and must be ignored, not read.
            hooks = [_hook("PreToolUse", "python3 hooks/../../pre_tool_use_dispatch.py")]
            found = detect_evidence(root, hooks)
        self.assertEqual(found, {})

    def test_lifecycle_event_dispatcher_is_not_scanned(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = self._harness(tmp)
            # A dispatcher on SessionStart routes lifecycle chores, not tool guards -> no evidence.
            found = detect_evidence(
                root, [_hook("SessionStart", "python3 hooks/pre_tool_use_dispatch.py")]
            )
        self.assertEqual(found, {})

    def test_single_line_docstring_mention_is_not_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "hooks").mkdir()
            (root / "hooks" / "pre_tool_use_dispatch.py").write_text(
                '"""This dispatcher blocks git push --force on the Bash lane."""\nx = 1\n',
                encoding="utf-8",
            )
            found = detect_evidence(
                root, [_hook("PreToolUse", "python3 hooks/pre_tool_use_dispatch.py")]
            )
        self.assertNotIn("CDX-D4-02", found)


class TestApplyDetection(unittest.TestCase):
    def test_credit_upgrades_failing_check(self) -> None:
        results = [_result("CDX-D3-02")]
        evidence = {"CDX-D3-02": Evidence("CDX-D3-02", "x.py:1", "injection_signals(")}
        notes = _apply_detection(results, evidence, credit=True)
        self.assertIs(results[0].status, Status.PARTIAL)
        self.assertTrue(results[0].dispatcher_credited)
        self.assertEqual(results[0].credit_source, "detected")
        self.assertTrue(any("auto-credited" in note for note in notes))

    def test_suggest_leaves_status_and_emits_note(self) -> None:
        results = [_result("CDX-D3-02")]
        evidence = {"CDX-D3-02": Evidence("CDX-D3-02", "x.py:1", "injection_signals(")}
        notes = _apply_detection(results, evidence, credit=False)
        self.assertIs(results[0].status, Status.FAIL)
        self.assertFalse(results[0].dispatcher_credited)
        self.assertTrue(any("--credit-detected" in note for note in notes))

    def test_manifest_credited_check_is_not_re_sourced(self) -> None:
        # A manifest credit (operator-verified) must not be overwritten to the lower-trust
        # "detected" source, and detection must add no note for an already-PARTIAL check.
        result = _result("CDX-D3-02", status=Status.PARTIAL)
        result.dispatcher_credited = True
        result.credit_source = "manifest"
        evidence = {"CDX-D3-02": Evidence("CDX-D3-02", "x.py:1", "injection_signals(")}
        notes = _apply_detection([result], evidence, credit=True)
        self.assertEqual(result.credit_source, "manifest")
        self.assertEqual(notes, [])

    def test_gate_check_is_never_auto_credited(self) -> None:
        # Lifting a capability-gate floor on a source-scan heuristic is too consequential.
        result = _result("CDX-D4-01")
        result.is_gate = True
        result.gate_cap = Grade.C
        evidence = {"CDX-D4-01": Evidence("CDX-D4-01", "x.py:1", "")}
        notes = _apply_detection([result], evidence, credit=True)
        self.assertIs(result.status, Status.FAIL)
        self.assertFalse(result.dispatcher_credited)
        self.assertTrue(any("never" in note and "auto-credited" in note for note in notes))

    def test_waived_check_is_not_credited(self) -> None:
        result = _result("CDX-D3-02")
        result.waived = True
        evidence = {"CDX-D3-02": Evidence("CDX-D3-02", "x.py:1", "injection_signals(")}
        notes = _apply_detection([result], evidence, credit=True)
        self.assertFalse(result.dispatcher_credited)
        self.assertEqual(notes, [])

    def test_unknown_check_is_ignored(self) -> None:
        notes = _apply_detection(
            [_result("CDX-D3-02")],
            {"CDX-DOES-NOT-EXIST": Evidence("CDX-DOES-NOT-EXIST", "x.py:1", "")},
            credit=True,
        )
        self.assertEqual(notes, [])


class TestDetectionRendering(unittest.TestCase):
    def test_detected_label_distinct_from_manifest(self) -> None:
        detected = _result("CDX-D3-02", status=Status.PARTIAL)
        detected.dispatcher_credited = True
        detected.credit_source = "detected"
        line = "\n".join(_check_line(detected))
        self.assertIn("(dispatcher-detected)", line)
        self.assertNotIn("(dispatcher-credited)", line)


class TestEndToEndCreditDetected(unittest.TestCase):
    def test_credit_detected_lifts_a_failing_codex_check(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "config.toml").write_text(
                'sandbox_mode = "workspace-write"\n', encoding="utf-8"
            )
            hooks_dir = root / "hooks"
            hooks_dir.mkdir()
            (hooks_dir / "pre_tool_use_dispatch.py").write_text(_DISPATCHER, encoding="utf-8")
            (root / "hooks.json").write_text(
                json.dumps(
                    {
                        "hooks": {
                            "PreToolUse": [
                                {
                                    "matcher": "",
                                    "hooks": [
                                        {"command": "python3 hooks/pre_tool_use_dispatch.py"}
                                    ],
                                }
                            ]
                        }
                    }
                ),
                encoding="utf-8",
            )
            config = load_codex_harness(root)
            detected = detect_evidence(root, config.hooks)
            self.assertIn("CDX-D5-03", detected)

            suggested = score_harness(config, CODEX_CHECKS, detected=detected)
            credited = score_harness(config, CODEX_CHECKS, detected=detected, credit_detected=True)

        by_id = {c.id: c for dim in suggested.dimensions for c in dim.checks}
        self.assertIs(by_id["CDX-D5-03"].status, Status.FAIL)  # suggested, not credited
        self.assertTrue(any("CDX-D5-03" in note for note in suggested.policy_notes))

        by_id_credited = {c.id: c for dim in credited.dimensions for c in dim.checks}
        self.assertIs(by_id_credited["CDX-D5-03"].status, Status.PARTIAL)
        self.assertEqual(by_id_credited["CDX-D5-03"].credit_source, "detected")
        self.assertIn("(dispatcher-detected)", render_console(credited))


if __name__ == "__main__":
    unittest.main()

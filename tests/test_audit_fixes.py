"""Regression tests for the 1.0.1 audit fixes (graceful merge, stderr redaction, N/A dimension)."""

import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path

from harness_scorecard.cli import main
from harness_scorecard.discovery import load_harness
from harness_scorecard.models import CheckResult, DimensionResult, Status
from harness_scorecard.scoring import _overall_score


class TestMergeNullHookEvent(unittest.TestCase):
    def test_null_hook_event_does_not_crash_merge(self) -> None:
        # settings.json with a null hook event + settings.local.json with a real hook under it
        # must merge gracefully (degrade, not TypeError), keeping the valid hook.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "settings.json").write_text(
                json.dumps({"hooks": {"PreToolUse": None}}), encoding="utf-8"
            )
            (root / "settings.local.json").write_text(
                json.dumps(
                    {
                        "hooks": {
                            "PreToolUse": [
                                {"matcher": "Bash", "hooks": [{"command": "hooks/guard.sh"}]}
                            ]
                        }
                    }
                ),
                encoding="utf-8",
            )
            config = load_harness(root)
        self.assertTrue(any(h.command == "hooks/guard.sh" for h in config.hooks))


class TestErrorPathRedaction(unittest.TestCase):
    def test_missing_harness_error_redacts_home_path(self) -> None:
        home = os.path.expanduser("~")  # noqa: PTH111 - asserting the literal home is gone
        target = "~/.harness-scorecard-no-such-dir-xyz"
        buffer = io.StringIO()
        with contextlib.redirect_stderr(buffer):
            code = main(["scan", target])
        self.assertEqual(code, 2)
        err = buffer.getvalue()
        self.assertNotIn(home, err)
        self.assertIn("~/.harness-scorecard-no-such-dir-xyz", err)


class TestAllNaDimensionExcluded(unittest.TestCase):
    def _check(self, status: Status) -> CheckResult:
        return CheckResult(id="X", dimension="D1", title="t", status=status, weight=1, message="m")

    def test_all_na_dimension_is_excluded_from_overall(self) -> None:
        applicable = DimensionResult(
            id="D1", name="D1", weight=5, score=1.0, checks=[self._check(Status.PASS)]
        )
        all_na = DimensionResult(
            id="D7",
            name="D7",
            weight=3,
            score=0.0,
            checks=[self._check(Status.NOT_APPLICABLE)],
        )
        # Without the fix this would be (5*1.0 + 3*0.0) / 8 = 0.625; the all-N/A dim is excluded.
        self.assertEqual(_overall_score([applicable, all_na]), 1.0)


if __name__ == "__main__":
    unittest.main()

"""Tests for the diff engine, JSON round-trip reconstruction, renderers, and the `diff` CLI."""

import json
import tempfile
import unittest
from pathlib import Path

from harness_scorecard.cli import main
from harness_scorecard.diff import (
    diff_scorecards,
    render_diff_console,
    render_diff_json,
)
from harness_scorecard.models import (
    CheckResult,
    DimensionResult,
    Grade,
    Scorecard,
    Status,
)
from harness_scorecard.report import from_dict, render_json, to_dict


def _check(
    cid: str,
    dim: str,
    status: Status,
    *,
    is_gate: bool = False,
    gate_cap: Grade | None = None,
    title: str = "a check title",
) -> CheckResult:
    return CheckResult(
        id=cid,
        dimension=dim,
        title=title,
        status=status,
        weight=1,
        message="msg",
        is_gate=is_gate,
        gate_cap=gate_cap,
    )


def _dim(
    did: str, score: float, checks: list[CheckResult], *, name: str = "Dim", weight: int = 5
) -> DimensionResult:
    return DimensionResult(id=did, name=name, weight=weight, score=score, checks=checks)


def _card(
    grade: Grade,
    overall: float,
    dimensions: list[DimensionResult],
    *,
    harness_type: str = "claude-code",
) -> Scorecard:
    gate_caps = [c for dim in dimensions for c in dim.checks if c.triggered_gate_cap is not None]
    return Scorecard(
        harness_path="~/.claude",
        harness_type=harness_type,
        rubric_version="1.0.0",
        overall_score=overall,
        grade=grade,
        dimensions=dimensions,
        gate_caps=gate_caps,
    )


class TestDiffCore(unittest.TestCase):
    def test_identical_cards_produce_no_deltas(self) -> None:
        card = _card(Grade.B, 0.82, [_dim("D1", 1.0, [_check("HS-D1-01", "D1", Status.PASS)])])
        diff = diff_scorecards(card, card)
        self.assertEqual(diff.check_deltas, [])
        self.assertEqual(diff.dimension_deltas, [])
        self.assertEqual(diff.gate_deltas, [])
        self.assertFalse(diff.grade_regressed)
        self.assertFalse(diff.grade_improved)

    def test_check_flip_pass_to_fail_is_captured(self) -> None:
        old = _card(Grade.A, 0.95, [_dim("D1", 1.0, [_check("HS-D1-01", "D1", Status.PASS)])])
        new = _card(Grade.B, 0.85, [_dim("D1", 0.0, [_check("HS-D1-01", "D1", Status.FAIL)])])
        diff = diff_scorecards(old, new)
        self.assertEqual(len(diff.check_deltas), 1)
        delta = diff.check_deltas[0]
        self.assertEqual(delta.id, "HS-D1-01")
        self.assertEqual(delta.old_status, Status.PASS)
        self.assertEqual(delta.new_status, Status.FAIL)

    def test_dimension_score_move_is_captured(self) -> None:
        old = _card(Grade.B, 0.80, [_dim("D1", 0.90, [_check("HS-D1-01", "D1", Status.PASS)])])
        new = _card(Grade.B, 0.80, [_dim("D1", 0.40, [_check("HS-D1-01", "D1", Status.PARTIAL)])])
        diff = diff_scorecards(old, new)
        self.assertEqual(len(diff.dimension_deltas), 1)
        self.assertAlmostEqual(diff.dimension_deltas[0].old_score, 0.90)
        self.assertAlmostEqual(diff.dimension_deltas[0].new_score, 0.40)

    def test_sub_rounding_dimension_move_is_ignored(self) -> None:
        # A move below 4-decimal reporting granularity is noise, not a real change.
        old = _card(Grade.B, 0.80, [_dim("D1", 0.800000, [_check("HS-D1-01", "D1", Status.PASS)])])
        new = _card(Grade.B, 0.80, [_dim("D1", 0.800001, [_check("HS-D1-01", "D1", Status.PASS)])])
        diff = diff_scorecards(old, new)
        self.assertEqual(diff.dimension_deltas, [])

    def test_grade_regression_flags(self) -> None:
        old = _card(Grade.B, 0.82, [_dim("D1", 1.0, [_check("HS-D1-01", "D1", Status.PASS)])])
        new = _card(Grade.C, 0.71, [_dim("D1", 0.5, [_check("HS-D1-01", "D1", Status.PARTIAL)])])
        diff = diff_scorecards(old, new)
        self.assertTrue(diff.grade_regressed)
        self.assertFalse(diff.grade_improved)

    def test_grade_improvement_flags(self) -> None:
        old = _card(Grade.C, 0.71, [_dim("D1", 0.5, [_check("HS-D1-01", "D1", Status.PARTIAL)])])
        new = _card(Grade.B, 0.82, [_dim("D1", 1.0, [_check("HS-D1-01", "D1", Status.PASS)])])
        diff = diff_scorecards(old, new)
        self.assertTrue(diff.grade_improved)
        self.assertFalse(diff.grade_regressed)

    def test_gate_newly_trips_is_captured(self) -> None:
        gate_pass = _check("HS-D1-01", "D1", Status.PASS, is_gate=True, gate_cap=Grade.D)
        gate_fail = _check("HS-D1-01", "D1", Status.FAIL, is_gate=True, gate_cap=Grade.D)
        old = _card(Grade.B, 0.82, [_dim("D1", 1.0, [gate_pass])])
        new = _card(Grade.D, 0.40, [_dim("D1", 0.0, [gate_fail])])
        diff = diff_scorecards(old, new)
        self.assertEqual(len(diff.gate_deltas), 1)
        gate = diff.gate_deltas[0]
        self.assertFalse(gate.old_tripped)
        self.assertTrue(gate.new_tripped)
        self.assertEqual(gate.cap, Grade.D)

    def test_added_and_removed_checks(self) -> None:
        old = _card(Grade.B, 0.82, [_dim("D1", 1.0, [_check("HS-D1-01", "D1", Status.PASS)])])
        new = _card(
            Grade.B,
            0.82,
            [_dim("D1", 1.0, [_check("HS-D1-02", "D1", Status.PASS)])],
        )
        diff = diff_scorecards(old, new)
        by_id = {d.id: d for d in diff.check_deltas}
        self.assertIsNone(by_id["HS-D1-01"].new_status)  # removed
        self.assertEqual(by_id["HS-D1-01"].old_status, Status.PASS)
        self.assertIsNone(by_id["HS-D1-02"].old_status)  # added
        self.assertEqual(by_id["HS-D1-02"].new_status, Status.PASS)


class TestJsonRoundTrip(unittest.TestCase):
    def test_from_dict_reconstructs_a_card_that_diffs_clean(self) -> None:
        card = _card(
            Grade.B,
            0.8333333,
            [
                _dim(
                    "D1",
                    0.8333333,
                    [
                        _check("HS-D1-01", "D1", Status.PASS, is_gate=True, gate_cap=Grade.D),
                        _check("HS-D1-02", "D1", Status.PARTIAL),
                    ],
                ),
            ],
        )
        restored = from_dict(to_dict(card))
        diff = diff_scorecards(card, restored)
        self.assertEqual(diff.check_deltas, [])
        self.assertEqual(diff.dimension_deltas, [])
        self.assertEqual(diff.gate_deltas, [])
        self.assertEqual(restored.grade, Grade.B)

    def test_from_dict_rejects_non_report_json(self) -> None:
        with self.assertRaises(ValueError):
            from_dict({"hello": "world"})

    def test_from_dict_rejects_malformed_report(self) -> None:
        # Passes the top-level guard (has 'dimensions' + 'grade') but is missing inner
        # required keys -> clean ValueError, not a raw KeyError/TypeError.
        with self.assertRaises(ValueError):
            from_dict({"dimensions": [{"id": "D1"}], "grade": "B"})


class TestDiffRender(unittest.TestCase):
    def test_console_reports_regression_and_arrow(self) -> None:
        old = _card(Grade.B, 0.82, [_dim("D1", 1.0, [_check("HS-D1-01", "D1", Status.PASS)])])
        new = _card(Grade.C, 0.71, [_dim("D1", 0.5, [_check("HS-D1-01", "D1", Status.PARTIAL)])])
        text = render_diff_console(diff_scorecards(old, new))
        self.assertIn("B -> C", text)
        self.assertIn("regressed", text)
        self.assertIn("HS-D1-01", text)

    def test_console_clean_diff_states_no_change(self) -> None:
        card = _card(Grade.B, 0.82, [_dim("D1", 1.0, [_check("HS-D1-01", "D1", Status.PASS)])])
        text = render_diff_console(diff_scorecards(card, card))
        self.assertIn("no change", text.lower())

    def test_console_notes_harness_type_mismatch(self) -> None:
        checks = [_check("HS-D1-01", "D1", Status.PASS)]
        old = _card(Grade.B, 0.82, [_dim("D1", 1.0, checks)], harness_type="claude-code")
        new = _card(Grade.B, 0.82, [_dim("D1", 1.0, checks)], harness_type="codex")
        text = render_diff_console(diff_scorecards(old, new))
        self.assertIn("different harness types", text)

    def test_json_is_machine_readable(self) -> None:
        old = _card(Grade.B, 0.82, [_dim("D1", 1.0, [_check("HS-D1-01", "D1", Status.PASS)])])
        new = _card(Grade.C, 0.71, [_dim("D1", 0.5, [_check("HS-D1-01", "D1", Status.FAIL)])])
        payload = json.loads(render_diff_json(diff_scorecards(old, new)))
        self.assertEqual(payload["old_grade"], "B")
        self.assertEqual(payload["new_grade"], "C")
        self.assertTrue(payload["grade_regressed"])
        self.assertEqual(len(payload["checks_changed"]), 1)

    def test_harness_type_is_redacted_in_both_renderers(self) -> None:
        # A JSON-loaded baseline can carry an arbitrary harness_type string; it must be
        # redacted like every other emitted field. A secret-prefixed value proves redaction runs.
        leaky = "ghp_0123456789abcdefghijklmnopqrstuvwx"
        checks = [_check("HS-D1-01", "D1", Status.PASS)]
        old = _card(Grade.B, 0.82, [_dim("D1", 1.0, checks)], harness_type=leaky)
        new = _card(Grade.B, 0.82, [_dim("D1", 1.0, checks)], harness_type="codex")
        diff = diff_scorecards(old, new)
        text = render_diff_console(diff)
        payload = render_diff_json(diff)
        self.assertNotIn(leaky, text)
        self.assertNotIn(leaky, payload)
        self.assertIn("[redacted-secret]", text)


class TestDiffCli(unittest.TestCase):
    def _write_card(self, root: Path, name: str, card: Scorecard) -> str:
        target = root / name
        target.write_text(render_json(card), encoding="utf-8")
        return str(target)

    def test_regression_exits_one_improvement_exits_zero(self) -> None:
        better = _card(Grade.B, 0.82, [_dim("D1", 1.0, [_check("HS-D1-01", "D1", Status.PASS)])])
        worse = _card(Grade.C, 0.71, [_dim("D1", 0.5, [_check("HS-D1-01", "D1", Status.PARTIAL)])])
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            good = self._write_card(root, "good.json", better)
            bad = self._write_card(root, "bad.json", worse)
            self.assertEqual(main(["diff", good, bad]), 1)  # regression
            self.assertEqual(main(["diff", bad, good]), 0)  # improvement
            self.assertEqual(main(["diff", good, good]), 0)  # identical

    def test_diff_two_directories_identical_is_zero(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "settings.json").write_text(json.dumps({"hooks": {}}), encoding="utf-8")
            self.assertEqual(main(["diff", tmp, tmp]), 0)

    def test_diff_missing_input_exits_two(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            missing = str(Path(tmp) / "nope-not-here")
            self.assertEqual(main(["diff", missing, missing]), 2)

    def test_diff_malformed_json_exits_two(self) -> None:
        # Valid JSON that passes the top-level guard but lacks required fields must produce
        # the contract exit code (2), not a traceback / Python's implicit non-zero.
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "bad.json"
            bad.write_text(json.dumps({"dimensions": [], "grade": "B"}), encoding="utf-8")
            self.assertEqual(main(["diff", str(bad), str(bad)]), 2)


if __name__ == "__main__":
    unittest.main()

"""Tests for the fleet aggregator, its renderers, and the `fleet` CLI command."""

import json
import tempfile
import unittest
from pathlib import Path

from harness_scorecard.cli import main
from harness_scorecard.fleet import (
    FleetError,
    FleetReport,
    fleet_weakest_dimension,
    grade_distribution,
    render_fleet_console,
    render_fleet_json,
    worst_offender,
)
from harness_scorecard.models import CheckResult, DimensionResult, Grade, Scorecard, Status


def _dim(dim_id: str, score: float, name: str = "Dim") -> DimensionResult:
    check = CheckResult(
        id=f"{dim_id}-01",
        dimension=dim_id,
        title="t",
        status=Status.PASS if score >= 1.0 else Status.FAIL,
        weight=1,
        message="m",
    )
    return DimensionResult(id=dim_id, name=name, weight=5, score=score, checks=[check])


def _card(
    grade: Grade, overall: float, dims: list[DimensionResult], *, path: str = "~/.claude"
) -> Scorecard:
    return Scorecard(
        harness_path=path,
        harness_type="claude-code",
        rubric_version="1.0.0",
        overall_score=overall,
        grade=grade,
        dimensions=dims,
    )


class TestFleetAggregation(unittest.TestCase):
    def test_grade_distribution_counts_in_order(self) -> None:
        cards = [
            _card(Grade.A, 0.95, [_dim("D1", 1.0)]),
            _card(Grade.F, 0.20, [_dim("D1", 0.2)]),
            _card(Grade.A, 0.92, [_dim("D1", 1.0)]),
        ]
        dist = grade_distribution(cards)
        self.assertEqual(dist[Grade.A], 2)
        self.assertEqual(dist[Grade.F], 1)
        self.assertEqual(dist[Grade.B], 0)
        self.assertEqual(list(dist.keys()), [Grade.A, Grade.B, Grade.C, Grade.D, Grade.F])

    def test_fleet_weakest_dimension_is_lowest_average(self) -> None:
        cards = [
            _card(Grade.B, 0.8, [_dim("D1", 1.0, "Secrets"), _dim("D5", 0.4, "Self-protect")]),
            _card(Grade.C, 0.7, [_dim("D1", 0.8, "Secrets"), _dim("D5", 0.2, "Self-protect")]),
        ]
        weakest = fleet_weakest_dimension(cards)
        assert weakest is not None
        self.assertEqual(weakest[0], "D5")  # avg 0.3 < D1 avg 0.9
        self.assertAlmostEqual(weakest[2], 0.3)

    def test_worst_offender_is_lowest_grade_then_score(self) -> None:
        a = _card(Grade.A, 0.95, [_dim("D1", 1.0)], path="~/.claude")
        d1 = _card(Grade.D, 0.65, [_dim("D1", 0.6)], path="~/work")
        d2 = _card(Grade.D, 0.61, [_dim("D1", 0.6)], path="~/.codex")
        worst = worst_offender([a, d1, d2])
        assert worst is not None
        self.assertEqual(worst.harness_path, "~/.codex")  # lowest score among the two Ds

    def test_empty_fleet_has_no_weakest_or_worst(self) -> None:
        self.assertIsNone(fleet_weakest_dimension([]))
        self.assertIsNone(worst_offender([]))


class TestFleetRender(unittest.TestCase):
    def _report(self) -> FleetReport:
        return FleetReport(
            cards=[
                _card(Grade.A, 0.95, [_dim("D1", 1.0)], path="~/.claude"),
                _card(Grade.F, 0.28, [_dim("D1", 0.2, "Secrets")], path="~/.codex"),
            ],
            errors=[FleetError(path="~/Projects/foo/.claude", message="No settings.json found")],
        )

    def test_console_has_distribution_worst_and_errors(self) -> None:
        text = render_fleet_console(self._report())
        self.assertIn("Ax1", text)
        self.assertIn("Fx1", text)
        self.assertIn("Worst offender: ~/.codex", text)
        self.assertIn("Skipped", text)
        self.assertIn("~/Projects/foo/.claude", text)

    def test_json_structure(self) -> None:
        payload = json.loads(render_fleet_json(self._report()))
        self.assertEqual(payload["harness_count"], 2)
        self.assertEqual(payload["grades"]["A"], 1)
        self.assertEqual(payload["worst_offender"]["grade"], "F")
        self.assertEqual(len(payload["harnesses"]), 2)
        self.assertEqual(len(payload["errors"]), 1)


class TestFleetCli(unittest.TestCase):
    def _bare_harness(self, root: Path) -> None:
        (root / "settings.json").write_text(
            json.dumps({"permissions": {"defaultMode": "default"}, "hooks": {}}), encoding="utf-8"
        )

    def test_fleet_grades_multiple_and_gates_on_min_grade(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            a, b = root / "h1", root / "h2"
            a.mkdir()
            b.mkdir()
            self._bare_harness(a)
            self._bare_harness(b)
            # bare harnesses grade low -> below B (exit 1), at/above F (exit 0)
            self.assertEqual(main(["fleet", str(a), str(b), "--min-grade", "B"]), 1)
            self.assertEqual(main(["fleet", str(a), str(b), "--min-grade", "F"]), 0)

    def test_fleet_skips_bad_path_but_grades_the_rest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            good, bad = root / "good", root / "empty"
            good.mkdir()
            bad.mkdir()
            self._bare_harness(good)
            code = main(["fleet", str(good), str(bad), "--format", "json", "--min-grade", "F"])
            self.assertEqual(code, 0)  # one gradable harness, no error abort
            # console path also works and lists the skip
            text_code = main(["fleet", str(good), str(bad), "--min-grade", "F"])
            self.assertEqual(text_code, 0)

    def test_fleet_all_bad_paths_exits_two(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.assertEqual(main(["fleet", str(root / "nope"), str(root / "nada")]), 2)


if __name__ == "__main__":
    unittest.main()

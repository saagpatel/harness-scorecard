"""RUNTIME checks are reported but never folded into the grade (rubric §2)."""

import unittest
from dataclasses import dataclass, field
from pathlib import Path

from harness_scorecard.checks.base import Check, failed, passed
from harness_scorecard.models import Detectability, Grade
from harness_scorecard.scoring import score_harness


@dataclass
class _Config:
    root: Path = Path("/fixture")
    harness_type: str = "claude-code"
    caveats: list[str] = field(default_factory=list)


def _static(check_id: str, dimension: str, *, ok: bool) -> Check[_Config]:
    outcome = passed("ok") if ok else failed("missing")
    return Check(
        id=check_id,
        dimension=dimension,
        title=f"static {check_id}",
        weight=1,
        evaluate=lambda _config: outcome,
    )


def _runtime(check_id: str, dimension: str, *, ok: bool, is_gate: bool = False) -> Check[_Config]:
    outcome = passed("ok") if ok else failed("no receipt")
    return Check(
        id=check_id,
        dimension=dimension,
        title=f"runtime {check_id}",
        weight=5,
        evaluate=lambda _config: outcome,
        detectability=Detectability.RUNTIME,
        is_gate=is_gate,
        gate_cap=Grade.F if is_gate else None,
    )


class TestRuntimeChecksAreNotGraded(unittest.TestCase):
    def test_failing_runtime_check_does_not_lower_the_score(self) -> None:
        card = score_harness(
            _Config(),
            checks=[_static("S1", "D10", ok=True), _runtime("R1", "D10", ok=False)],
        )
        self.assertAlmostEqual(card.overall_score, 1.0)
        self.assertEqual(card.grade, Grade.A)

    def test_passing_runtime_check_does_not_raise_the_score(self) -> None:
        card = score_harness(
            _Config(),
            checks=[_static("S1", "D10", ok=False), _runtime("R1", "D10", ok=True)],
        )
        self.assertAlmostEqual(card.overall_score, 0.0)

    def test_dimension_with_only_runtime_checks_is_excluded(self) -> None:
        card = score_harness(
            _Config(),
            checks=[_static("S1", "D1", ok=True), _runtime("R1", "D10", ok=False)],
        )
        self.assertAlmostEqual(card.overall_score, 1.0)

    def test_runtime_gate_never_caps_the_grade(self) -> None:
        card = score_harness(
            _Config(),
            checks=[_static("S1", "D1", ok=True), _runtime("R1", "D10", ok=False, is_gate=True)],
        )
        self.assertEqual(card.gate_caps, [])
        self.assertEqual(card.grade, Grade.A)

    def test_runtime_result_is_still_reported_with_a_caveat(self) -> None:
        config = _Config(caveats=["existing caveat"])
        card = score_harness(
            config, checks=[_static("S1", "D10", ok=True), _runtime("R1", "D10", ok=False)]
        )
        reported = [c for d in card.dimensions for c in d.checks if c.id == "R1"]
        self.assertEqual(len(reported), 1)
        self.assertEqual(card.caveats[0], "existing caveat")
        self.assertIn("R1", card.caveats[1])
        self.assertIn("not graded", card.caveats[1])


if __name__ == "__main__":
    unittest.main()

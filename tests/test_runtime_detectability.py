"""RUNTIME checks are reported but never folded into the grade (rubric §2)."""

import unittest
from dataclasses import dataclass, field
from pathlib import Path

from harness_scorecard.checks.base import Check, failed, passed
from harness_scorecard.fleet import fleet_weakest_dimension
from harness_scorecard.htmlreport import render_html
from harness_scorecard.models import Detectability, Grade
from harness_scorecard.policy import Policy, Waiver
from harness_scorecard.report import render_console
from harness_scorecard.sarif import to_sarif
from harness_scorecard.scoring import score_harness
from harness_scorecard.summary import render_github_summary


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

    def test_runtime_result_is_reported_and_marked_not_graded(self) -> None:
        card = score_harness(
            _Config(caveats=["existing caveat"]),
            checks=[_static("S1", "D10", ok=True), _runtime("R1", "D10", ok=False)],
        )
        reported = [c for d in card.dimensions for c in d.checks if c.id == "R1"]
        self.assertEqual(len(reported), 1)
        self.assertEqual(card.caveats, ["existing caveat"])
        console = render_console(card)
        self.assertIn("R1", console)
        self.assertIn("(RUNTIME, not graded)", console)
        self.assertIn("RUNTIME, not graded", render_github_summary(card))
        self.assertIn("RUNTIME, not graded", render_html(card))

    def test_runtime_only_dimension_is_labelled_excluded(self) -> None:
        card = score_harness(
            _Config(),
            checks=[_static("S1", "D1", ok=True), _runtime("R1", "D10", ok=False)],
        )
        self.assertIn("(excluded: only RUNTIME checks, which are not graded)", render_console(card))

    def test_fleet_never_names_a_runtime_only_dimension_weakest(self) -> None:
        card = score_harness(
            _Config(),
            checks=[_static("S1", "D1", ok=False), _runtime("R1", "D10", ok=False)],
        )
        weakest = fleet_weakest_dimension([card])
        self.assertIsNotNone(weakest)
        assert weakest is not None
        self.assertEqual(weakest[0], "D1")

    def test_sarif_reports_runtime_failures_as_notes(self) -> None:
        card = score_harness(
            _Config(),
            checks=[_static("S1", "D1", ok=True), _runtime("R1", "D10", ok=False)],
        )
        results = to_sarif(card)["runs"][0]["results"]
        levels = {r["ruleId"]: r["level"] for r in results}
        self.assertEqual(levels.get("R1"), "note")


class TestPolicyOnRuntimeChecks(unittest.TestCase):
    def test_waiver_and_credit_on_runtime_check_are_flagged_unnecessary(self) -> None:
        policy = Policy(
            waivers=(Waiver(check="R1", reason="accepted"),),
            dispatcher_credits=("R1",),
        )
        card = score_harness(
            _Config(),
            checks=[_static("S1", "D1", ok=True), _runtime("R1", "D10", ok=False)],
            policy=policy,
        )
        result = next(c for d in card.dimensions for c in d.checks if c.id == "R1")
        self.assertFalse(result.waived)
        self.assertFalse(result.dispatcher_credited)
        notes = " | ".join(card.policy_notes)
        self.assertIn("waiver for R1 is unnecessary (RUNTIME", notes)
        self.assertIn("dispatcher credit for R1 is unnecessary (RUNTIME", notes)


if __name__ == "__main__":
    unittest.main()

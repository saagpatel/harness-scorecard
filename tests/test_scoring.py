"""End-to-end grading: weighted aggregation, A-F banding, and capability-gate capping."""

import unittest
from pathlib import Path

from harness_scorecard.discovery import HookEntry, load_harness
from harness_scorecard.models import Grade, grade_from_score
from harness_scorecard.scoring import score_harness
from tests.test_checks import make_config

FIXTURES = Path(__file__).parent / "fixtures"


class TestStrongHarnessGrade(unittest.TestCase):
    def setUp(self):
        self.card = score_harness(load_harness(FIXTURES / "strong_harness"))

    def test_scores_an_A(self):
        self.assertEqual(self.card.grade, Grade.A)

    def test_no_gates_tripped(self):
        self.assertEqual(self.card.gate_caps, [])

    def test_reports_both_implemented_dimensions(self):
        self.assertEqual({d.id for d in self.card.dimensions}, {"D1", "D4"})

    def test_overall_score_is_perfect(self):
        self.assertAlmostEqual(self.card.overall_score, 1.0)


class TestWeakHarnessGrade(unittest.TestCase):
    def setUp(self):
        self.card = score_harness(load_harness(FIXTURES / "weak_harness"))

    def test_scores_an_F(self):
        self.assertEqual(self.card.grade, Grade.F)

    def test_both_gates_trip(self):
        tripped = {r.id for r in self.card.gate_caps}
        self.assertEqual(tripped, {"HS-D1-01", "HS-D4-01"})


class TestGateCapping(unittest.TestCase):
    """A harness that scores well on weighting but fails a gate is capped down."""

    def setUp(self):
        # Strong D4 (effective hooks, non-bypass) but NO secret denies -> D1-01 gate fails.
        self.card = score_harness(
            make_config(
                default_mode="acceptEdits",
                deny=[],
                env={"DISABLE_TELEMETRY": "1", "DISABLE_ERROR_REPORTING": "1"},
                hooks=_strong_d4_hooks() + _partial_d1_hooks(),
            )
        )

    def test_uncapped_band_would_be_higher_than_final(self):
        uncapped = grade_from_score(self.card.overall_score)
        # The weighted score alone earns at least a C...
        self.assertIn(uncapped, (Grade.A, Grade.B, Grade.C))
        # ...but the D1 secret gate caps the final grade strictly lower.
        self.assertEqual(self.card.grade, Grade.D)

    def test_d1_gate_is_the_cause(self):
        self.assertEqual({r.id for r in self.card.gate_caps}, {"HS-D1-01"})


def _strong_d4_hooks():
    names = ["git-safety", "block-dangerous-cmds", "db-guard", "confirm-token"]
    return [HookEntry("PreToolUse", "Bash", f"/h/{name}.sh") for name in names]


def _partial_d1_hooks():
    return [
        HookEntry("PreToolUse", "Bash", "/h/protect-sensitive-reads.sh"),
        HookEntry("PreToolUse", "Edit|Write", "/h/detect-secrets.sh"),
    ]


if __name__ == "__main__":
    unittest.main()

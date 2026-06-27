"""End-to-end grading: weighted aggregation, A-F banding, and capability-gate capping."""

import unittest
from pathlib import Path

from harness_scorecard.discovery import load_harness
from harness_scorecard.models import Grade, grade_from_score
from harness_scorecard.scoring import score_harness

FIXTURES = Path(__file__).parent / "fixtures"


class TestStrongHarnessGrade(unittest.TestCase):
    def setUp(self):
        self.card = score_harness(load_harness(FIXTURES / "strong_harness"))

    def test_scores_an_A(self):
        self.assertEqual(self.card.grade, Grade.A)

    def test_no_gates_tripped(self):
        self.assertEqual(self.card.gate_caps, [])

    def test_reports_implemented_dimensions(self):
        self.assertEqual({d.id for d in self.card.dimensions}, {"D1", "D2", "D3", "D4", "D5"})

    def test_overall_score_is_perfect(self):
        self.assertAlmostEqual(self.card.overall_score, 1.0)


class TestWeakHarnessGrade(unittest.TestCase):
    def setUp(self):
        self.card = score_harness(load_harness(FIXTURES / "weak_harness"))

    def test_scores_an_F(self):
        self.assertEqual(self.card.grade, Grade.F)

    def test_all_critical_gates_trip(self):
        tripped = {r.id for r in self.card.gate_caps}
        self.assertEqual(tripped, {"HS-D1-01", "HS-D4-01", "HS-D5-01"})


class TestGateCapping(unittest.TestCase):
    """A harness that scores well on weighting but fails a gate is capped down."""

    # Core credential-path needles whose removal makes HS-D1-01 (the secret gate) fail while
    # leaving every other check satisfied (token-store, wallet, MCP denies all stay).
    _SECRET_NEEDLES = (".ssh", ".aws", ".gnupg", "/op/", "gcloud", ".env")

    def setUp(self):
        # Start from the canonical A harness and strip ONLY the core secret-path denies, so
        # HS-D1-01 is the single failing check -> it alone caps an otherwise-high grade.
        config = load_harness(FIXTURES / "strong_harness")
        config.deny = [
            entry for entry in config.deny if not any(s in entry for s in self._SECRET_NEEDLES)
        ]
        self.card = score_harness(config)

    def test_uncapped_band_would_be_higher_than_final(self):
        uncapped = grade_from_score(self.card.overall_score)
        # The weighted score alone earns at least a C...
        self.assertIn(uncapped, (Grade.A, Grade.B, Grade.C))
        # ...but the D1 secret gate caps the final grade strictly lower.
        self.assertEqual(self.card.grade, Grade.D)

    def test_d1_gate_is_the_cause(self):
        self.assertEqual({r.id for r in self.card.gate_caps}, {"HS-D1-01"})


if __name__ == "__main__":
    unittest.main()

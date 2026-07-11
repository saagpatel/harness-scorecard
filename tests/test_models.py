"""Behavior of the scoring primitives: status values, A-F banding, and grade capping."""

import unittest

from harness_scorecard.models import (
    CheckResult,
    Grade,
    Status,
    grade_from_score,
    worse_grade,
)


class TestStatusScore(unittest.TestCase):
    def test_pass_is_full_credit(self):
        self.assertEqual(Status.PASS.score, 1.0)

    def test_partial_is_half_credit(self):
        self.assertEqual(Status.PARTIAL.score, 0.5)

    def test_fail_is_zero(self):
        self.assertEqual(Status.FAIL.score, 0.0)

    def test_not_applicable_has_no_score(self):
        self.assertIsNone(Status.NOT_APPLICABLE.score)

    def test_unknown_has_no_score(self):
        self.assertIsNone(Status.UNKNOWN.score)


class TestBanding(unittest.TestCase):
    def test_a_band_floor(self):
        self.assertEqual(grade_from_score(0.90), Grade.A)
        self.assertEqual(grade_from_score(1.0), Grade.A)

    def test_just_below_a_is_b(self):
        self.assertEqual(grade_from_score(0.899), Grade.B)

    def test_band_boundaries(self):
        self.assertEqual(grade_from_score(0.80), Grade.B)
        self.assertEqual(grade_from_score(0.70), Grade.C)
        self.assertEqual(grade_from_score(0.60), Grade.D)

    def test_below_d_is_f(self):
        self.assertEqual(grade_from_score(0.599), Grade.F)
        self.assertEqual(grade_from_score(0.0), Grade.F)


class TestGradeCapping(unittest.TestCase):
    def test_worse_grade_picks_lower_band(self):
        # A capped at C must yield C (the worse of the two).
        self.assertEqual(worse_grade(Grade.A, Grade.C), Grade.C)

    def test_worse_grade_is_symmetric(self):
        self.assertEqual(worse_grade(Grade.C, Grade.A), Grade.C)

    def test_worse_grade_keeps_already_worse(self):
        # An F should never be lifted by a cap of D.
        self.assertEqual(worse_grade(Grade.F, Grade.D), Grade.F)


class TestCheckResult(unittest.TestCase):
    def test_gate_cap_defaults_to_none(self):
        result = CheckResult(
            id="HS-D1-99",
            dimension="D1",
            title="example",
            status=Status.PASS,
            weight=3,
            message="ok",
        )
        self.assertFalse(result.is_gate)
        self.assertIsNone(result.gate_cap)


if __name__ == "__main__":
    unittest.main()

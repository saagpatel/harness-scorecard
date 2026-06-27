"""CLI smoke tests: scan exits with the right code and emits the grade."""

import contextlib
import io
import json
import unittest
from pathlib import Path

from harness_scorecard.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


def run_cli(argv: list[str]) -> tuple[int, str]:
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        code = main(argv)
    return code, buffer.getvalue()


class TestScanCommand(unittest.TestCase):
    def test_strong_harness_exits_zero_and_grades_a(self):
        code, out = run_cli(["scan", str(FIXTURES / "strong_harness")])
        self.assertEqual(code, 0)
        self.assertIn("GRADE:  A", out)

    def test_weak_harness_exits_one_and_grades_f(self):
        code, out = run_cli(["scan", str(FIXTURES / "weak_harness")])
        self.assertEqual(code, 1)
        self.assertIn("GRADE:  F", out)
        self.assertIn("Capability gates tripped", out)

    def test_missing_harness_exits_two(self):
        code, _ = run_cli(["scan", str(FIXTURES / "nope")])
        self.assertEqual(code, 2)

    def test_json_format_is_valid_json(self):
        _, out = run_cli(["scan", str(FIXTURES / "strong_harness"), "--format", "json"])
        payload = json.loads(out)
        self.assertEqual(payload["grade"], "A")
        self.assertEqual(payload["dimensions_total"], 10)
        self.assertEqual(payload["dimensions_scored"], 5)


if __name__ == "__main__":
    unittest.main()

"""Execute the composite Action's enforcement shell with inert exit codes."""

import os
import shutil
import subprocess
import unittest
from pathlib import Path

ACTION = Path(__file__).resolve().parents[1] / "action.yml"


class TestActionExitCodes(unittest.TestCase):
    def enforce(self, scan, diff="", baseline=""):
        block = ACTION.read_text().split("    - name: Enforce grade and input validity")[1]
        script = "\n".join(line[8:] for line in block.split("      run: |\n")[1].splitlines())
        return subprocess.run(  # noqa: S603 - executes the reviewed repository action block
            [shutil.which("bash") or "/bin/bash", "-c", script],
            env={
                **os.environ,
                "SCAN_CODE": scan,
                "DIFF_CODE": diff,
                "HS_BASELINE": baseline,
                "HS_PATH": "fixture",
                "HS_MIN_GRADE": "B",
            },
            check=False,
            capture_output=True,
            text=True,
        )

    def test_crashes_and_interrupts_fail(self):
        for code in ("137", "130"):
            with self.subTest(code=code):
                result = self.enforce(code)
                self.assertEqual(result.returncode, 1)
                self.assertIn(
                    f"::error::harness-scorecard exited with unexpected code {code} "
                    "(crash or interrupt), not a grade result",
                    result.stdout,
                )

    def test_diff_crashes_and_interrupts_fail(self):
        for code in ("137", "130"):
            with self.subTest(code=code):
                result = self.enforce("0", code, "baseline.json")
                self.assertEqual(result.returncode, 1)
                self.assertIn(f"unexpected code {code}", result.stdout)

    def test_known_codes_and_missing_outputs_keep_messages(self):
        for code, exit_code, message in (
            ("0", 0, "Harness meets the minimum grade (B)."),
            ("1", 1, "Harness graded below the required minimum grade."),
            ("2", 1, "harness-scorecard found no harness at the configured path."),
            ("", 1, "Scan step produced no exit code; harness-scorecard setup likely failed."),
        ):
            with self.subTest(code=code):
                result = self.enforce(code)
                self.assertEqual(result.returncode, exit_code)
                self.assertIn(message, result.stdout)
        for code, exit_code, message in (
            ("0", 0, "No grade regression vs baseline"),
            ("1", 1, "Harness grade regressed below the committed baseline."),
            ("2", 1, "harness-scorecard diff could not read"),
            ("", 1, "Baseline comparison produced no exit code"),
        ):
            with self.subTest(diff=code):
                result = self.enforce("0", code, "baseline.json")
                self.assertEqual(result.returncode, exit_code)
                self.assertIn(message, result.stdout)

    def test_sarif_upload_allows_only_grade_results(self):
        condition = ACTION.read_text().split("- name: Upload SARIF")[1].split("uses:")[0]
        self.assertIn("steps.scan.outputs.exit-code == '0'", condition)
        self.assertIn("steps.scan.outputs.exit-code == '1'", condition)
        self.assertNotIn("!= '2'", condition)

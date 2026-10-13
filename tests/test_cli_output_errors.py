"""Report failures are input/output errors, never grade results."""

import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from harness_scorecard.cli import main

FIXTURE = "tests/fixtures/strong_harness"


def invoke(args):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(args)
    return code, out.getvalue(), err.getvalue()


class TestOutputErrors(unittest.TestCase):
    def test_missing_parent_for_all_report_types(self):
        with tempfile.TemporaryDirectory() as tmp:
            for flag in ("--json", "--html", "--sarif", "--badge", "--summary"):
                with self.subTest(flag=flag):
                    target = Path(tmp) / "missing" / "report"
                    code, out, err = invoke(["scan", FIXTURE, flag, str(target)])
                    self.assertEqual(code, 2)
                    self.assertEqual(out, "")
                    self.assertIn("error: cannot write", err)
                    self.assertFalse(target.exists())
            code, out, err = invoke(["claims", FIXTURE, "--json", str(target)])
            self.assertEqual((code, out), (2, ""))
            self.assertIn("error: cannot write", err)

    def test_denied_directory_has_no_stdout_or_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            root.chmod(0o500)
            try:
                code, out, err = invoke(["scan", FIXTURE, "--json", str(root / "report")])
                self.assertEqual((code, out), (2, ""))
                self.assertIn("error: cannot write", err)
                self.assertFalse((root / "report").exists())
            finally:
                root.chmod(0o700)

    def test_failed_replace_preserves_existing_report_and_cleans_temp(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "report.json"
            target.write_text("original")
            with patch("os.replace", side_effect=PermissionError("denied")):
                code, out, err = invoke(["scan", FIXTURE, "--json", str(target)])
            self.assertEqual((code, out), (2, ""))
            self.assertIn("denied", err)
            self.assertEqual(target.read_text(), "original")
            self.assertEqual(list(Path(tmp).iterdir()), [target])

    def test_success_preserves_stdout_and_report_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "report.json"
            baseline = invoke(["scan", FIXTURE, "--format", "json"])
            actual = invoke(["scan", FIXTURE, "--format", "json", "--json", str(target)])
            self.assertEqual(actual, baseline)
            self.assertEqual(target.read_text() + "\n", actual[1])

    def test_later_staging_failure_preserves_earlier_destination(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "existing.json"
            target.write_text("original")
            code, out, err = invoke(
                [
                    "scan",
                    FIXTURE,
                    "--json",
                    str(target),
                    "--html",
                    str(Path(tmp) / "missing" / "report"),
                ]
            )
            self.assertEqual((code, out), (2, ""))
            self.assertIn("error: cannot write", err)
            self.assertEqual(target.read_text(), "original")
            self.assertEqual(list(Path(tmp).iterdir()), [target])

    def test_all_requested_reports_render_before_writing(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "report.json"
            out = io.StringIO()
            with (
                patch("harness_scorecard.cli.render_html", side_effect=ValueError("render failed")),
                contextlib.redirect_stdout(out),
                self.assertRaises(ValueError),
            ):
                main(
                    [
                        "scan",
                        FIXTURE,
                        "--json",
                        str(target),
                        "--html",
                        str(Path(tmp) / "report.html"),
                    ]
                )
            self.assertEqual(out.getvalue(), "")
            self.assertFalse(target.exists())

"""The HTML renderer produces a self-contained, redacted, escaped scorecard."""

import contextlib
import io
import unittest
from pathlib import Path

from harness_scorecard.cli import main
from harness_scorecard.discovery import load_harness
from harness_scorecard.htmlreport import render_html
from harness_scorecard.scoring import score_harness

FIXTURES = Path(__file__).parent / "fixtures"
SCRATCH = Path("/private/tmp/claude-501/-Users-d/c7b31602-76dc-4835-90af-3e5c4fb27c52/scratchpad")


class TestRenderHtml(unittest.TestCase):
    def setUp(self):
        self.card = score_harness(load_harness(FIXTURES / "weak_harness"))
        self.html = render_html(self.card)

    def test_is_self_contained_html(self):
        self.assertTrue(self.html.startswith("<!DOCTYPE html>"))
        self.assertIn("</html>", self.html)
        # No external assets / scripts.
        self.assertNotIn("<script", self.html)
        self.assertNotIn("http://", self.html)

    def test_shows_grade_and_gates(self):
        self.assertIn(">F<", self.html)
        self.assertIn("Capability gates tripped", self.html)

    def test_escapes_interpolated_values(self):
        # mcp__.* style matchers and rule text must not inject raw markup.
        self.assertNotIn("<script>", self.html)


class TestCliHtmlFlag(unittest.TestCase):
    def test_html_flag_writes_file(self):
        SCRATCH.mkdir(parents=True, exist_ok=True)
        out_path = SCRATCH / "scorecard_test.html"
        if out_path.exists():
            out_path.unlink()
        with contextlib.redirect_stdout(io.StringIO()):
            code = main(["scan", str(FIXTURES / "strong_harness"), "--html", str(out_path)])
        self.assertEqual(code, 0)
        self.assertTrue(out_path.exists())
        self.assertIn(">A<", out_path.read_text(encoding="utf-8"))
        out_path.unlink()


if __name__ == "__main__":
    unittest.main()

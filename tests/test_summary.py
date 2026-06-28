"""scan --summary: the GitHub-flavored Markdown report and its CLI side-output."""

import contextlib
import io
import tempfile
import unittest
from pathlib import Path

from harness_scorecard.cli import main
from harness_scorecard.dispatch import select_adapter
from harness_scorecard.failure_modes import FAILURE_MODES
from harness_scorecard.scoring import score_harness
from harness_scorecard.summary import _cell, _quote, render_github_summary

FIXTURES = Path(__file__).parent / "fixtures"


def _summary(fixture: str) -> str:
    config, checks = select_adapter(FIXTURES / fixture, "auto")
    return render_github_summary(score_harness(config, checks))


class TestRenderSummary(unittest.TestCase):
    def test_failing_harness_headline_and_gate_table(self):
        md = _summary("weak_harness")
        self.assertTrue(md.startswith("## Harness Scorecard — Grade F"))
        self.assertIn("### Capability gates tripped", md)
        self.assertIn("| `HS-D4-01` | **C** |", md)

    def test_failing_finding_carries_its_failure_mode_and_fix(self):
        md = _summary("weak_harness")
        self.assertIn("### Findings to address", md)
        self.assertIn("**`HS-D4-01`**", md)
        self.assertIn("**Fix:**", md)
        # the "why" is the documented failure mode, verbatim and inside its blockquote
        self.assertIn("> **Why:** " + FAILURE_MODES["HS-D4-01"], md)

    def test_passing_harness_has_no_findings_or_gate_section(self):
        md = _summary("strong_harness")
        self.assertIn("Grade A", md)
        self.assertIn("No findings to address", md)
        self.assertNotIn("### Findings to address", md)
        self.assertNotIn("### Capability gates tripped", md)

    def test_codex_harness_renders_with_cdx_findings(self):
        md = _summary("codex_weak")
        self.assertIn("`codex`", md)
        # a CDX finding must appear in the body, not merely in the metadata header
        self.assertIn("**`CDX-D", md)


class TestMarkdownSafety(unittest.TestCase):
    def test_pipe_in_a_table_cell_is_escaped(self):
        # An unescaped pipe would open a spurious column and desync the GFM table.
        self.assertEqual(_cell("scope | restrict"), "scope \\| restrict")

    def test_multiline_text_stays_inside_the_blockquote(self):
        # Every continuation line keeps the > prefix instead of escaping as a plain paragraph.
        self.assertEqual(_quote("Fix", "step one\nstep two"), ["> **Fix:** step one", "> step two"])

    def test_empty_text_quote_is_safe(self):
        self.assertEqual(_quote("Why", ""), ["> **Why:** "])


class TestSummaryCli(unittest.TestCase):
    def _scan_to_file(self, fixture: str, *extra: str) -> tuple[int, str]:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "summary.md"
            with contextlib.redirect_stdout(io.StringIO()):
                code = main(["scan", str(FIXTURES / fixture), "--summary", str(out), *extra])
            return code, out.read_text(encoding="utf-8")

    def test_summary_flag_writes_markdown_to_the_file(self):
        code, md = self._scan_to_file("weak_harness", "--min-grade", "F")
        self.assertEqual(code, 0)
        self.assertIn("## Harness Scorecard — Grade F", md)
        self.assertIn("**Why:**", md)
        # the console format must not leak into the markdown side-output
        self.assertNotIn("GRADE:", md)

    def test_summary_appends_so_prior_step_content_survives(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "step_summary.md"
            out.write_text("PRIOR STEP CONTENT\n", encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()):
                main(["scan", str(FIXTURES / "strong_harness"), "--summary", str(out)])
            content = out.read_text(encoding="utf-8")
        self.assertIn("PRIOR STEP CONTENT", content)
        self.assertIn("Harness Scorecard", content)
        self.assertLess(content.index("PRIOR"), content.index("Harness Scorecard"))


if __name__ == "__main__":
    unittest.main()

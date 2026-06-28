"""Tests for the SVG grade badge and the `scan --badge` output.

The badge is self-generated from a static template, so well-formedness is checked structurally
(no XML parser is invoked on the output -- avoiding stdlib XXE/entity-expansion footguns and the
need for a third-party parser in a stdlib-only project). Escaping of dynamic values is tested
directly instead.
"""

import tempfile
import unittest
from pathlib import Path

from harness_scorecard.badge import render_badge
from harness_scorecard.cli import main
from harness_scorecard.models import Grade, Scorecard


def _card(grade: Grade) -> Scorecard:
    return Scorecard(
        harness_path="~/.claude",
        harness_type="claude-code",
        rubric_version="1.0.0",
        overall_score=0.9,
        grade=grade,
        dimensions=[],
    )


def _is_svg(text: str) -> bool:
    return text.startswith("<svg") and text.rstrip().endswith("</svg>")


class TestBadge(unittest.TestCase):
    def test_badge_is_svg_with_grade(self) -> None:
        svg = render_badge(_card(Grade.A))
        self.assertTrue(_is_svg(svg))
        self.assertIn("harness", svg)
        self.assertIn(">A<", svg)

    def test_grade_drives_color(self) -> None:
        self.assertIn("#1a7f37", render_badge(_card(Grade.A)))  # green
        self.assertIn("#cf222e", render_badge(_card(Grade.F)))  # red

    def test_dynamic_values_are_escaped(self) -> None:
        svg = render_badge(_card(Grade.B), label="me & <you>")
        self.assertTrue(_is_svg(svg))
        self.assertNotIn("<you>", svg)  # the raw angle-bracketed text must not break the markup
        self.assertIn("&amp;", svg)

    def test_scan_writes_badge_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "settings.json").write_text(
                '{"permissions": {"defaultMode": "default"}, "hooks": {}}', encoding="utf-8"
            )
            badge = root / "grade.svg"
            main(["scan", tmp, "--badge", str(badge), "--min-grade", "F"])
            self.assertTrue(_is_svg(badge.read_text(encoding="utf-8")))


if __name__ == "__main__":
    unittest.main()

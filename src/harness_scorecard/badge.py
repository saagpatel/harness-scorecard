"""Render a scorecard grade as a flat SVG badge for a harness repo's README.

Dependency-free: a hand-built ``flat`` badge (the shields.io style), colored by grade. The badge
carries only the label and the A-F letter -- no paths, secrets, or harness detail -- so there is
nothing to redact. Drop the SVG in a repo and the grade is visible at a glance; regenerate it in
CI to keep it honest.
"""

from __future__ import annotations

import html
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from harness_scorecard.models import Scorecard

_GRADE_COLOR = {
    "A": "#1a7f37",
    "B": "#4c9a2a",
    "C": "#b08800",
    "D": "#bc4c00",
    "F": "#cf222e",
}
_DEFAULT_COLOR = "#9f9f9f"

# Approximate Verdana 11px advance width; a badge does not need pixel-perfect metrics.
_CHAR_PX = 7.0
_SIDE_PAD = 10


def _segment_width(text: str) -> int:
    return round(len(text) * _CHAR_PX) + _SIDE_PAD


def render_badge(card: Scorecard, label: str = "harness") -> str:
    """A flat SVG badge string: ``<label>: <grade>``, colored by grade."""
    grade = card.grade.value
    color = _GRADE_COLOR.get(grade, _DEFAULT_COLOR)
    safe_label = html.escape(label)
    safe_grade = html.escape(grade)

    label_w = _segment_width(safe_label)
    value_w = _segment_width(safe_grade)
    total_w = label_w + value_w
    label_x = label_w / 2
    value_x = label_w + value_w / 2

    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{total_w}" height="20" '
        f'role="img" aria-label="{safe_label}: {safe_grade}">'
        f"<title>{safe_label}: {safe_grade}</title>"
        '<linearGradient id="s" x2="0" y2="100%">'
        '<stop offset="0" stop-color="#bbb" stop-opacity=".1"/>'
        '<stop offset="1" stop-opacity=".1"/>'
        "</linearGradient>"
        f'<clipPath id="r"><rect width="{total_w}" height="20" rx="3" fill="#fff"/></clipPath>'
        '<g clip-path="url(#r)">'
        f'<rect width="{label_w}" height="20" fill="#555"/>'
        f'<rect x="{label_w}" width="{value_w}" height="20" fill="{color}"/>'
        f'<rect width="{total_w}" height="20" fill="url(#s)"/>'
        "</g>"
        '<g fill="#fff" text-anchor="middle" '
        'font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11">'
        f'<text x="{label_x}" y="15" fill="#010101" fill-opacity=".3">{safe_label}</text>'
        f'<text x="{label_x}" y="14">{safe_label}</text>'
        f'<text x="{value_x}" y="15" fill="#010101" fill-opacity=".3">{safe_grade}</text>'
        f'<text x="{value_x}" y="14">{safe_grade}</text>'
        "</g>"
        "</svg>"
    )

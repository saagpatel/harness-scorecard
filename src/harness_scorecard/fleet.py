"""Aggregate many graded :class:`~harness_scorecard.models.Scorecard` objects into a fleet view.

A fleet report answers the team/scale questions one scorecard can't: how do my harnesses grade
as a set, which dimension is weakest *across* them, and which harness is the worst offender. It
deliberately does NOT roll up to a single averaged A-F (averaging letter grades is meaningless) --
it shows the distribution and names the floor. Pure: it operates on already-graded scorecards, so
it is filesystem-free and trivially testable; the CLI does the per-path scan loop.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from harness_scorecard.models import Grade, grade_rank
from harness_scorecard.redaction import redact_text

if TYPE_CHECKING:
    from harness_scorecard.models import DimensionResult, Scorecard

# Best -> worst, the order grades are displayed in the distribution line.
_GRADE_DISPLAY_ORDER: tuple[Grade, ...] = (Grade.A, Grade.B, Grade.C, Grade.D, Grade.F)


@dataclass(frozen=True, slots=True)
class FleetError:
    """A path that could not be graded (not a harness, unreadable, malformed policy, ...)."""

    path: str
    message: str


@dataclass(slots=True)
class FleetReport:
    """The graded fleet: every harness that scored, plus the paths that were skipped."""

    cards: list[Scorecard]
    errors: list[FleetError] = field(default_factory=list)


def grade_distribution(cards: list[Scorecard]) -> dict[Grade, int]:
    """Count of harnesses at each grade, in A->F order (zeros included)."""
    counts = Counter(card.grade for card in cards)
    return {grade: counts.get(grade, 0) for grade in _GRADE_DISPLAY_ORDER}


def _card_weakest_dimension(card: Scorecard) -> DimensionResult | None:
    """The lowest-scoring dimension of one harness (ties resolve by list position)."""
    return min(card.dimensions, key=lambda dim: dim.score) if card.dimensions else None


def fleet_weakest_dimension(cards: list[Scorecard]) -> tuple[str, str, float] | None:
    """The dimension with the lowest *average* score across the fleet: (id, name, avg).

    Both adapters implement the same 10 shared dimensions, so coverage is uniform and the
    averages compare equal sample sizes. If a future adapter ever reports a different dimension
    set, weight by coverage here before calling the result "fleet-wide".
    """
    scores: dict[str, list[float]] = {}
    names: dict[str, str] = {}
    for card in cards:
        for dim in card.dimensions:
            scores.setdefault(dim.id, []).append(dim.score)
            names[dim.id] = dim.name
    if not scores:
        return None
    averages = {dim_id: sum(values) / len(values) for dim_id, values in scores.items()}
    worst_id = min(averages, key=lambda dim_id: averages[dim_id])
    return worst_id, names[worst_id], averages[worst_id]


def worst_offender(cards: list[Scorecard]) -> Scorecard | None:
    """The lowest-graded harness (tie-break: lowest overall score)."""
    if not cards:
        return None
    return min(cards, key=lambda card: (grade_rank(card.grade), card.overall_score))


def _weakest_label(card: Scorecard) -> str:
    weakest = _card_weakest_dimension(card)
    if weakest is None or weakest.score >= 1.0:
        return "-"  # nothing is actually weak (a perfect harness has no weakest dimension)
    return f"{weakest.id} {weakest.score:.2f}"


def render_fleet_console(report: FleetReport) -> str:
    """A skimmable, redacted fleet report."""
    cards = report.cards
    noun = "harness" if len(cards) == 1 else "harnesses"
    out: list[str] = [f"Harness Scorecard  fleet  ({len(cards)} {noun})", ""]

    distribution = grade_distribution(cards)
    out.append(
        "  Grades:  "
        + "   ".join(f"{grade.value}x{count}" for grade, count in distribution.items())
    )

    weakest = fleet_weakest_dimension(cards)
    if weakest:
        dim_id, name, avg = weakest
        out.append(f"  Weakest dimension fleet-wide: {dim_id} {redact_text(name)} (avg {avg:.2f})")

    worst = worst_offender(cards)
    if worst:
        out.append(
            f"  Worst offender: {redact_text(worst.harness_path)} "
            f"({worst.grade.value}, {worst.overall_score:.2f})"
        )
    out.append("")

    out.append(f"  {'GRADE':<6} {'SCORE':<6} {'TYPE':<12} {'WEAKEST':<10} HARNESS")
    out.extend(
        f"  {card.grade.value:<6} {card.overall_score:<6.2f} {card.harness_type:<12} "
        f"{_weakest_label(card):<10} {redact_text(card.harness_path)}"
        for card in cards
    )

    if report.errors:
        out.append("")
        out.append("  Skipped (no gradable harness):")
        out.extend(
            f"    - {redact_text(err.path)}: {redact_text(err.message)}" for err in report.errors
        )
    return "\n".join(out)


def _harness_summary(card: Scorecard) -> dict[str, Any]:
    weakest = _card_weakest_dimension(card)
    return {
        "path": redact_text(card.harness_path),
        "harness_type": card.harness_type,
        "grade": card.grade.value,
        "overall_score": round(card.overall_score, 4),
        "weakest_dimension": (
            {"id": weakest.id, "score": round(weakest.score, 4)} if weakest else None
        ),
    }


def to_fleet_dict(report: FleetReport) -> dict[str, Any]:
    """A JSON-serializable, redacted view of the fleet report."""
    weakest = fleet_weakest_dimension(report.cards)
    worst = worst_offender(report.cards)
    return {
        "harness_count": len(report.cards),
        "grades": {grade.value: count for grade, count in grade_distribution(report.cards).items()},
        "weakest_dimension": (
            {"id": weakest[0], "name": redact_text(weakest[1]), "avg_score": round(weakest[2], 4)}
            if weakest
            else None
        ),
        "worst_offender": (
            {
                "path": redact_text(worst.harness_path),
                "grade": worst.grade.value,
                "overall_score": round(worst.overall_score, 4),
            }
            if worst
            else None
        ),
        "harnesses": [_harness_summary(card) for card in report.cards],
        "errors": [
            {"path": redact_text(err.path), "message": redact_text(err.message)}
            for err in report.errors
        ],
    }


def render_fleet_json(report: FleetReport) -> str:
    return json.dumps(to_fleet_dict(report), indent=2)

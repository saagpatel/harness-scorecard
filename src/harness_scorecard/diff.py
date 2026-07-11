"""Compare two :class:`~harness_scorecard.models.Scorecard` objects into a structured delta.

The delta answers the three questions a harness owner asks when a config changes: which
checks flipped, which dimension scores moved, and whether a capability gate newly trips.
The letter grade is the contract -- a regression in grade is what fails a CI gate; gate and
dimension moves are reported for context. All rendered strings are redacted.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from harness_scorecard.models import Grade, Status, grade_rank
from harness_scorecard.redaction import redact_text

if TYPE_CHECKING:
    from harness_scorecard.models import CheckResult, DimensionResult, Scorecard

# Dimension moves smaller than this many decimals are noise, not a real change (it matches the
# precision the JSON report rounds scores to). Used for both delta detection and display.
_SCORE_DP = 4


@dataclass(slots=True)
class CheckDelta:
    """One check whose status changed. A ``None`` status means the check was absent on that side."""

    id: str
    dimension: str
    title: str
    old_status: Status | None
    new_status: Status | None


@dataclass(slots=True)
class DimensionDelta:
    """One dimension whose score moved beyond reporting granularity."""

    id: str
    name: str
    old_score: float | None
    new_score: float | None


@dataclass(slots=True)
class GateDelta:
    """One capability gate whose tripped state changed (newly trips, or newly clears)."""

    id: str
    title: str
    cap: Grade | None
    old_tripped: bool
    new_tripped: bool


@dataclass(slots=True)
class ScorecardDiff:
    """The full delta between an ``old`` (baseline) and ``new`` (current) scorecard."""

    old_grade: Grade
    new_grade: Grade
    old_overall: float
    new_overall: float
    old_harness_type: str
    new_harness_type: str
    check_deltas: list[CheckDelta]
    dimension_deltas: list[DimensionDelta]
    gate_deltas: list[GateDelta]

    @property
    def grade_regressed(self) -> bool:
        """The current grade is strictly worse than the baseline -- the CI-failing condition."""
        return grade_rank(self.new_grade) < grade_rank(self.old_grade)

    @property
    def grade_improved(self) -> bool:
        return grade_rank(self.new_grade) > grade_rank(self.old_grade)

    @property
    def has_changes(self) -> bool:
        return bool(
            self.old_grade is not self.new_grade
            or self.check_deltas
            or self.dimension_deltas
            or self.gate_deltas
        )


def _checks_by_id(card: Scorecard) -> dict[str, CheckResult]:
    return {check.id: check for dim in card.dimensions for check in dim.checks}


def _dims_by_id(card: Scorecard) -> dict[str, DimensionResult]:
    return {dim.id: dim for dim in card.dimensions}


def _ordered_union(old: dict[str, Any], new: dict[str, Any]) -> list[str]:
    """Keys in baseline order, with new-only keys appended in current order."""
    return list(dict.fromkeys([*old, *new]))


def _check_deltas(old: Scorecard, new: Scorecard) -> list[CheckDelta]:
    old_checks = _checks_by_id(old)
    new_checks = _checks_by_id(new)
    deltas: list[CheckDelta] = []
    for cid in _ordered_union(old_checks, new_checks):
        before = old_checks.get(cid)
        after = new_checks.get(cid)
        old_status = before.status if before else None
        new_status = after.status if after else None
        if old_status is new_status:
            continue
        ref = after or before
        assert ref is not None  # noqa: S101 - cid came from one of the two maps
        deltas.append(
            CheckDelta(
                id=cid,
                dimension=ref.dimension,
                title=ref.title,
                old_status=old_status,
                new_status=new_status,
            )
        )
    return deltas


def _dimension_deltas(old: Scorecard, new: Scorecard) -> list[DimensionDelta]:
    old_dims = _dims_by_id(old)
    new_dims = _dims_by_id(new)
    deltas: list[DimensionDelta] = []
    for did in _ordered_union(old_dims, new_dims):
        before = old_dims.get(did)
        after = new_dims.get(did)
        old_rounded = round(before.score, _SCORE_DP) if before else None
        new_rounded = round(after.score, _SCORE_DP) if after else None
        if old_rounded == new_rounded:
            continue
        ref = after or before
        assert ref is not None  # noqa: S101 - did came from one of the two maps
        deltas.append(
            DimensionDelta(
                id=did,
                name=ref.name,
                old_score=before.score if before else None,
                new_score=after.score if after else None,
            )
        )
    return deltas


def _gate_deltas(old: Scorecard, new: Scorecard) -> list[GateDelta]:
    old_gates = {c.id: c for c in _checks_by_id(old).values() if c.is_gate}
    new_gates = {c.id: c for c in _checks_by_id(new).values() if c.is_gate}
    deltas: list[GateDelta] = []
    for gid in _ordered_union(old_gates, new_gates):
        before = old_gates.get(gid)
        after = new_gates.get(gid)
        old_tripped = bool(before and before.triggered_gate_cap is not None)
        new_tripped = bool(after and after.triggered_gate_cap is not None)
        if old_tripped == new_tripped:
            continue
        ref = after or before
        assert ref is not None  # noqa: S101 - gid came from one of the two maps
        deltas.append(
            GateDelta(
                id=gid,
                title=ref.title,
                cap=ref.gate_cap,
                old_tripped=old_tripped,
                new_tripped=new_tripped,
            )
        )
    return deltas


def diff_scorecards(old: Scorecard, new: Scorecard) -> ScorecardDiff:
    """Compute the structured delta from a baseline ``old`` card to a current ``new`` card."""
    return ScorecardDiff(
        old_grade=old.grade,
        new_grade=new.grade,
        old_overall=old.overall_score,
        new_overall=new.overall_score,
        old_harness_type=old.harness_type,
        new_harness_type=new.harness_type,
        check_deltas=_check_deltas(old, new),
        dimension_deltas=_dimension_deltas(old, new),
        gate_deltas=_gate_deltas(old, new),
    )


_STATUS_TAG = {
    Status.PASS: "PASS",
    Status.PARTIAL: "PART",
    Status.FAIL: "FAIL",
    Status.UNKNOWN: "UNKN",
    Status.NOT_APPLICABLE: "N/A ",
    None: "----",
}


def _grade_verdict(diff: ScorecardDiff) -> str:
    if diff.grade_regressed:
        return "regressed"
    if diff.grade_improved:
        return "improved"
    return "unchanged"


def _score_str(score: float | None) -> str:
    # Display at detection precision so a real sub-0.01 move isn't rendered as "0.80 -> 0.80".
    return f"{score:.{_SCORE_DP}f}" if score is not None else "n/a"


def render_diff_console(diff: ScorecardDiff) -> str:
    """A skimmable, redacted text report of what changed between two scorecards."""
    out: list[str] = ["Harness Scorecard  diff", ""]
    out.append(
        f"  GRADE:  {diff.old_grade.value} -> {diff.new_grade.value}   ({_grade_verdict(diff)})"
        f"        overall {diff.old_overall:.2f} -> {diff.new_overall:.2f}"
    )
    if diff.old_harness_type != diff.new_harness_type:
        out.append(
            f"  note: comparing different harness types "
            f"({redact_text(diff.old_harness_type)} -> {redact_text(diff.new_harness_type)}); "
            f"deltas may be noisy."
        )
    out.append("")

    if not diff.has_changes:
        out.append("  No change. Both scorecards grade identically.")
        return "\n".join(out)

    if diff.gate_deltas:
        out.append(f"  Capability gates changed ({len(diff.gate_deltas)}):")
        for gate in diff.gate_deltas:
            verb = "now trips" if gate.new_tripped else "now clears"
            cap = gate.cap.value if gate.cap else "?"
            out.append(f"    - {gate.id} {verb} (caps at {cap})  {redact_text(gate.title)}")
        out.append("")

    if diff.check_deltas:
        out.append(f"  Checks changed ({len(diff.check_deltas)}):")
        for check in diff.check_deltas:
            arrow = f"{_STATUS_TAG[check.old_status]} -> {_STATUS_TAG[check.new_status]}"
            out.append(f"    - {check.id}  [{arrow}]  {redact_text(check.title)}")
        out.append("")

    if diff.dimension_deltas:
        out.append(f"  Dimensions moved ({len(diff.dimension_deltas)}):")
        out.extend(
            f"    - {dim.id}  {redact_text(dim.name)}   "
            f"{_score_str(dim.old_score)} -> {_score_str(dim.new_score)}"
            for dim in diff.dimension_deltas
        )
        out.append("")

    return "\n".join(out).rstrip()


def _status_value(status: Status | None) -> str | None:
    return status.value if status is not None else None


def to_diff_dict(diff: ScorecardDiff) -> dict[str, Any]:
    """A JSON-serializable, redacted view of the diff."""
    return {
        "old_grade": diff.old_grade.value,
        "new_grade": diff.new_grade.value,
        "grade_regressed": diff.grade_regressed,
        "grade_improved": diff.grade_improved,
        "old_overall": round(diff.old_overall, _SCORE_DP),
        "new_overall": round(diff.new_overall, _SCORE_DP),
        "old_harness_type": redact_text(diff.old_harness_type),
        "new_harness_type": redact_text(diff.new_harness_type),
        "checks_changed": [
            {
                "id": c.id,
                "dimension": c.dimension,
                "title": redact_text(c.title),
                "old_status": _status_value(c.old_status),
                "new_status": _status_value(c.new_status),
            }
            for c in diff.check_deltas
        ],
        "dimensions_moved": [
            {
                "id": d.id,
                "name": redact_text(d.name),
                "old_score": round(d.old_score, _SCORE_DP) if d.old_score is not None else None,
                "new_score": round(d.new_score, _SCORE_DP) if d.new_score is not None else None,
            }
            for d in diff.dimension_deltas
        ],
        "gates_changed": [
            {
                "id": g.id,
                "title": redact_text(g.title),
                "cap": g.cap.value if g.cap else None,
                "old_tripped": g.old_tripped,
                "new_tripped": g.new_tripped,
            }
            for g in diff.gate_deltas
        ],
    }


def render_diff_json(diff: ScorecardDiff) -> str:
    return json.dumps(to_diff_dict(diff), indent=2)

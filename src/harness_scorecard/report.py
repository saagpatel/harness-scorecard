"""Render a :class:`Scorecard` to console text or JSON. All output is redacted."""

from __future__ import annotations

import json
from typing import Any

from harness_scorecard.checks import DIMENSIONS
from harness_scorecard.failure_modes import FAILURE_MODES
from harness_scorecard.models import (
    CheckResult,
    Detectability,
    DimensionResult,
    Grade,
    Scorecard,
    Severity,
    Status,
)
from harness_scorecard.redaction import redact_text

_STATUS_TAG = {
    Status.PASS: "PASS",
    Status.PARTIAL: "PART",
    Status.FAIL: "FAIL",
    Status.NOT_APPLICABLE: "N/A ",
}


def _pending_dimension_ids(card: Scorecard) -> list[str]:
    scored = {dim.id for dim in card.dimensions}
    return [dim_id for dim_id in DIMENSIONS if dim_id not in scored]


def _check_line(check: CheckResult, *, explain: bool = False) -> list[str]:
    gate = f"  [GATE->{check.gate_cap.value}]" if check.is_gate and check.gate_cap else ""
    tag = "WAIV" if check.waived else _STATUS_TAG[check.status]
    credited = ""
    if check.dispatcher_credited:
        credited = (
            "  (dispatcher-detected)"
            if check.credit_source == "detected"
            else "  (dispatcher-credited)"
        )
    lines = [
        f"      [{tag}] {check.id}  {redact_text(check.title)}{gate}{credited}",
        f"             {redact_text(check.message)}",
        *(f"             - {redact_text(item)}" for item in check.evidence),
    ]
    if check.waived:
        lines.append(f"             waived: {redact_text(check.waiver_reason)}")
        return lines
    # --explain annotates each actionable finding with the red-team failure mode it guards
    # against (the why behind the fix), from the same registry the explain command uses.
    if explain and check.status in (Status.FAIL, Status.PARTIAL):
        failure_mode = FAILURE_MODES.get(check.id)
        if failure_mode:
            lines.append(f"             why: {redact_text(failure_mode)}")
    if check.status is not Status.PASS and check.remediation:
        lines.append(f"             fix: {redact_text(check.remediation)}")
    return lines


def _waived_checks(card: Scorecard) -> list[CheckResult]:
    return [check for dim in card.dimensions for check in dim.checks if check.waived]


def _credited_checks(card: Scorecard) -> list[CheckResult]:
    # A waived check's credit is moot (it's excluded anyway), so it counts only as waived.
    return [
        check
        for dim in card.dimensions
        for check in dim.checks
        if check.dispatcher_credited and not check.waived
    ]


def _policy_summary_lines(card: Scorecard) -> list[str]:
    """A short 'policy applied' summary plus any stale-policy warnings, or nothing."""
    out: list[str] = []
    waived = _waived_checks(card)
    credited = _credited_checks(card)
    manifest_credited = [c for c in credited if c.credit_source != "detected"]
    detected_credited = [c for c in credited if c.credit_source == "detected"]
    if waived or credited:
        parts = []
        if waived:
            parts.append(f"{len(waived)} finding(s) waived (excluded from the grade)")
        if manifest_credited:
            parts.append(f"{len(manifest_credited)} credited via dispatcher manifest")
        if detected_credited:
            parts.append(f"{len(detected_credited)} auto-detected behind the dispatcher")
        out.append(f"  Policy applied: {'; '.join(parts)}.")
        out.append("")
    if card.policy_notes:
        out.append("  Policy notes:")
        out.extend(f"    ! {redact_text(note)}" for note in card.policy_notes)
        out.append("")
    return out


def render_console(card: Scorecard, *, explain: bool = False) -> str:
    """A skimmable, dependency-free text report.

    When ``explain`` is set, each non-passing finding is annotated with the red-team failure
    mode it guards against, so the console output is self-explanatory without a second command.
    """
    out: list[str] = []
    out.append(f"Harness Scorecard  v{card.rubric_version}")
    out.append(f"Target: {redact_text(card.harness_path)}   ({card.harness_type})")
    out.append("")
    out.append(f"  GRADE:  {card.grade.value}        overall {card.overall_score:.2f} / 1.00")
    out.append(
        f"  Scored {len(card.dimensions)} of {len(DIMENSIONS)} rubric dimensions "
        f"({len(_pending_dimension_ids(card))} specced, pending)."
    )
    out.append("")

    if card.caveats:
        out.append("  Caveats (a low score below may be a static-analysis limit, not a gap):")
        out.extend(f"    * {redact_text(caveat)}" for caveat in card.caveats)
        out.append("")

    if card.gate_caps:
        out.append("  Capability gates tripped (grade capped):")
        for result in card.gate_caps:
            cap = result.triggered_gate_cap
            cap_value = cap.value if cap is not None else "?"
            out.append(f"    - {result.id} caps at {cap_value}  ({result.title})")
        out.append("")

    out.extend(_policy_summary_lines(card))

    for dim in card.dimensions:
        # Distinguish a dimension excluded by waivers from one that genuinely scored 0.00.
        counting = [c for c in dim.checks if not c.waived and c.status.score is not None]
        all_waived = not counting and any(c.waived for c in dim.checks)
        excluded = "  (excluded: all findings waived)" if all_waived else ""
        out.append(f"  {dim.id}  {dim.name}    {dim.score:.2f}  [weight {dim.weight}]{excluded}")
        for check in dim.checks:
            out.extend(_check_line(check, explain=explain))
        out.append("")

    pending = _pending_dimension_ids(card)
    if pending:
        out.append(f"  Pending dimensions (specced, not yet scored): {', '.join(pending)}")
    return "\n".join(out)


def to_dict(card: Scorecard) -> dict[str, Any]:
    """A JSON-serializable, redacted view of the scorecard."""
    return {
        "rubric_version": card.rubric_version,
        "harness_path": redact_text(card.harness_path),
        "harness_type": card.harness_type,
        "grade": card.grade.value,
        "overall_score": round(card.overall_score, 4),
        "dimensions_scored": len(card.dimensions),
        "dimensions_total": len(DIMENSIONS),
        "pending_dimensions": _pending_dimension_ids(card),
        "caveats": [redact_text(caveat) for caveat in card.caveats],
        "policy_notes": [redact_text(note) for note in card.policy_notes],
        "gate_caps": [
            {"id": r.id, "caps_at": r.triggered_gate_cap.value if r.triggered_gate_cap else None}
            for r in card.gate_caps
        ],
        "dimensions": [
            {
                "id": dim.id,
                "name": dim.name,
                "weight": dim.weight,
                "score": round(dim.score, 4),
                "checks": [
                    {
                        "id": c.id,
                        "title": redact_text(c.title),
                        "status": c.status.value,
                        "weight": c.weight,
                        "severity": c.severity.value,
                        "detectability": c.detectability.value,
                        "is_gate": c.is_gate,
                        "gate_cap": c.gate_cap.value if c.gate_cap else None,
                        "message": redact_text(c.message),
                        "evidence": [redact_text(e) for e in c.evidence],
                        "remediation": redact_text(c.remediation),
                        "waived": c.waived,
                        "waiver_reason": redact_text(c.waiver_reason),
                        "dispatcher_credited": c.dispatcher_credited,
                        "credit_source": c.credit_source,
                    }
                    for c in dim.checks
                ],
            }
            for dim in card.dimensions
        ],
    }


def render_json(card: Scorecard) -> str:
    return json.dumps(to_dict(card), indent=2)


def _check_from_dict(data: dict[str, Any], dimension_id: str) -> CheckResult:
    gate_cap = data.get("gate_cap")
    return CheckResult(
        id=data["id"],
        dimension=dimension_id,
        title=data["title"],
        status=Status(data["status"]),
        weight=data["weight"],
        message=data.get("message", ""),
        severity=Severity(data.get("severity", Severity.MEDIUM.value)),
        detectability=Detectability(data.get("detectability", Detectability.STATIC.value)),
        is_gate=data.get("is_gate", False),
        gate_cap=Grade(gate_cap) if gate_cap else None,
        remediation=data.get("remediation", ""),
        evidence=list(data.get("evidence", [])),
        waived=data.get("waived", False),
        waiver_reason=data.get("waiver_reason", ""),
        dispatcher_credited=data.get("dispatcher_credited", False),
        credit_source=data.get("credit_source", ""),
    )


def from_dict(data: dict[str, Any]) -> Scorecard:
    """Reconstruct a :class:`Scorecard` from a saved JSON report (the inverse of :func:`to_dict`).

    Gate caps are recomputed from the reconstructed checks rather than read back from the
    report's summary list, so the tripped-gate set has a single source of truth. Raises
    ``ValueError`` if ``data`` is not a recognizable harness-scorecard report.
    """
    if not isinstance(data, dict) or "dimensions" not in data or "grade" not in data:
        msg = "not a harness-scorecard JSON report (missing 'dimensions'/'grade')"
        raise ValueError(msg)
    try:
        dimensions = [
            DimensionResult(
                id=dim["id"],
                name=dim["name"],
                weight=dim["weight"],
                score=dim["score"],
                checks=[_check_from_dict(c, dim["id"]) for c in dim["checks"]],
            )
            for dim in data["dimensions"]
        ]
        gate_caps = [
            c for dim in dimensions for c in dim.checks if c.triggered_gate_cap is not None
        ]
        return Scorecard(
            harness_path=data["harness_path"],
            harness_type=data["harness_type"],
            rubric_version=data["rubric_version"],
            overall_score=data["overall_score"],
            grade=Grade(data["grade"]),
            dimensions=dimensions,
            gate_caps=gate_caps,
            caveats=[str(caveat) for caveat in data.get("caveats", [])],
            policy_notes=[str(note) for note in data.get("policy_notes", [])],
        )
    except (KeyError, TypeError) as exc:
        msg = f"malformed harness-scorecard JSON report: missing or invalid field {exc}"
        raise ValueError(msg) from exc

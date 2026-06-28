"""Aggregate check results into a graded :class:`Scorecard`.

Pipeline: run every registered check -> weighted dimension scores -> dimension-weighted
overall score -> A-F band -> apply capability-gate caps (the worse of band and any tripped
gate wins).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol

from harness_scorecard.checks import ALL_CHECKS, DIMENSIONS
from harness_scorecard.models import (
    RUBRIC_VERSION,
    CheckResult,
    DimensionResult,
    Scorecard,
    Status,
    grade_from_score,
    worse_grade,
)
from harness_scorecard.policy import EMPTY_POLICY, Policy
from harness_scorecard.redaction import redact_path

if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path

    from harness_scorecard.checks.base import Check


class ScorableConfig(Protocol):
    """The minimal surface scoring needs from any harness config (Claude Code or Codex)."""

    root: Path
    harness_type: str

    @property
    def caveats(self) -> list[str]:
        """Advisory notes that reframe the grade (e.g. an opaque dispatcher under-crediting)."""
        ...


def _scores(checks: list[CheckResult]) -> list[tuple[int, float]]:
    """(weight, score) for each check that counts: applicable (non-N/A) and not waived."""
    return [
        (c.weight, c.status.score) for c in checks if c.status.score is not None and not c.waived
    ]


def _weighted_score(checks: list[CheckResult]) -> float:
    """Weighted average of counting check scores (N/A and waived checks excluded)."""
    scored = _scores(checks)
    total_weight = sum(weight for weight, _ in scored)
    if total_weight == 0:
        return 0.0
    return sum(weight * score for weight, score in scored) / total_weight


def _dimension_applies(dimension: DimensionResult) -> bool:
    """A dimension counts only if at least one of its checks counts (non-N/A and unwaived)."""
    return bool(_scores(dimension.checks))


def _overall_score(dimensions: list[DimensionResult]) -> float:
    """Dimension-weighted average over dimensions that have at least one applicable check.

    A dimension whose checks are all N/A is excluded entirely rather than counted as a zero,
    so a harness genuinely not subject to a dimension is not penalized for it.
    """
    applicable = [dim for dim in dimensions if _dimension_applies(dim)]
    total_weight = sum(dim.weight for dim in applicable)
    if total_weight == 0:
        return 0.0
    return sum(dim.weight * dim.score for dim in applicable) / total_weight


def _apply_policy(results: list[CheckResult], policy: Policy) -> list[str]:
    """Apply an operator policy in place. Returns transparency notes for the report.

    Dispatcher credits run first (FAIL -> PARTIAL), then waivers exclude any remaining non-PASS
    finding. Both surface a note when they target a check that passes or doesn't exist, so a stale
    policy entry is visible rather than silently inert.
    """
    by_id = {result.id: result for result in results}
    notes: list[str] = []
    for check_id in policy.dispatcher_credits:
        result = by_id.get(check_id)
        if result is None:
            notes.append(f"dispatcher credit for unknown check {check_id} (ignored)")
        elif result.status is Status.FAIL:
            result.status = Status.PARTIAL
            result.dispatcher_credited = True
        else:
            notes.append(f"dispatcher credit for {check_id} is unnecessary (check did not fail)")
    for check_id, reason in policy.waiver_map.items():
        result = by_id.get(check_id)
        if result is None:
            notes.append(f"waiver for unknown check {check_id} (ignored)")
        elif result.status is Status.PASS:
            notes.append(f"waiver for {check_id} is unnecessary (check passes)")
        else:
            result.waived = True
            result.waiver_reason = reason
    return notes


def score_harness(
    config: ScorableConfig,
    checks: Sequence[Check[Any]] = ALL_CHECKS,
    policy: Policy = EMPTY_POLICY,
) -> Scorecard:
    """Grade a parsed harness config against the rubric using the given check set.

    ``checks`` defaults to the Claude Code suite; the Codex adapter passes its own. Scored
    dimensions are derived from the checks that ran, so the engine stays harness-agnostic. An
    optional operator ``policy`` waives accepted findings and credits dispatcher-declared checks.
    """
    results = [check.run(config) for check in checks]
    policy_notes = _apply_policy(results, policy)
    implemented_ids = list(dict.fromkeys(result.dimension for result in results))

    dimensions: list[DimensionResult] = []
    for dim_id in implemented_ids:
        dim = DIMENSIONS.get(dim_id)
        if dim is None:
            msg = f"check returned dimension {dim_id!r}, which is not in the rubric catalog"
            raise ValueError(msg)
        dim_checks = [r for r in results if r.dimension == dim_id]
        dimensions.append(
            DimensionResult(
                id=dim.id,
                name=dim.name,
                weight=dim.weight,
                score=_weighted_score(dim_checks),
                checks=dim_checks,
            )
        )

    overall = _overall_score(dimensions)
    grade = grade_from_score(overall)

    gate_caps = [r for r in results if r.triggered_gate_cap is not None]
    for result in gate_caps:
        assert result.triggered_gate_cap is not None  # noqa: S101 - narrowing for type checker
        grade = worse_grade(grade, result.triggered_gate_cap)

    return Scorecard(
        harness_path=redact_path(str(config.root)),
        harness_type=config.harness_type,
        rubric_version=RUBRIC_VERSION,
        overall_score=overall,
        grade=grade,
        dimensions=dimensions,
        gate_caps=gate_caps,
        caveats=list(config.caveats),
        policy_notes=policy_notes,
    )

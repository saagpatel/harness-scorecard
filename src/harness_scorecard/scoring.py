"""Aggregate check results into a graded :class:`Scorecard`.

Pipeline: run every registered check -> weighted dimension scores -> dimension-weighted
overall score -> A-F band -> apply capability-gate caps (the worse of band and any tripped
gate wins).
"""

from __future__ import annotations

from harness_scorecard.checks import ALL_CHECKS, DIMENSIONS, IMPLEMENTED_DIMENSION_IDS
from harness_scorecard.discovery import HarnessConfig
from harness_scorecard.models import (
    RUBRIC_VERSION,
    CheckResult,
    DimensionResult,
    Scorecard,
    grade_from_score,
    worse_grade,
)
from harness_scorecard.redaction import redact_path


def _weighted_score(checks: list[CheckResult]) -> float:
    """Weighted average of applicable check scores (N/A checks excluded)."""
    scored = [(c.weight, c.status.score) for c in checks if c.status.score is not None]
    total_weight = sum(weight for weight, _ in scored)
    if total_weight == 0:
        return 0.0
    return sum(weight * score for weight, score in scored) / total_weight


def _overall_score(dimensions: list[DimensionResult]) -> float:
    """Dimension-weighted average over dimensions that produced a score."""
    total_weight = sum(dim.weight for dim in dimensions)
    if total_weight == 0:
        return 0.0
    return sum(dim.weight * dim.score for dim in dimensions) / total_weight


def score_harness(config: HarnessConfig) -> Scorecard:
    """Grade a parsed harness config against the full rubric."""
    results = [check.run(config) for check in ALL_CHECKS]

    dimensions: list[DimensionResult] = []
    for dim_id in IMPLEMENTED_DIMENSION_IDS:
        dim = DIMENSIONS[dim_id]
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
    )

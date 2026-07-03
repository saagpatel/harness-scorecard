"""Core scoring primitives: statuses, grades, and result records.

These types are deliberately dependency-free (stdlib ``dataclasses`` + ``enum``) so the
scorer carries no third-party runtime surface of its own.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

RUBRIC_VERSION = "1.1.0"


class Status(StrEnum):
    """Outcome of a single check."""

    PASS = "pass"  # noqa: S105 - a check status, not a credential
    PARTIAL = "partial"
    FAIL = "fail"
    NOT_APPLICABLE = "not_applicable"

    @property
    def score(self) -> float | None:
        """Numeric credit, or ``None`` when the check is excluded from the denominator."""
        return {
            Status.PASS: 1.0,
            Status.PARTIAL: 0.5,
            Status.FAIL: 0.0,
            Status.NOT_APPLICABLE: None,
        }[self]


class Severity(StrEnum):
    """How badly the guarded failure mode hurts when it lands."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Detectability(StrEnum):
    """How confidently config-reading can confirm the check (see rubric §2)."""

    STATIC = "static"
    PARTIAL = "partial"
    RUNTIME = "runtime"


class Grade(StrEnum):
    """A-F maturity band."""

    A = "A"
    B = "B"
    C = "C"
    D = "D"
    F = "F"


# Worst -> best. Used for capping (take the worse of band and gate cap).
_GRADE_ORDER: tuple[Grade, ...] = (Grade.F, Grade.D, Grade.C, Grade.B, Grade.A)

# Band floors, highest first. A score >= floor earns that grade.
_BAND_FLOORS: tuple[tuple[float, Grade], ...] = (
    (0.90, Grade.A),
    (0.80, Grade.B),
    (0.70, Grade.C),
    (0.60, Grade.D),
)


def grade_rank(grade: Grade) -> int:
    """Higher rank = better grade. ``F`` is 0, ``A`` is 4."""
    return _GRADE_ORDER.index(grade)


def grade_from_score(score: float) -> Grade:
    """Map a 0.0-1.0 score to an A-F band per the rubric thresholds."""
    for floor, grade in _BAND_FLOORS:
        if score >= floor:
            return grade
    return Grade.F


def worse_grade(left: Grade, right: Grade) -> Grade:
    """Return the lower (worse) of two grades. Used to apply capability-gate caps."""
    return left if grade_rank(left) <= grade_rank(right) else right


@dataclass(slots=True)
class CheckResult:
    """The graded outcome of one rubric check against a harness."""

    id: str
    dimension: str
    title: str
    status: Status
    weight: int
    message: str
    severity: Severity = Severity.MEDIUM
    detectability: Detectability = Detectability.STATIC
    is_gate: bool = False
    gate_cap: Grade | None = None
    remediation: str = ""
    evidence: list[str] = field(default_factory=list)
    # Set by policy application (see harness_scorecard.policy): a waived finding is excluded from
    # scoring and its gate cap suppressed; a dispatcher-credited finding is upgraded to PARTIAL.
    waived: bool = False
    waiver_reason: str = ""
    dispatcher_credited: bool = False
    # How a dispatcher credit was established: "manifest" (operator-declared in the policy file)
    # or "detected" (auto-found in the dispatcher source via introspection, lower-trust). Empty
    # when the check is not dispatcher-credited.
    credit_source: str = ""

    @property
    def triggered_gate_cap(self) -> Grade | None:
        """The cap this check imposes, if it is a gate and it failed (and is not waived)."""
        if self.waived:
            return None
        if self.is_gate and self.status is Status.FAIL:
            return self.gate_cap
        return None


@dataclass(slots=True)
class DimensionResult:
    """Aggregated outcome for one rubric dimension."""

    id: str
    name: str
    weight: int
    score: float
    checks: list[CheckResult]


@dataclass(slots=True)
class Scorecard:
    """The full graded report for one harness."""

    harness_path: str
    harness_type: str
    rubric_version: str
    overall_score: float
    grade: Grade
    dimensions: list[DimensionResult]
    gate_caps: list[CheckResult] = field(default_factory=list)
    # Advisory notes that reframe (never change) the grade -- e.g. an opaque hook dispatcher
    # that makes named-guard checks under-credit. See harness_scorecard.caveats.
    caveats: list[str] = field(default_factory=list)
    # Transparency notes from applying an operator policy file (stale/unnecessary waivers,
    # unknown dispatcher credits). See harness_scorecard.policy.
    policy_notes: list[str] = field(default_factory=list)

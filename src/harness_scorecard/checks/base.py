"""Check abstraction, the dimension catalog, and the effective-enforcement helper.

A :class:`Check` pairs immutable rubric metadata (id, weight, gate status) with an
``evaluate`` function that inspects a :class:`HarnessConfig` and returns a status. The
effective-floor helper (:func:`effective_block`) centralizes the bypass-aware rule so every
destructive-action check enforces it identically.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field

from harness_scorecard.discovery import HarnessConfig
from harness_scorecard.models import (
    CheckResult,
    Detectability,
    Grade,
    Severity,
    Status,
)


@dataclass(frozen=True, slots=True)
class Dimension:
    id: str
    name: str
    weight: int


# The full rubric catalog (all ten dimensions). Scoring runs over whichever dimensions
# have registered checks; the rest are reported as specced-but-pending.
DIMENSIONS: dict[str, Dimension] = {
    "D1": Dimension("D1", "Secret protection & credential isolation", 5),
    "D2": Dimension("D2", "Egress / exfiltration control", 4),
    "D3": Dimension("D3", "Tool-surface & inbound-injection defense", 4),
    "D4": Dimension("D4", "Destructive-action & git safety", 5),
    "D5": Dimension("D5", "Harness self-protection & integrity", 5),
    "D6": Dimension("D6", "Verification gates", 3),
    "D7": Dimension("D7", "Subagent isolation & governance", 3),
    "D8": Dimension("D8", "Recovery / rollback safety", 2),
    "D9": Dimension("D9", "Memory / provenance hygiene", 2),
    "D10": Dimension("D10", "Observability / audit trail", 2),
}


@dataclass(slots=True)
class CheckOutcome:
    """The mutable result of evaluating a check: status + human-readable rationale."""

    status: Status
    message: str
    evidence: list[str] = field(default_factory=list)


def passed(message: str, evidence: Iterable[str] = ()) -> CheckOutcome:
    return CheckOutcome(Status.PASS, message, list(evidence))


def partial(message: str, evidence: Iterable[str] = ()) -> CheckOutcome:
    return CheckOutcome(Status.PARTIAL, message, list(evidence))


def failed(message: str, evidence: Iterable[str] = ()) -> CheckOutcome:
    return CheckOutcome(Status.FAIL, message, list(evidence))


def not_applicable(message: str, evidence: Iterable[str] = ()) -> CheckOutcome:
    """A check that does not apply to this harness; excluded from the dimension denominator."""
    return CheckOutcome(Status.NOT_APPLICABLE, message, list(evidence))


@dataclass(frozen=True, slots=True)
class Check[ConfigT]:
    """A single rubric check: metadata plus an evaluation function.

    Generic over the harness config it inspects (``HarnessConfig`` for Claude Code,
    ``CodexConfig`` for Codex) so the rubric metadata, ``run()``, and the dimension catalog
    are shared across adapters while each check only sees the config shape it understands.
    """

    id: str
    dimension: str
    title: str
    weight: int
    evaluate: Callable[[ConfigT], CheckOutcome]
    severity: Severity = Severity.MEDIUM
    detectability: Detectability = Detectability.STATIC
    is_gate: bool = False
    gate_cap: Grade | None = None
    remediation: str = ""
    # Dispatcher introspection (see harness_scorecard.introspect): regex code-signatures whose
    # presence in an opaque dispatcher's source evidences this check's guard. Empty unless the
    # guard can be routed through a dispatcher that name-based detection would miss.
    dispatcher_evidence: tuple[str, ...] = ()

    def run(self, config: ConfigT) -> CheckResult:
        outcome = self.evaluate(config)
        return CheckResult(
            id=self.id,
            dimension=self.dimension,
            title=self.title,
            status=outcome.status,
            weight=self.weight,
            message=outcome.message,
            severity=self.severity,
            detectability=self.detectability,
            is_gate=self.is_gate,
            gate_cap=self.gate_cap,
            remediation=self.remediation,
            evidence=outcome.evidence,
        )


@dataclass(slots=True)
class EffectiveFloor:
    """Whether a protection is present in the *effective* enforcement floor (rubric §3)."""

    blocked: bool
    sources: list[str]


def hard_deny_covers(config: HarnessConfig, token_groups: Sequence[Sequence[str]]) -> bool:
    """True only if ``hard_deny`` is effective AND some rule matches an AND-group of tokens."""
    if not config.hard_deny_effective:
        return False
    rules = [rule.lower() for rule in config.hard_deny]
    return any(all(token in rule for token in group) for group in token_groups for rule in rules)


def effective_block(
    config: HarnessConfig,
    *,
    hooks: Sequence[str] = (),
    deny_needles: Sequence[str] = (),
    hard_deny_tokens: Sequence[Sequence[str]] = (),
    event: str = "PreToolUse",
    matcher: str | None = "Bash",
) -> EffectiveFloor:
    """Resolve whether an action is blocked by the effective floor.

    The floor counts a guard present if any of: a registered hook matches; a
    ``permissions.deny`` entry matches; or an effective (non-bypass) ``hard_deny`` rule
    matches. A ``hard_deny`` rule under bypass mode contributes nothing.
    """
    sources: list[str] = [
        f"hook:{hook_name}" for hook_name in hooks if config.has_hook(event, hook_name, matcher)
    ]
    if any(config.deny_matches(needle) for needle in deny_needles):
        sources.append("permissions.deny")
    if hard_deny_covers(config, hard_deny_tokens):
        sources.append("hard_deny")
    return EffectiveFloor(blocked=bool(sources), sources=sources)

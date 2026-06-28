"""D7 (Codex) - Subagent isolation & governance.

Codex can fan out to subagent roles; ungoverned fan-out (unbounded threads/depth) or a role
that runs with ``approval_policy = "never"`` widens the blast radius. Bounds and per-role
approval discipline keep delegation contained.
"""

from __future__ import annotations

from harness_scorecard.checks.base import (
    Check,
    CheckOutcome,
    failed,
    not_applicable,
    partial,
    passed,
)
from harness_scorecard.discovery_codex import APPROVAL_NEVER, CodexConfig
from harness_scorecard.models import Detectability, Severity


def _fanout_bounded(config: CodexConfig) -> CheckOutcome:
    bounds: list[str] = []
    if config.agents_max_threads is not None:
        bounds.append(f"max_threads={config.agents_max_threads}")
    if config.agents_max_depth is not None:
        bounds.append(f"max_depth={config.agents_max_depth}")
    if len(bounds) == 2:  # noqa: PLR2004 - both thread and depth bounds present
        return passed("Subagent fan-out is bounded in both breadth and depth.", bounds)
    if len(bounds) == 1:
        return partial("Only one of max_threads / max_depth bounds subagent fan-out.", bounds)
    return failed("Subagent fan-out is unbounded: neither max_threads nor max_depth is set.")


def _no_agent_bypasses_approval(config: CodexConfig) -> CheckOutcome:
    if not config.agents:
        # Intentional N/A (not PASS): with no subagent roles there is nothing to govern, so the
        # check is excluded from the D7 denominator rather than vacuously credited.
        return not_applicable("No subagent roles are declared.")
    offenders = [agent.name for agent in config.agents if agent.approval_policy == APPROVAL_NEVER]
    if offenders:
        return failed(
            f"Subagent role(s) run with approval_policy=never: {', '.join(offenders)}.",
            evidence=offenders,
        )
    return passed("No subagent role bypasses the approval gate.")


CHECKS: list[Check[CodexConfig]] = [
    Check(
        id="CDX-D7-01",
        dimension="D7",
        title="Subagent fan-out is bounded",
        weight=2,
        evaluate=_fanout_bounded,
        severity=Severity.MEDIUM,
        detectability=Detectability.STATIC,
        remediation="Set [agents].max_threads and max_depth to bound concurrency and recursion.",
    ),
    Check(
        id="CDX-D7-02",
        dimension="D7",
        title="No subagent role bypasses approval",
        weight=1,
        evaluate=_no_agent_bypasses_approval,
        severity=Severity.HIGH,
        detectability=Detectability.STATIC,
        remediation="Remove approval_policy=never from any [agents.*] role.",
    ),
]

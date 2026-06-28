"""D10 (Codex) - Observability / audit trail.

Can an operator see what the agent did? A PostToolUse audit-log hook records tool calls, and a
turn-completion signal (the ``notify`` command, or at least a Stop hook) surfaces activity.
"""

from __future__ import annotations

from harness_scorecard.checks.base import Check, CheckOutcome, failed, partial, passed
from harness_scorecard.discovery_codex import CodexConfig
from harness_scorecard.models import Detectability, Severity

# Compound/specific only: bare "logging"/"telemetry" credit disable-logging / configure-telemetry
# hooks that do the opposite of recording tool calls.
_AUDIT_NEEDLES = ("audit", "audit-log", "tool-log")


def _has_audit_log(config: CodexConfig) -> bool:
    return any(config.has_hook("PostToolUse", needle) for needle in _AUDIT_NEEDLES)


def _tool_audit_log(config: CodexConfig) -> CheckOutcome:
    if _has_audit_log(config):
        return passed("A PostToolUse hook records tool calls for an audit trail.")
    return failed("No PostToolUse audit-log hook records what the agent did.")


def _turn_observability(config: CodexConfig) -> CheckOutcome:
    if config.notify:
        return passed("A notify command signals turn completion to an external channel.")
    if config.has_event("Stop"):
        return partial("A Stop hook fires at turn end, but no external notify is configured.")
    return failed("No turn-completion signal: neither a notify command nor a Stop hook.")


CHECKS: list[Check[CodexConfig]] = [
    Check(
        id="CDX-D10-01",
        dimension="D10",
        title="Tool calls are audit-logged",
        weight=1,
        evaluate=_tool_audit_log,
        severity=Severity.MEDIUM,
        detectability=Detectability.STATIC,
        remediation="Add a PostToolUse hook that appends tool calls to an audit log.",
    ),
    Check(
        id="CDX-D10-02",
        dimension="D10",
        title="Turn completion is observable",
        weight=1,
        evaluate=_turn_observability,
        severity=Severity.LOW,
        detectability=Detectability.STATIC,
        remediation=(
            "Configure a notify command (or at least a Stop hook) to surface turn completion."
        ),
    ),
]

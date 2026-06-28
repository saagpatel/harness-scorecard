"""D8 (Codex) - Recovery / rollback safety.

Codex has no PreCompact-style snapshot, so recovery rests on the sandbox confining changes to a
bounded, reversible area and on a SessionStart hook that can checkpoint or restore state. This is
the softest-fitting dimension for Codex; the checks credit what its surface actually offers.
"""

from __future__ import annotations

from harness_scorecard.checks.base import Check, CheckOutcome, failed, passed
from harness_scorecard.discovery_codex import CodexConfig
from harness_scorecard.models import Detectability, Severity


def _sandbox_confines_changes(config: CodexConfig) -> CheckOutcome:
    if config.sandbox_disabled:
        return failed(
            "danger-full-access lets the agent write anywhere; changes are not confined for "
            "rollback.",
        )
    return passed(f"The {config.sandbox_mode} sandbox confines writes, keeping changes reversible.")


def _session_checkpoint(config: CodexConfig) -> CheckOutcome:
    if config.has_event("SessionStart"):
        return passed("A SessionStart hook can establish a recovery checkpoint each session.")
    return failed("No SessionStart hook to checkpoint or restore session state.")


CHECKS: list[Check[CodexConfig]] = [
    Check(
        id="CDX-D8-01",
        dimension="D8",
        title="Sandbox confines changes for rollback",
        weight=1,
        evaluate=_sandbox_confines_changes,
        severity=Severity.MEDIUM,
        detectability=Detectability.STATIC,
        remediation=(
            "Use read-only or workspace-write sandbox so changes stay bounded and reversible."
        ),
    ),
    Check(
        id="CDX-D8-02",
        dimension="D8",
        title="Session-start checkpoint hook",
        weight=1,
        evaluate=_session_checkpoint,
        severity=Severity.LOW,
        detectability=Detectability.STATIC,
        remediation="Add a SessionStart hook that snapshots or restores recovery state.",
    ),
]

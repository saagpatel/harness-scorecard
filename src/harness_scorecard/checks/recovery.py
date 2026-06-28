"""D8 - Recovery / rollback safety."""

from __future__ import annotations

from harness_scorecard.checks.base import Check, CheckOutcome, failed, partial, passed
from harness_scorecard.discovery import HarnessConfig
from harness_scorecard.models import Severity


def _check_precompact_backup(config: HarnessConfig) -> CheckOutcome:
    if config.has_hook("PreCompact", "backup") or config.has_hook("PreCompact", "precompact"):
        return passed("A PreCompact hook backs up state before context compaction.")
    return failed("No PreCompact backup; compaction can lose un-snapshotted state irrecoverably.")


def _worktree_isolated(config: HarnessConfig) -> bool:
    """True when worktree isolation is actually enabled (not merely present-and-false)."""
    setting = config.raw_settings.get("worktree")
    if isinstance(setting, dict):
        enabled = setting.get("enabled", True) is not False
    elif isinstance(setting, bool):
        enabled = setting
    else:
        enabled = setting is not None
    return (
        enabled
        or config.has_hook("SessionStart", "worktree")
        or config.has_hook("SessionEnd", "worktree")
    )


def _check_defer_and_isolate(config: HarnessConfig) -> CheckOutcome:
    has_defer = config.has_hook("PreToolUse", "defer-destructive", matcher="Bash")
    has_worktree = _worktree_isolated(config)
    if has_defer and has_worktree:
        return passed("Destructive ops are deferred and work is isolated in worktrees.")
    if has_defer or has_worktree:
        covered = "destructive-op deferral" if has_defer else "worktree isolation"
        return partial(f"Only {covered} provides a recovery path.")
    return failed(
        "No defer-destructive posture or worktree isolation; irreversible acts have no path back."
    )


CHECKS: list[Check] = [
    Check(
        id="HS-D8-01",
        dimension="D8",
        title="Pre-compaction backup",
        weight=3,
        evaluate=_check_precompact_backup,
        severity=Severity.MEDIUM,
        remediation="Add a PreCompact hook that snapshots state before compaction.",
    ),
    Check(
        id="HS-D8-02",
        dimension="D8",
        title="Defer-destructive posture",
        weight=2,
        evaluate=_check_defer_and_isolate,
        severity=Severity.LOW,
        remediation="Defer destructive ops for confirmation and isolate work in git worktrees.",
        # Only the PreToolUse-Bash defer-destructive half is dispatcher-scannable; the worktree
        # half is settings/SessionStart, so detection lifts FAIL->PARTIAL, never to PASS.
        dispatcher_evidence=(
            r"defer[_-]?destructive",
            r"destructive[_-]?confirm",
            r"confirm[_-]?destructive",
        ),
    ),
]

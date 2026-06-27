"""D4 - Destructive-action & git safety.

Every block check here resolves against the *effective* enforcement floor, so a guard that
exists only in an inert ``hard_deny`` block under bypass mode scores as absent.
"""

from __future__ import annotations

from harness_scorecard.checks.base import (
    Check,
    CheckOutcome,
    effective_block,
    failed,
    partial,
    passed,
)
from harness_scorecard.discovery import HarnessConfig
from harness_scorecard.models import Detectability, Grade, Severity


def _bypass_note(config: HarnessConfig) -> list[str]:
    if config.is_bypass:
        return ["defaultMode=bypassPermissions: autoMode.hard_deny is INERT"]
    return []


def _check_push_to_protected_branch(config: HarnessConfig) -> CheckOutcome:
    floor = effective_block(
        config,
        hooks=("git-safety", "git-guard", "protect-branch"),
        deny_needles=("push origin main", "push origin master", "git push"),
        hard_deny_tokens=(("push", "main"), ("push", "master")),
    )
    if floor.blocked:
        return passed(
            "Push to a protected branch is blocked by the effective floor.",
            evidence=floor.sources,
        )
    return failed(
        "Push to main/master is not blocked by any effective guard.",
        evidence=[*_bypass_note(config), "no git-safety hook or deny entry found"],
    )


def _check_catastrophic_deletion(config: HarnessConfig) -> CheckOutcome:
    floor = effective_block(
        config,
        hooks=("block-dangerous-cmds", "defer-destructive", "dangerous"),
        deny_needles=("rm -rf /", "rm -rf ~", "rm -rf /*"),
        hard_deny_tokens=(("rm -rf",),),
    )
    if floor.blocked:
        return passed("Catastrophic deletion is blocked by the effective floor.", floor.sources)
    return failed(
        "No effective guard against catastrophic rm -rf deletion.",
        evidence=_bypass_note(config),
    )


def _check_destructive_db(config: HarnessConfig) -> CheckOutcome:
    floor = effective_block(
        config,
        hooks=("db-guard", "database-guard"),
        deny_needles=(),
        hard_deny_tokens=(("destructive", "db"), ("database",), ("db", "host")),
    )
    if floor.blocked:
        return passed("Destructive DB operations are guarded.", floor.sources)
    return failed(
        "No effective guard against destructive DB operations on non-local hosts.",
        evidence=_bypass_note(config),
    )


def _check_dependency_install_gate(config: HarnessConfig) -> CheckOutcome:
    if config.has_hook("PreToolUse", "confirm-token", matcher="Bash") or config.has_hook(
        "PreToolUse", "lockfile-freeze", matcher="Bash"
    ):
        return passed("Dependency installs require a confirm-token / lockfile freeze.")
    return failed("No gate on dependency installs; unvetted packages can be pulled in.")


def _check_force_push_policy(config: HarnessConfig) -> CheckOutcome:
    if config.has_hook("PreToolUse", "git-safety", matcher="Bash"):
        return passed("A git-safety hook covers force-push / history-rewrite.")
    if any(("force" in rule.lower() or "git-safety" in rule.lower()) for rule in config.rule_files):
        return partial(
            "Force-push policy is documented in rules/ but not enforced by a hook.",
            evidence=["advisory only"],
        )
    return failed("No force-push / history-rewrite guard or documented policy.")


CHECKS: list[Check] = [
    Check(
        id="HS-D4-01",
        dimension="D4",
        title="Push to protected branch effectively blocked",
        weight=5,
        evaluate=_check_push_to_protected_branch,
        severity=Severity.CRITICAL,
        is_gate=True,
        gate_cap=Grade.C,
        remediation=(
            "Block push to main/master via a PreToolUse Bash hook or a deny entry "
            "(not hard_deny alone under bypass)."
        ),
    ),
    Check(
        id="HS-D4-02",
        dimension="D4",
        title="Catastrophic deletion blocked",
        weight=4,
        evaluate=_check_catastrophic_deletion,
        severity=Severity.HIGH,
        remediation="Add a dangerous-command hook and deny rm -rf at shallow depth.",
    ),
    Check(
        id="HS-D4-03",
        dimension="D4",
        title="Destructive DB ops on non-local hosts blocked",
        weight=4,
        evaluate=_check_destructive_db,
        severity=Severity.HIGH,
        remediation=(
            "Add a PreToolUse Bash db-guard hook that blocks destructive ops on non-local hosts."
        ),
    ),
    Check(
        id="HS-D4-04",
        dimension="D4",
        title="Dependency-install / lockfile gate",
        weight=3,
        evaluate=_check_dependency_install_gate,
        severity=Severity.MEDIUM,
        remediation="Require a confirm-token for *-add/install, or add a lockfile-freeze guard.",
    ),
    Check(
        id="HS-D4-05",
        dimension="D4",
        title="Force-push / history-rewrite policy",
        weight=3,
        evaluate=_check_force_push_policy,
        severity=Severity.MEDIUM,
        detectability=Detectability.PARTIAL,
        remediation="Enforce a no-force-push policy via the git-safety hook, not docs alone.",
    ),
]

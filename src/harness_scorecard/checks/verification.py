"""D6 - Verification gates."""

from __future__ import annotations

from harness_scorecard.checks.base import Check, CheckOutcome, failed, partial, passed
from harness_scorecard.discovery import HarnessConfig
from harness_scorecard.models import Severity


def _check_task_completion_gate(config: HarnessConfig) -> CheckOutcome:
    if config.has_hook("TaskCompleted", "verify") or config.has_hook(
        "TaskCompleted", "task-completed"
    ):
        return passed("A TaskCompleted hook verifies work (compile/tests) before 'done'.")
    return failed("No TaskCompleted verification hook; 'done' can be claimed with no evidence.")


def _check_stop_quality_gate(config: HarnessConfig) -> CheckOutcome:
    has_stop = config.has_hook("Stop", "stop-gate")
    has_subagent = (
        config.has_hook("SubagentStop", "quality")
        or config.has_hook("SubagentStop", "review")
        or config.has_hook("SubagentStop", "subagent")
    )
    if has_stop and has_subagent:
        return passed("Stop and SubagentStop quality gates are both configured.")
    if has_stop or has_subagent:
        covered = "Stop" if has_stop else "SubagentStop"
        return partial(f"Only the {covered} quality gate is configured.")
    return failed("No Stop or SubagentStop quality gate; subagent output is trusted blindly.")


CHECKS: list[Check] = [
    Check(
        id="HS-D6-01",
        dimension="D6",
        title="Task-completion verification hook",
        weight=4,
        evaluate=_check_task_completion_gate,
        severity=Severity.HIGH,
        remediation="Add a TaskCompleted hook that runs the project's compile/test toolchain.",
    ),
    Check(
        id="HS-D6-02",
        dimension="D6",
        title="Stop / SubagentStop quality gate",
        weight=3,
        evaluate=_check_stop_quality_gate,
        severity=Severity.MEDIUM,
        remediation="Add a Stop gate and a SubagentStop reviewer to vet output before it lands.",
    ),
]

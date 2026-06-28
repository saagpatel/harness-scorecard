"""D4 (Codex) - Destructive-action & git safety.

Codex gates destructive commands through three independent layers: the approval policy (a human
prompt before a command runs), the filesystem sandbox (bounding what a command can damage), and
PreToolUse Bash hooks. The effective-floor gate caps the grade at C when all three are absent --
i.e. ``approval_policy = "never"`` and ``sandbox_mode = "danger-full-access"`` with no Bash hook.
"""

from __future__ import annotations

from harness_scorecard.checks.base import Check, CheckOutcome, failed, partial, passed
from harness_scorecard.discovery_codex import APPROVAL_NEVER, CodexConfig
from harness_scorecard.models import Detectability, Grade, Severity

# Compound needles only: bare "git"/"push"/"force"/"safety" over-credit unrelated hooks
# (push-notification, aws-safety-logger, "legitimate" containing "git", etc.).
_GIT_HOOK_NEEDLES = ("git-safety", "git-guard", "force-push", "destructive")
_GATED_APPROVALS = ("untrusted", "on-request")


def _has_bash_git_guard(config: CodexConfig) -> bool:
    return any(
        config.has_hook_on_tool("PreToolUse", needle, "Bash") for needle in _GIT_HOOK_NEEDLES
    )


def _destructive_floor(config: CodexConfig) -> CheckOutcome:
    sources: list[str] = []
    if not config.approval_disabled:
        sources.append(f"approval_policy={config.approval_policy}")
    if not config.sandbox_disabled:
        sources.append(f"sandbox_mode={config.sandbox_mode}")
    if _has_bash_git_guard(config):
        sources.append("hook:bash-git-safety")

    if len(sources) >= 2:  # noqa: PLR2004 - two independent layers = defense in depth
        return passed("Destructive actions are gated by multiple independent layers.", sources)
    if len(sources) == 1:
        return partial("Destructive actions rest on a single layer; add defense in depth.", sources)
    return failed(
        "No effective gate: danger-full-access sandbox with approval_policy=never and no Bash "
        "PreToolUse hook -- destructive commands run unchecked.",
    )


def _git_safety_hook(config: CodexConfig) -> CheckOutcome:
    if _has_bash_git_guard(config):
        return passed("A PreToolUse Bash hook guards git / destructive commands.")
    return failed("No PreToolUse Bash hook guards git pushes or destructive shell commands.")


def _approval_granularity(config: CodexConfig) -> CheckOutcome:
    policy = config.approval_policy
    if policy in _GATED_APPROVALS:
        return passed(f"approval_policy={policy} prompts before model-proposed commands run.")
    if policy == "on-failure":
        return partial(
            "approval_policy=on-failure only prompts after a command fails; the first run is "
            "ungated.",
        )
    if policy == APPROVAL_NEVER:
        return failed("approval_policy=never removes the human approval gate entirely.")
    return partial(f"Unrecognized approval_policy={policy!r}; cannot confirm it gates actions.")


CHECKS: list[Check[CodexConfig]] = [
    Check(
        id="CDX-D4-01",
        dimension="D4",
        title="Effective gate on destructive actions",
        weight=3,
        evaluate=_destructive_floor,
        severity=Severity.CRITICAL,
        detectability=Detectability.STATIC,
        is_gate=True,
        gate_cap=Grade.C,
        remediation=(
            "Keep approval_policy off 'never' or sandbox_mode off 'danger-full-access' (ideally "
            "both), and add a PreToolUse Bash hook for git/destructive commands."
        ),
    ),
    Check(
        id="CDX-D4-02",
        dimension="D4",
        title="Git-safety hook on the Bash lane",
        weight=2,
        evaluate=_git_safety_hook,
        severity=Severity.HIGH,
        detectability=Detectability.STATIC,
        remediation=(
            "Add a PreToolUse hook on the Bash matcher that blocks force-push and destructive rm."
        ),
    ),
    Check(
        id="CDX-D4-03",
        dimension="D4",
        title="Approval policy gates before execution",
        weight=2,
        evaluate=_approval_granularity,
        severity=Severity.HIGH,
        detectability=Detectability.STATIC,
        remediation=(
            "Set approval_policy to 'on-request' or 'untrusted' so commands are gated before "
            "they run."
        ),
    ),
]

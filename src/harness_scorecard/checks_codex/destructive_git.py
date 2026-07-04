"""D4 (Codex) - Destructive-action & git safety.

Codex gates destructive commands through three independent layers: the approval policy (a human
prompt before a command runs), the filesystem sandbox (bounding what a command can damage), and
PreToolUse Bash hooks. The effective-floor gate caps the grade at C when all three are absent --
i.e. ``approval_policy = "never"`` and ``sandbox_mode = "danger-full-access"`` with no Bash hook.
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
from harness_scorecard.models import Detectability, Grade, Severity

# Compound needles only: bare "git"/"push"/"force"/"safety" over-credit unrelated hooks
# (push-notification, aws-safety-logger, "legitimate" containing "git", etc.).
_GIT_HOOK_NEEDLES = ("git-safety", "git-guard", "force-push", "destructive")
# Only `untrusted` prompts deterministically for every model-proposed command.
# `on-request` leaves the ask to the model's own discretion, so it is a risk reducer,
# not a pre-run gate — crediting it as one disagreed with the claims audit (rubric 1.4.0).
_DETERMINISTIC_APPROVALS = ("untrusted",)
_DISCRETIONARY_APPROVALS = ("on-request",)

# trust_level=trusted suppresses approval prompts inside a directory. A handful of trusted
# project roots is a normal, bounded choice; a large set erodes the approval gate broadly.
_TRUST_PARTIAL_THRESHOLD = 25
_TRUST_FAIL_THRESHOLD = 100


def _has_bash_git_guard(config: CodexConfig) -> bool:
    return any(
        config.has_hook_on_tool("PreToolUse", needle, "Bash") for needle in _GIT_HOOK_NEEDLES
    )


def _destructive_floor(config: CodexConfig) -> CheckOutcome:
    sources: list[str] = []
    if not config.approval_disabled:
        # Still a defense-in-depth layer, but a discretionary one is labeled so the
        # evidence never overstates it as a deterministic gate.
        qualifier = (
            "" if config.approval_policy in _DETERMINISTIC_APPROVALS else " (model-discretionary)"
        )
        sources.append(f"approval_policy={config.approval_policy}{qualifier}")
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
    if policy in _DETERMINISTIC_APPROVALS:
        return passed(f"approval_policy={policy} prompts before every model-proposed command.")
    if policy in _DISCRETIONARY_APPROVALS:
        return partial(
            "approval_policy=on-request leaves the approval ask to the model's discretion; "
            "a risk reducer, not a deterministic pre-run gate.",
        )
    if policy == "on-failure":
        return partial(
            "approval_policy=on-failure only prompts after a command fails; the first run is "
            "ungated.",
        )
    if policy == APPROVAL_NEVER:
        return failed("approval_policy=never removes the human approval gate entirely.")
    return partial(f"Unrecognized approval_policy={policy!r}; cannot confirm it gates actions.")


def _trusted_project_breadth(config: CodexConfig) -> CheckOutcome:
    if config.approval_disabled:
        return not_applicable(
            "approval_policy=never already removes the approval gate globally, so per-project "
            "trust_level adds no further erosion.",
        )
    trusted = config.trusted_projects
    count = len(trusted)
    if count == 0:
        return passed("No projects set trust_level=trusted; the approval gate applies everywhere.")
    sample = [f"trusted: {path}" for path in trusted[:3]]
    if count > _TRUST_FAIL_THRESHOLD:
        return failed(
            f"{count} projects are marked trust_level=trusted; the approval gate is eroded across "
            f"a very broad set of directories.",
            sample,
        )
    if count > _TRUST_PARTIAL_THRESHOLD:
        return partial(
            f"{count} projects are trust_level=trusted; each suppresses approval prompts in its "
            f"directory. Prune the set to the few you genuinely trust.",
            sample,
        )
    return passed(
        f"A bounded set of {count} trusted project(s); the approval gate still applies elsewhere.",
        sample,
    )


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
        dispatcher_evidence=(
            r"force[_\s-]?push",
            r"git\s+push\b[^\n]*--force",
            r"git\s+(?:reset|rebase|filter-branch|filter-repo)\b",
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
            "Set approval_policy to 'untrusted' for a deterministic pre-run gate; 'on-request' "
            "leaves the ask to the model's discretion and earns partial credit only."
        ),
    ),
    Check(
        id="CDX-D4-04",
        dimension="D4",
        title="Trusted-project breadth is bounded",
        weight=2,
        evaluate=_trusted_project_breadth,
        severity=Severity.MEDIUM,
        detectability=Detectability.STATIC,
        remediation=(
            "Prune [projects.*] entries with trust_level='trusted' to the few directories you "
            "genuinely trust; each one suppresses approval prompts in that directory."
        ),
    ),
]

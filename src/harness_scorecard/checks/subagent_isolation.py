"""D7 - Subagent isolation & governance."""

from __future__ import annotations

from harness_scorecard.checks.base import Check, CheckOutcome, failed, partial, passed
from harness_scorecard.discovery import HarnessConfig
from harness_scorecard.models import Severity

_SUBAGENT_MODEL_ENV = "CLAUDE_CODE_SUBAGENT_MODEL"
_MCP_PROBE = "mcp__example_server__example_tool"


def _check_guards_are_global(config: HarnessConfig) -> CheckOutcome:
    # A subagent inherits the parent PreToolUse floor only if that floor covers the lanes a
    # subagent uses: Agent dispatch, Bash, and MCP. Bash-only matchers leave lanes open.
    lanes = {
        "Agent": config.matches_tool("PreToolUse", "Agent"),
        "Bash": config.matches_tool("PreToolUse", "Bash"),
        "MCP": config.matches_tool("PreToolUse", _MCP_PROBE),
    }
    covered = [name for name, ok in lanes.items() if ok]
    if len(covered) == len(lanes):
        return passed("PreToolUse guards cover the Agent, Bash, and MCP lanes subagents use.")
    if covered:
        return partial(f"PreToolUse guards cover {', '.join(covered)} but not every subagent lane.")
    return failed(
        "PreToolUse guards do not cover the lanes subagents use; the floor may not inherit."
    )


def _check_no_subagent_model_pin(config: HarnessConfig) -> CheckOutcome:
    if _SUBAGENT_MODEL_ENV in config.env:
        return failed(
            f"env pins {_SUBAGENT_MODEL_ENV}, forcing every subagent to one model.",
            evidence=[f"{_SUBAGENT_MODEL_ENV} is set"],
        )
    return passed(f"No {_SUBAGENT_MODEL_ENV} env pin; per-dispatch model selection is preserved.")


def _check_scope_governance(config: HarnessConfig) -> CheckOutcome:
    has_linter = config.has_hook("PreToolUse", "scope-linter", matcher="Agent") or config.has_hook(
        "PreToolUse", "subagent-scope", matcher="Agent"
    )
    has_reviewer = config.has_hook("SubagentStop", "quality") or config.has_hook(
        "SubagentStop", "review"
    )
    if has_linter and has_reviewer:
        return passed("A subagent scope linter and a SubagentStop reviewer both govern scope.")
    if has_linter or has_reviewer:
        covered = "scope linter" if has_linter else "SubagentStop reviewer"
        return partial(f"Only the {covered} governs subagent scope.")
    return failed("No subagent scope governance; a builder can edit beyond its declared slice.")


CHECKS: list[Check] = [
    Check(
        id="HS-D7-01",
        dimension="D7",
        title="Guards are global (subagents inherit)",
        weight=4,
        evaluate=_check_guards_are_global,
        severity=Severity.HIGH,
        remediation=(
            "Use top-level PreToolUse matchers covering Agent|Bash|mcp__.* so subagents "
            "inherit the floor."
        ),
    ),
    Check(
        id="HS-D7-02",
        dimension="D7",
        title="No subagent-model env override",
        weight=2,
        evaluate=_check_no_subagent_model_pin,
        severity=Severity.LOW,
        remediation=f"Remove {_SUBAGENT_MODEL_ENV} from env so the Agent model param is honored.",
    ),
    Check(
        id="HS-D7-03",
        dimension="D7",
        title="Subagent scope linter / reviewer",
        weight=3,
        evaluate=_check_scope_governance,
        severity=Severity.MEDIUM,
        remediation="Add a PreToolUse Agent scope linter and a SubagentStop reviewer.",
        # Only the PreToolUse-Agent scope-linter half is dispatcher-scannable; the SubagentStop
        # reviewer half is on an unscanned event, so detection lifts FAIL->PARTIAL, never to PASS.
        dispatcher_evidence=(
            r"scope[_-]?linter",
            r"subagent[_-]?scope",
            r"scope[_-]?(?:creep|guard|govern)",
        ),
    ),
]

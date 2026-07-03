"""D10 - Observability / audit trail."""

from __future__ import annotations

from harness_scorecard.checks.base import Check, CheckOutcome, failed, partial, passed
from harness_scorecard.checks.receipt_discipline import RECEIPT_DISCIPLINE_CHECK
from harness_scorecard.discovery import HarnessConfig
from harness_scorecard.models import Severity

_MCP_PROBE = "mcp__example_server__example_tool"


def _logs_lane(config: HarnessConfig, tool_name: str) -> bool:
    """A PostToolUse audit-log hook registered under a matcher covering ``tool_name``."""
    return config.has_hook_on_tool("PostToolUse", "audit", tool_name) or config.has_hook_on_tool(
        "PostToolUse", "calls-log", tool_name
    )


def _check_tool_audit_logging(config: HarnessConfig) -> CheckOutcome:
    has_bash_log = _logs_lane(config, "Bash")
    has_mcp_log = _logs_lane(config, _MCP_PROBE)
    if has_bash_log and has_mcp_log:
        return passed("Tool-call audit logs cover both the Bash and MCP lanes.")
    if has_bash_log or has_mcp_log:
        covered = "Bash" if has_bash_log else "MCP"
        return partial(f"Only the {covered} lane has tool-call audit logging.")
    return failed("No tool-call audit logging; agent/injection actions can't be reconstructed.")


def _logs_event(config: HarnessConfig, event: str) -> bool:
    """A hook under ``event`` whose command names a log/audit handler."""
    return config.has_hook(event, "log") or config.has_hook(event, "audit")


def _check_failure_logging(config: HarnessConfig) -> CheckOutcome:
    has_denial = _logs_event(config, "PermissionDenied")
    has_failure = _logs_event(config, "PostToolUseFailure") or _logs_event(config, "StopFailure")
    if has_denial and has_failure:
        return passed("Denied calls and tool failures are both logged.")
    if has_denial or has_failure:
        covered = "permission-denial" if has_denial else "tool-failure"
        return partial(f"Only {covered} logging is configured.")
    return failed("No denial/failure logging; silent failures leave no audit trail.")


CHECKS: list[Check] = [
    Check(
        id="HS-D10-01",
        dimension="D10",
        title="Tool-call audit logging",
        weight=3,
        evaluate=_check_tool_audit_logging,
        severity=Severity.MEDIUM,
        remediation="Add PostToolUse audit-log hooks on both the Bash and mcp__.* lanes.",
        dispatcher_evidence=(
            r"\bappend\w*audit\b",
            r"\baudit[_-]?log\b",
            r"audit[\w-]*\.jsonl\b",
        ),
    ),
    Check(
        id="HS-D10-02",
        dimension="D10",
        title="Failure & denial logging",
        weight=2,
        evaluate=_check_failure_logging,
        severity=Severity.LOW,
        remediation="Add PermissionDenied, PostToolUseFailure, and StopFailure log hooks.",
    ),
    RECEIPT_DISCIPLINE_CHECK,
]

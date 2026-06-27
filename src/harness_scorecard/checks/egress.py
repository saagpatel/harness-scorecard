"""D2 - Egress / exfiltration control."""

from __future__ import annotations

from harness_scorecard.checks.base import Check, CheckOutcome, failed, partial, passed
from harness_scorecard.discovery import HarnessConfig
from harness_scorecard.models import Severity


def _check_network_egress_guard(config: HarnessConfig) -> CheckOutcome:
    has_guard = config.has_hook(
        "PreToolUse", "bash-egress-guard", matcher="Bash"
    ) or config.has_hook("PreToolUse", "remote-command-guard", matcher="Bash")
    if has_guard:
        return passed("A PreToolUse Bash hook inspects outbound network commands.")
    if config.deny_matches("wget"):
        return partial(
            "wget is denied, but there is no egress guard inspecting curl and friends.",
            evidence=["no bash-egress-guard / remote-command-guard hook"],
        )
    return failed(
        "No network-egress guard; a curl --data @secret to an attacker host is unblocked.",
    )


def _check_mcp_resource_enumeration(config: HarnessConfig) -> CheckOutcome:
    has_list = config.deny_matches("ListMcpResourcesTool")
    has_read = config.deny_matches("ReadMcpResourceTool")
    if has_list and has_read:
        return passed("MCP resource enumeration tools are denied.")
    if has_list or has_read:
        return partial("Only one of the MCP resource enumeration tools is denied.")
    return failed("MCP resource enumeration tools are not denied; bulk resource dump is possible.")


def _check_mcp_output_cap(config: HarnessConfig) -> CheckOutcome:
    raw = config.env.get("MAX_MCP_OUTPUT_TOKENS", "").strip()
    if raw.isdigit() and int(raw) > 0:
        return passed("MCP output is capped via MAX_MCP_OUTPUT_TOKENS.")
    return failed("MCP output is uncapped; an oversized payload can flood context or exfiltrate.")


CHECKS: list[Check] = [
    Check(
        id="HS-D2-01",
        dimension="D2",
        title="Network-egress guard on Bash",
        weight=4,
        evaluate=_check_network_egress_guard,
        severity=Severity.HIGH,
        remediation="Add a PreToolUse Bash hook inspecting curl/wget for exfiltration; deny wget.",
    ),
    Check(
        id="HS-D2-02",
        dimension="D2",
        title="MCP resource enumeration denied",
        weight=3,
        evaluate=_check_mcp_resource_enumeration,
        severity=Severity.MEDIUM,
        remediation="Deny ListMcpResourcesTool(*) and ReadMcpResourceTool(*) in permissions.deny.",
    ),
    Check(
        id="HS-D2-03",
        dimension="D2",
        title="MCP output cap set",
        weight=2,
        evaluate=_check_mcp_output_cap,
        severity=Severity.LOW,
        remediation="Set env MAX_MCP_OUTPUT_TOKENS to bound MCP payload size.",
    ),
]

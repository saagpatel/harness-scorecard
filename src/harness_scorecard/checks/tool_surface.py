"""D3 - Tool-surface & inbound-injection defense."""

from __future__ import annotations

from harness_scorecard.checks.base import Check, CheckOutcome, failed, partial, passed
from harness_scorecard.discovery import HarnessConfig
from harness_scorecard.models import Detectability, Severity

# Representative tool names used to probe whether a PreToolUse matcher covers a lane.
_MCP_PROBE = "mcp__example_server__example_tool"
_FILE_LANE_PROBES = ("Read", "Edit", "Write")

# Each inbound vector: (label, sentinel hook name, a tool that proves the matcher's lane).
_INBOUND_VECTORS = (
    ("mcp-output", "content-sentinel", _MCP_PROBE),
    ("web", "webfetch-sentinel", "WebFetch"),
    ("file-read", "read-grep-sentinel", "Read"),
)


def _covers_file_lane(config: HarnessConfig) -> bool:
    return any(config.matches_tool("PreToolUse", probe) for probe in _FILE_LANE_PROBES)


def _check_mcp_lane_gated(config: HarnessConfig) -> CheckOutcome:
    if config.matches_tool("PreToolUse", _MCP_PROBE):
        return passed("The MCP tool lane is gated by a PreToolUse matcher.")
    return failed(
        "The MCP lane is ungated; MCP calls bypass the PreToolUse guard stack entirely.",
        evidence=["no PreToolUse matcher covers the mcp__ lane"],
    )


def _check_inbound_sentinels(config: HarnessConfig) -> CheckOutcome:
    # A sentinel only counts if registered under a matcher covering its own lane.
    present = [
        name
        for name, hook, lane in _INBOUND_VECTORS
        if config.has_hook_on_tool("PostToolUse", hook, lane)
    ]
    if len(present) == len(_INBOUND_VECTORS):
        return passed("Inbound-content sentinels cover all three injection vectors.")
    if present:
        return partial(
            f"Inbound sentinels cover {len(present)}/{len(_INBOUND_VECTORS)} vectors: "
            f"{', '.join(present)}.",
            evidence=[f"present: {', '.join(present)}"],
        )
    return failed(
        "No inbound-content sentinels; injected text from MCP/web/file output is untagged.",
    )


def _check_matcher_breadth(config: HarnessConfig) -> CheckOutcome:
    covers_mcp = config.matches_tool("PreToolUse", _MCP_PROBE)
    covers_file = _covers_file_lane(config)
    if covers_mcp and covers_file:
        return passed("PreToolUse guards reach beyond Bash to the MCP and file lanes.")
    if covers_mcp or covers_file:
        lane = "MCP" if covers_mcp else "file"
        return partial(f"PreToolUse guards reach the {lane} lane but not all non-Bash lanes.")
    return failed("PreToolUse guards are Bash-only; the MCP and file lanes are ungated.")


CHECKS: list[Check] = [
    Check(
        id="HS-D3-01",
        dimension="D3",
        title="MCP lane is gated",
        weight=5,
        evaluate=_check_mcp_lane_gated,
        severity=Severity.HIGH,
        remediation=(
            "Add a PreToolUse hook with a matcher covering mcp__.* so the MCP lane is guarded."
        ),
    ),
    Check(
        id="HS-D3-02",
        dimension="D3",
        title="Inbound-content sentinels present",
        weight=4,
        evaluate=_check_inbound_sentinels,
        severity=Severity.HIGH,
        detectability=Detectability.PARTIAL,
        remediation=(
            "Add PostToolUse sentinels on all three inbound vectors: MCP output, "
            "web fetch/search, and file read/grep."
        ),
        dispatcher_evidence=(
            r"content[_-]sentinel",
            r"\binjection[_-]?(?:signal|pattern|guard|screen|re)s?\b",
            r"\bsanitiz\w*[_-](?:tool|output|input|content|inbound|prompt)\b",
        ),
    ),
    Check(
        id="HS-D3-03",
        dimension="D3",
        title="PreToolUse matcher breadth",
        weight=3,
        evaluate=_check_matcher_breadth,
        severity=Severity.MEDIUM,
        remediation="Broaden PreToolUse matchers to Bash|mcp__.*|Read|Edit|Write, not Bash alone.",
    ),
]

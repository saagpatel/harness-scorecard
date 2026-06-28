"""D3 (Codex) - Tool-surface & inbound-injection defense.

Two complementary controls: every tool call should pass a gate (a PreToolUse or
PermissionRequest hook), and inbound content (user prompts, tool output) should be screened for
prompt-injection before it steers the agent (a UserPromptSubmit or content-sanitization hook).
"""

from __future__ import annotations

from harness_scorecard.checks.base import Check, CheckOutcome, failed, passed
from harness_scorecard.discovery_codex import CodexConfig
from harness_scorecard.models import Detectability, Severity

# Compound/specific terms only ("content-sentinel" not bare "sentinel", "injection" not "inject");
# "redact" is intentionally a D1 credential needle, not an injection-screening one.
_SANITIZE_NEEDLES = ("sanitize", "content-sentinel", "injection", "content-guard")
# Inbound content arrives via a submitted prompt or a tool result, so screen either lane.
_SANITIZE_EVENTS = ("UserPromptSubmit", "PreToolUse")


def _has_sanitization_hook(config: CodexConfig) -> bool:
    return any(
        config.has_hook(event, needle) for event in _SANITIZE_EVENTS for needle in _SANITIZE_NEEDLES
    )


def _tool_call_gating(config: CodexConfig) -> CheckOutcome:
    events = [e for e in ("PreToolUse", "PermissionRequest") if config.has_event(e)]
    if events:
        # A registered hook on these lanes intercepts every matching tool call before it runs;
        # whether its policy blocks is its own (statically opaque) logic.
        return passed("A hook intercepts tool calls before they run.", evidence=events)
    return failed(
        "No PreToolUse or PermissionRequest hook intercepts tool calls; the agent's tool surface "
        "is ungoverned.",
    )


def _injection_defense(config: CodexConfig) -> CheckOutcome:
    if _has_sanitization_hook(config):
        return passed(
            "A content-sanitization hook screens inbound prompts/tool output for injection."
        )
    return failed(
        "No content-sanitization hook (on UserPromptSubmit or PreToolUse) defends against prompt "
        "injection in inbound content.",
    )


CHECKS: list[Check[CodexConfig]] = [
    Check(
        id="CDX-D3-01",
        dimension="D3",
        title="Tool calls pass through a gate",
        weight=2,
        evaluate=_tool_call_gating,
        severity=Severity.HIGH,
        detectability=Detectability.STATIC,
        remediation="Add a PreToolUse (or PermissionRequest) hook so every tool call is screened.",
    ),
    Check(
        id="CDX-D3-02",
        dimension="D3",
        title="Inbound content is screened for injection",
        weight=2,
        evaluate=_injection_defense,
        severity=Severity.HIGH,
        detectability=Detectability.STATIC,
        remediation=(
            "Add a UserPromptSubmit hook (or a content-sanitization PreToolUse hook) to screen "
            "inbound prompts and tool output for prompt-injection."
        ),
    ),
]

"""D3 (Codex) - Tool-surface & inbound-injection defense.

Two complementary controls: every tool call should pass a gate (a PreToolUse or
PermissionRequest hook), and inbound content (user prompts, tool output) should be screened for
prompt-injection before it steers the agent (a UserPromptSubmit or content-sanitization hook).
"""

from __future__ import annotations

from harness_scorecard.checks.base import Check, CheckOutcome, failed, partial, passed
from harness_scorecard.discovery_codex import CodexConfig
from harness_scorecard.models import Detectability, Severity

# Compound/specific terms only ("content-sentinel" not bare "sentinel", "injection" not "inject");
# "redact" is intentionally a D1 credential needle, not an injection-screening one.
_SANITIZE_NEEDLES = ("sanitize", "content-sentinel", "injection", "content-guard")
# Inbound content arrives via a submitted prompt or a tool result, so screen either lane.
_PROMPT_EVENTS = ("UserPromptSubmit",)
_RESULT_EVENTS = ("PostToolUse",)


def _has_screening(config: CodexConfig, events: tuple[str, ...]) -> bool:
    if events == _RESULT_EVENTS:
        return any(
            hook.event == "PostToolUse"
            and not hook.async_hook
            and hook.matcher.strip() in ("", "*")
            and any(needle in hook.command for needle in _SANITIZE_NEEDLES)
            for hook in config.hooks
        )
    return any(
        hook.event == event
        and not hook.async_hook
        and any(needle in hook.command for needle in _SANITIZE_NEEDLES)
        for event in events
        for hook in config.hooks
    )


def _tool_call_gating(config: CodexConfig) -> CheckOutcome:
    hooks = [
        hook
        for hook in config.hooks
        if hook.event in ("PreToolUse", "PermissionRequest")
        and not hook.async_hook
        and hook.command.strip()
    ]
    universal = [hook for hook in hooks if hook.matcher.strip() in ("", "*")]
    if universal:
        # A registered hook on these lanes intercepts every matching tool call before it runs;
        # whether its policy blocks is its own (statically opaque) logic.
        return passed("A valid universal hook intercepts tool calls before they run.")
    if hooks:
        return partial(
            "Tool-call hooks cover only selected tools; universal coverage is not established.",
            evidence=[f"matcher: {hook.matcher or '(empty)'}" for hook in hooks],
        )
    return failed(
        "No PreToolUse or PermissionRequest hook intercepts tool calls; the agent's tool surface "
        "is ungoverned.",
    )


def _injection_defense(config: CodexConfig) -> CheckOutcome:
    prompt = _has_screening(config, _PROMPT_EVENTS)
    results = _has_screening(config, _RESULT_EVENTS)
    if prompt and results:
        return passed("Prompt screening and tool-result screening both cover inbound injection.")
    if prompt or results:
        covered = "prompts" if prompt else "tool results"
        missing = "tool results" if prompt else "prompts"
        return partial(
            f"Inbound screening covers {covered}, but {missing} are not screened for injection."
        )
    return failed(
        "Neither prompts nor tool results have content-sanitization screening for injection.",
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
        dispatcher_evidence=(
            r"\binjection_signals\s*\(",
            r"\bINJECTION_RE\b",
            r"\bINJECTION_PATTERNS\b",
        ),
    ),
]

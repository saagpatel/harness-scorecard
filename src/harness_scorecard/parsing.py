"""Shared, harness-agnostic parsing primitives for the discovery adapters.

Both the Claude Code (``discovery``) and Codex (``discovery_codex``) adapters read config into
typed structures and query a flat list of hook entries. The coercion helpers, the hook
flattener, and the regex matcher logic live here so the security-relevant matcher rules have a
single source of truth across adapters rather than drifting between two copies.
"""

from __future__ import annotations

import json
import re
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class HookEntry:
    """One registered hook command under a lifecycle event."""

    event: str
    matcher: str
    command: str


def read_json(path: Path) -> dict[str, Any]:
    """Parse a JSON file to a dict, degrading to ``{}`` on any read/parse error."""
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def as_dict(value: Any) -> dict[str, Any]:
    """Coerce a parsed value to a dict, treating wrong types as empty (no crash)."""
    return value if isinstance(value, dict) else {}


def as_str_list(value: Any) -> list[str]:
    """Coerce to a list of strings. A bare string is malformed -> empty (never char-iterated)."""
    return [str(item) for item in value] if isinstance(value, list) else []


def flatten_hooks(hooks_section: Any) -> list[HookEntry]:
    """Flatten a hooks section (``{event: [{matcher, hooks: [{command}]}]}``) into entries.

    The schema is shared: Claude Code nests it under ``settings.json`` and Codex stores it in a
    standalone ``hooks.json``, but the group/command shape is identical.
    """
    entries: list[HookEntry] = []
    if not isinstance(hooks_section, dict):
        return entries
    for event, groups in hooks_section.items():
        if not isinstance(groups, list):
            continue
        for group in groups:
            if not isinstance(group, dict):
                continue
            matcher = str(group.get("matcher", ""))
            for hook in group.get("hooks", []):
                if isinstance(hook, dict) and "command" in hook:
                    entries.append(  # noqa: PERF401 - guarded nested build reads clearer as a loop
                        HookEntry(str(event), matcher, str(hook["command"]))
                    )
    return entries


def matcher_covers(registered: str, wanted: str | None) -> bool:
    """Whether a registered matcher covers a wanted lane (substring or universal)."""
    if wanted is None:
        return True
    registered = registered.strip()
    if registered in ("", "*"):
        return True
    return wanted.lower() in registered.lower()


def matcher_matches_tool(matcher: str, tool_name: str) -> bool:
    """Whether a single matcher (a regex) matches a concrete tool name.

    A universal matcher (empty / ``*``) matches everything; an invalid regex falls back to a
    substring test.
    """
    matcher = matcher.strip()
    if matcher in ("", "*"):
        return True
    try:
        return re.search(matcher, tool_name) is not None
    except re.error:
        return matcher.lower() in tool_name.lower()


def hook_present(
    hooks: Sequence[HookEntry],
    event: str,
    command_contains: str,
    matcher: str | None = None,
) -> bool:
    """True if a hook under ``event`` whose command matches also covers ``matcher``'s lane."""
    return any(
        hook.event == event
        and command_contains in hook.command
        and matcher_covers(hook.matcher, matcher)
        for hook in hooks
    )


def hook_on_tool(
    hooks: Sequence[HookEntry],
    event: str,
    command_contains: str,
    tool_name: str,
) -> bool:
    """Like :func:`hook_present`, but the matcher must cover ``tool_name`` (regex match)."""
    return any(
        hook.event == event
        and command_contains in hook.command
        and matcher_matches_tool(hook.matcher, tool_name)
        for hook in hooks
    )


def matches_tool(hooks: Sequence[HookEntry], event: str, tool_name: str) -> bool:
    """True if any hook under ``event`` has a matcher that matches ``tool_name``."""
    return any(
        hook.event == event and matcher_matches_tool(hook.matcher, tool_name) for hook in hooks
    )


def event_present(hooks: Sequence[HookEntry], event: str) -> bool:
    """True when at least one hook is registered under ``event`` (any matcher)."""
    return any(hook.event == event for hook in hooks)

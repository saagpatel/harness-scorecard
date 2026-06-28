"""Read a harness directory into a queryable :class:`HarnessConfig`.

Read-only: discovery never writes to the audited harness. Parsing failures degrade
gracefully (a malformed sub-surface yields an empty inventory, not a crash) so a single
bad file can't blank the whole grade.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from harness_scorecard.parsing import (
    HookEntry,
    event_present,
    hook_on_tool,
    hook_present,
)
from harness_scorecard.parsing import as_dict as _as_dict
from harness_scorecard.parsing import as_str_list as _as_str_list
from harness_scorecard.parsing import flatten_hooks as _flatten_hooks
from harness_scorecard.parsing import matches_tool as _matches_tool
from harness_scorecard.parsing import read_json as _read_json

BYPASS_MODE = "bypassPermissions"
HARNESS_TYPE_CLAUDE_CODE = "claude-code"

__all__ = ["HARNESS_TYPE_CLAUDE_CODE", "HarnessConfig", "HookEntry", "load_harness"]


@dataclass(slots=True)
class HarnessConfig:
    """Everything the scorer needs, parsed once from a harness directory."""

    root: Path
    harness_type: str
    default_mode: str
    deny: list[str]
    allow: list[str]
    env: dict[str, str]
    hard_deny: list[str]
    hooks: list[HookEntry]
    rule_files: list[str]
    agent_files: list[str]
    skill_dirs: list[str]
    has_claude_md: bool
    raw_settings: dict[str, Any] = field(default_factory=dict)

    # --- enforcement-mode helpers --------------------------------------------------

    @property
    def is_bypass(self) -> bool:
        """True when the harness runs in bypass mode (``hard_deny`` is then inert)."""
        return self.default_mode == BYPASS_MODE

    @property
    def hard_deny_effective(self) -> bool:
        """``autoMode.hard_deny`` only enforces when NOT in bypass mode (rubric §3)."""
        return not self.is_bypass

    # --- query helpers -------------------------------------------------------------

    def deny_matches(self, *needles: str) -> bool:
        """True if any ``permissions.deny`` entry contains any of ``needles``."""
        return any(needle in entry for entry in self.deny for needle in needles)

    def has_hook(self, event: str, command_contains: str, matcher: str | None = None) -> bool:
        """True if a hook under ``event`` whose command matches also covers ``matcher``'s lane."""
        return hook_present(self.hooks, event, command_contains, matcher)

    def matches_tool(self, event: str, tool_name: str) -> bool:
        """True if any hook under ``event`` has a matcher that matches ``tool_name``."""
        return _matches_tool(self.hooks, event, tool_name)

    def has_hook_on_tool(self, event: str, command_contains: str, tool_name: str) -> bool:
        """True if a hook under ``event`` whose command matches also covers ``tool_name``'s lane.

        The matcher is required to cover the given tool's lane (regex match), so a sentinel
        registered on the wrong lane is not credited.
        """
        return hook_on_tool(self.hooks, event, command_contains, tool_name)

    def env_flag_enabled(self, key: str) -> bool:
        """True when an env var is set to a truthy value (``1``/``true``)."""
        return str(self.env.get(key, "")).strip().lower() in ("1", "true", "yes")

    def has_setting(self, key: str) -> bool:
        """True when a top-level settings key is present with a non-null value."""
        return self.raw_settings.get(key) is not None

    def has_event(self, event: str) -> bool:
        """True when at least one hook is registered under ``event`` (any matcher)."""
        return event_present(self.hooks, event)


def _merge_settings(base: dict[str, Any], local: dict[str, Any]) -> dict[str, Any]:
    """Shallow-merge ``settings.local.json`` over ``settings.json``.

    Scalars/dicts: local wins. ``permissions.deny``/``allow`` and ``hooks`` are unioned so
    a guard declared in either file is credited.
    """
    if not local:
        return base
    merged: dict[str, Any] = {**base, **local}
    base_perms = _as_dict(base.get("permissions"))
    local_perms = _as_dict(local.get("permissions"))
    if base_perms or local_perms:
        merged["permissions"] = {**base_perms, **local_perms}
        for key in ("deny", "allow"):
            combined = _as_str_list(base_perms.get(key)) + _as_str_list(local_perms.get(key))
            if combined:
                merged["permissions"][key] = list(dict.fromkeys(combined))
    base_hooks = _as_dict(base.get("hooks"))
    local_hooks = _as_dict(local.get("hooks"))
    if base_hooks or local_hooks:
        merged_hooks: dict[str, Any] = {**base_hooks}
        for event, groups in local_hooks.items():
            merged_hooks[event] = list(merged_hooks.get(event, [])) + list(groups)
        merged["hooks"] = merged_hooks
    return merged


def _normalize_hard_deny(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value]
    if isinstance(value, str):
        return [line.strip() for line in value.splitlines() if line.strip()]
    return []


def _inventory_dir(path: Path, suffix: str) -> list[str]:
    try:
        return sorted(p.name for p in path.iterdir() if p.is_file() and p.name.endswith(suffix))
    except OSError:
        return []


def _inventory_subdirs(path: Path) -> list[str]:
    try:
        return sorted(p.name for p in path.iterdir() if p.is_dir())
    except OSError:
        return []


def load_harness(root: Path | str) -> HarnessConfig:
    """Parse a Claude Code harness directory into a :class:`HarnessConfig`.

    Raises ``FileNotFoundError`` if neither ``settings.json`` nor ``settings.local.json``
    exists at ``root`` (nothing to grade).
    """
    root = Path(root)
    settings_path = root / "settings.json"
    local_path = root / "settings.local.json"
    if not settings_path.exists() and not local_path.exists():
        msg = f"No settings.json or settings.local.json found at {root}"
        raise FileNotFoundError(msg)

    settings = _as_dict(_merge_settings(_read_json(settings_path), _read_json(local_path)))
    permissions = _as_dict(settings.get("permissions"))
    auto_mode = _as_dict(settings.get("autoMode"))

    return HarnessConfig(
        root=root,
        harness_type=HARNESS_TYPE_CLAUDE_CODE,
        default_mode=str(permissions.get("defaultMode", "default")),
        deny=_as_str_list(permissions.get("deny")),
        allow=_as_str_list(permissions.get("allow")),
        env={str(k): str(v) for k, v in _as_dict(settings.get("env")).items()},
        hard_deny=_normalize_hard_deny(auto_mode.get("hard_deny")),
        hooks=_flatten_hooks(settings.get("hooks", {})),
        rule_files=_inventory_dir(root / "rules", ".md"),
        agent_files=_inventory_dir(root / "agents", ".md"),
        skill_dirs=_inventory_subdirs(root / "skills"),
        has_claude_md=(root / "CLAUDE.md").is_file(),
        raw_settings=settings,
    )

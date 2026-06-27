"""Read a harness directory into a queryable :class:`HarnessConfig`.

Read-only: discovery never writes to the audited harness. Parsing failures degrade
gracefully (a malformed sub-surface yields an empty inventory, not a crash) so a single
bad file can't blank the whole grade.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

BYPASS_MODE = "bypassPermissions"
HARNESS_TYPE_CLAUDE_CODE = "claude-code"


@dataclass(slots=True)
class HookEntry:
    """One registered hook command under a lifecycle event."""

    event: str
    matcher: str
    command: str


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

    def has_hook(
        self,
        event: str,
        command_contains: str,
        matcher: str | None = None,
    ) -> bool:
        """True if a hook is registered under ``event`` whose command matches.

        ``matcher`` (when given) is satisfied if it appears in the registered matcher
        string, or the matcher is universal (empty / ``*``).
        """
        for hook in self.hooks:
            if hook.event != event or command_contains not in hook.command:
                continue
            if self._matcher_covers(hook.matcher, matcher):
                return True
        return False

    @staticmethod
    def _matcher_covers(registered: str, wanted: str | None) -> bool:
        if wanted is None:
            return True
        registered = registered.strip()
        if registered in ("", "*"):
            return True
        return wanted.lower() in registered.lower()

    def env_flag_enabled(self, key: str) -> bool:
        """True when an env var is set to a truthy value (``1``/``true``)."""
        return str(self.env.get(key, "")).strip().lower() in ("1", "true", "yes")


def _read_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


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


def _flatten_hooks(hooks_section: dict[str, Any]) -> list[HookEntry]:
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
                        HookEntry(event, matcher, str(hook["command"]))
                    )
    return entries


def _as_dict(value: Any) -> dict[str, Any]:
    """Coerce a parsed JSON value to a dict, treating wrong types as empty (no crash)."""
    return value if isinstance(value, dict) else {}


def _as_str_list(value: Any) -> list[str]:
    """Coerce to a list of strings. A bare string is malformed -> empty (never char-iterated)."""
    return [str(item) for item in value] if isinstance(value, list) else []


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

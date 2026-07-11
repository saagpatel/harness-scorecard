"""Read a Codex harness directory into a queryable :class:`CodexConfig`.

Codex's guard surface differs from Claude Code's: instead of a permission mode plus
``permissions.deny`` globs, safety is governed by a filesystem **sandbox** (``sandbox_mode``),
a human **approval policy** (``approval_policy``), per-project **trust levels**, and a
``hooks.json`` whose schema matches Claude Code's. The effective-floor analog of Claude Code's
bypass mode is ``sandbox_mode = "danger-full-access"`` (sandbox inert) combined with
``approval_policy = "never"`` (no human gate) — together they let the agent act unchecked.

Read-only and dependency-free: ``config.toml`` is parsed with the stdlib ``tomllib``. Parsing
failures degrade to an empty surface rather than crashing the grade.
"""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from harness_scorecard.caveats import detect_dispatcher_caveats
from harness_scorecard.parsing import (
    HookEntry,
    event_present,
    hook_on_tool,
    hook_present,
)
from harness_scorecard.parsing import as_dict as _as_dict
from harness_scorecard.parsing import as_str_list as _as_str_list
from harness_scorecard.parsing import flatten_hooks as _flatten_hooks
from harness_scorecard.parsing import read_json as _read_json

HARNESS_TYPE_CODEX = "codex"

# sandbox_mode values (most → least restrictive).
SANDBOX_READ_ONLY = "read-only"
SANDBOX_WORKSPACE_WRITE = "workspace-write"
SANDBOX_DANGER = "danger-full-access"

# approval_policy values.
APPROVAL_NEVER = "never"

# A project trust_level that suppresses approval prompts inside that directory.
TRUST_TRUSTED = "trusted"

# Env var names that look like secrets; Codex's default excludes scrub these, but an explicit
# shell_environment_policy.set can re-introduce them into the subprocess environment. The
# lookarounds treat letters as the boundary (env names use ``_``/digits as separators) so
# AWS_SECRET_ACCESS_KEY matches while MONKEY / TURKEY do not.
_SECRET_ENV_HINT = re.compile(
    r"(?<![A-Za-z])(?:KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL)(?![A-Za-z])", re.IGNORECASE
)


@dataclass(slots=True)
class CodexAgent:
    """One declared subagent role and its (optional) approval-policy override."""

    name: str
    approval_policy: str | None
    config_file: str | None


@dataclass(frozen=True, slots=True)
class CodexRoutingRoute:
    """One statically resolvable persistent routing lane after config precedence."""

    name: str
    kind: str
    sources: tuple[str, ...]
    model: str | None
    reasoning_effort: str | None
    approval_policy: str
    sandbox_mode: str
    default_permissions: str | None
    agents_max_threads: int | None
    agents_max_depth: int | None
    model_provider: str | None = None
    issues: tuple[str, ...] = ()

    @property
    def write_enabled(self) -> bool | None:
        """Whether execution can write, or ``None`` for an unresolved custom profile."""
        if self.default_permissions == ":read-only":
            return False
        if self.default_permissions in (":workspace", ":danger-full-access"):
            return True
        if self.default_permissions:
            return None
        return self.sandbox_mode != SANDBOX_READ_ONLY

    @property
    def approval_disabled(self) -> bool:
        return self.approval_policy == APPROVAL_NEVER


@dataclass(slots=True)
class CodexConfig:
    """Everything the scorer needs from a Codex harness, parsed once."""

    root: Path
    harness_type: str
    model: str | None
    review_model: str | None
    model_reasoning_effort: str | None
    approval_policy: str
    sandbox_mode: str
    web_search: str
    network_access: bool | None
    writable_roots: list[str]
    env_inherit: str | None
    env_ignore_default_excludes: bool
    env_exclude: list[str]
    env_set: dict[str, str]
    mcp_servers: list[str]
    agents: list[CodexAgent]
    agents_max_threads: int | None
    agents_max_depth: int | None
    trusted_projects: list[str]
    history_persistence: str | None
    notify: list[str]
    hooks: list[HookEntry]
    has_agents_md: bool
    agent_files: list[str]
    raw_config: dict[str, Any] = field(default_factory=dict)
    routing_routes: list[CodexRoutingRoute] = field(default_factory=list)
    routing_issues: list[str] = field(default_factory=list)

    # --- effective-floor helpers (the bypass-aware moat for Codex) -----------------

    @property
    def sandbox_disabled(self) -> bool:
        """``danger-full-access`` removes the filesystem sandbox entirely."""
        return self.sandbox_mode == SANDBOX_DANGER

    @property
    def sandbox_read_only(self) -> bool:
        return self.sandbox_mode == SANDBOX_READ_ONLY

    @property
    def approval_disabled(self) -> bool:
        """``never`` removes the human-in-the-loop gate before commands run."""
        return self.approval_policy == APPROVAL_NEVER

    @property
    def is_bypass(self) -> bool:
        """Effective bypass: no sandbox AND no approval gate → actions run unchecked."""
        return self.sandbox_disabled and self.approval_disabled

    @property
    def network_blocked(self) -> bool:
        """Whether the sandbox denies outbound network (the primary egress control).

        Per OpenAI's Codex docs ("defaults include no network access"): ``danger-full-access``
        allows network; ``read-only`` denies it (network commands require approval);
        ``workspace-write`` denies it unless ``[sandbox_workspace_write].network_access`` is
        explicitly true. We grade configured intent, not platform quirks (e.g. the macOS
        seatbelt bug that ignores ``network_access = true``).
        """
        if self.sandbox_disabled:
            return False
        if self.sandbox_read_only:
            return True
        return self.network_access is not True

    @property
    def env_secrets_scrubbed(self) -> bool:
        """Whether secret-looking env vars are kept out of the spawned subprocess env.

        ``inherit = "none"`` passes no inherited env, and the default excludes (names matching
        KEY/SECRET/TOKEN) otherwise apply unless ``ignore_default_excludes`` turns them off.
        Either way, an explicit ``set`` of a secret-named var re-introduces the leak.
        """
        if any(_SECRET_ENV_HINT.search(name) for name in self.env_set):
            return False
        if self.env_inherit == "none":
            return True
        return not self.env_ignore_default_excludes

    @property
    def has_trusted_project(self) -> bool:
        """True when any project is marked trusted (approval suppression inside that dir)."""
        return bool(self.trusted_projects)

    # --- hook query helpers (shared matcher logic with the Claude Code adapter) -----

    def has_hook(self, event: str, command_contains: str, matcher: str | None = None) -> bool:
        """True if a hook under ``event`` whose command matches also covers ``matcher``'s lane."""
        return hook_present(self.hooks, event, command_contains, matcher)

    def has_hook_on_tool(self, event: str, command_contains: str, tool_name: str) -> bool:
        """True if a hook under ``event`` whose command matches also covers ``tool_name``'s lane."""
        return hook_on_tool(self.hooks, event, command_contains, tool_name)

    def has_event(self, event: str) -> bool:
        """True when at least one hook is registered under ``event`` (any matcher)."""
        return event_present(self.hooks, event)

    @property
    def caveats(self) -> list[str]:
        """Advisory notes that reframe the grade (e.g. an opaque hook dispatcher)."""
        return [
            *detect_dispatcher_caveats(self.hooks),
            *self.routing_issues,
            (
                "Codex invocation flags, --config overrides, and in-session /model or "
                "/reasoning changes are runtime state; the static grade covers persistent "
                "config routes only."
            ),
        ]


def _read_toml_layer(path: Path) -> tuple[dict[str, Any], str | None]:
    """Read one optional config layer while retaining parse/read uncertainty."""
    try:
        with path.open("rb") as handle:
            return tomllib.load(handle), None
    except FileNotFoundError:
        return {}, None
    except tomllib.TOMLDecodeError:
        return {}, f"Cannot resolve routing layer {path}: invalid TOML."
    except OSError:
        return {}, f"Cannot resolve routing layer {path}: unreadable."


def _as_bool(value: Any) -> bool | None:
    return value if isinstance(value, bool) else None


def _as_int(value: Any) -> int | None:
    # bool is a subclass of int; exclude it so `true` is never read as 1.
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _parse_agents(raw: dict[str, Any]) -> tuple[list[CodexAgent], int | None, int | None]:
    table = _as_dict(raw.get("agents"))
    agents = [
        CodexAgent(
            name=str(name),
            approval_policy=str(spec["approval_policy"]) if "approval_policy" in spec else None,
            config_file=str(spec["config_file"]) if "config_file" in spec else None,
        )
        for name, spec in table.items()
        if isinstance(spec, dict)
    ]
    return agents, _as_int(table.get("max_threads")), _as_int(table.get("max_depth"))


def _parse_trusted_projects(raw: dict[str, Any]) -> list[str]:
    projects = _as_dict(raw.get("projects"))
    return [
        str(path)
        for path, spec in projects.items()
        if _as_dict(spec).get("trust_level") == TRUST_TRUSTED
    ]


def _merge_layers(*layers: dict[str, Any]) -> dict[str, Any]:
    """Recursively overlay TOML tables in Codex's low-to-high precedence order."""
    merged: dict[str, Any] = {}
    for layer in layers:
        for key, value in layer.items():
            if isinstance(value, dict) and isinstance(merged.get(key), dict):
                merged[key] = _merge_layers(_as_dict(merged[key]), value)
            else:
                merged[key] = value
    return merged


def _approval_policy(raw: dict[str, Any]) -> str:
    value = raw.get("approval_policy", "on-request")
    if isinstance(value, str):
        return value
    if isinstance(value, dict) and isinstance(value.get("granular"), dict):
        return "granular"
    return "unknown"


def _route_from_config(
    *,
    name: str,
    kind: str,
    sources: tuple[str, ...],
    raw: dict[str, Any],
    inherited_issues: tuple[str, ...] = (),
) -> CodexRoutingRoute:
    agents = _as_dict(raw.get("agents"))
    issues = list(inherited_issues)
    default_permissions = str(raw["default_permissions"]) if "default_permissions" in raw else None
    if default_permissions is not None and (
        "sandbox_mode" in raw or "sandbox_workspace_write" in raw
    ):
        issues.append(
            f"{name} combines default_permissions with legacy sandbox settings; official "
            "configuration says not to combine them."
        )
    return CodexRoutingRoute(
        name=name,
        kind=kind,
        sources=sources,
        model=str(raw["model"]) if "model" in raw else None,
        reasoning_effort=(
            str(raw["model_reasoning_effort"]) if "model_reasoning_effort" in raw else None
        ),
        approval_policy=_approval_policy(raw),
        sandbox_mode=str(raw.get("sandbox_mode", SANDBOX_READ_ONLY)),
        default_permissions=default_permissions,
        agents_max_threads=_as_int(agents.get("max_threads")),
        agents_max_depth=_as_int(agents.get("max_depth")),
        model_provider=str(raw["model_provider"]) if "model_provider" in raw else None,
        issues=tuple(issues),
    )


def _project_config_path(root: Path, configured_path: str) -> Path:
    project = Path(configured_path).expanduser()
    if not project.is_absolute():
        project = root / project
    return project / ".codex" / "config.toml"


def _routing_routes(root: Path, raw: dict[str, Any]) -> tuple[list[CodexRoutingRoute], list[str]]:
    """Resolve user, separate profile, and trusted-project persistent routes."""
    issues: list[str] = []
    base_issues: list[str] = []
    if "profile" in raw or "profiles" in raw:
        base_issues.append(
            "Legacy profile/profile tables are stale in Codex 0.134.0+; separate "
            "$CODEX_HOME/<name>.config.toml files are the supported profile surface."
        )

    profiles: list[tuple[str, dict[str, Any], tuple[str, ...]]] = []
    try:
        profile_paths = sorted(root.glob("*.config.toml"))
    except OSError:
        profile_paths = []
        issues.append("Profile files could not be inventoried; profile routing is UNKNOWN.")
    for path in profile_paths:
        profile_raw, error = _read_toml_layer(path)
        profile_issues = (error,) if error else ()
        profiles.append((path.name.removesuffix(".config.toml"), profile_raw, profile_issues))

    projects: list[tuple[str, dict[str, Any], tuple[str, ...]]] = []
    for configured_path in _parse_trusted_projects(raw):
        path = _project_config_path(root, configured_path)
        project_raw, error = _read_toml_layer(path)
        if not project_raw and error is None:
            continue
        project_issues = (error,) if error else ()
        projects.append((configured_path, project_raw, project_issues))

    routes = [
        _route_from_config(
            name="default",
            kind="default",
            sources=("config.toml",),
            raw=raw,
            inherited_issues=tuple(base_issues),
        )
    ]
    for name, profile_raw, profile_issues in profiles:
        routes.append(
            _route_from_config(
                name=f"profile:{name}",
                kind="profile",
                sources=("config.toml", f"{name}.config.toml"),
                raw=_merge_layers(raw, profile_raw),
                inherited_issues=(*base_issues, *profile_issues),
            )
        )
    for project, project_raw, project_issues in projects:
        project_source = f"{project}/.codex/config.toml"
        routes.append(
            _route_from_config(
                name=f"project:{project}",
                kind="project",
                sources=("config.toml", project_source),
                raw=_merge_layers(raw, project_raw),
                inherited_issues=(*base_issues, *project_issues),
            )
        )
        for profile_name, profile_raw, profile_issues in profiles:
            routes.append(
                _route_from_config(
                    name=f"profile:{profile_name}+project:{project}",
                    kind="profile+project",
                    sources=(
                        "config.toml",
                        f"{profile_name}.config.toml",
                        project_source,
                    ),
                    raw=_merge_layers(raw, profile_raw, project_raw),
                    inherited_issues=(*base_issues, *profile_issues, *project_issues),
                )
            )
    return routes, issues


def load_codex_harness(root: Path | str) -> CodexConfig:
    """Parse a Codex harness directory into a :class:`CodexConfig`.

    Raises ``FileNotFoundError`` if neither ``config.toml`` nor ``AGENTS.md`` exists at
    ``root`` (nothing identifiably Codex to grade).
    """
    root = Path(root)
    config_path = root / "config.toml"
    agents_md = root / "AGENTS.md"
    if not config_path.exists() and not agents_md.exists():
        msg = f"No config.toml or AGENTS.md found at {root}"
        raise FileNotFoundError(msg)

    raw, base_error = _read_toml_layer(config_path)
    sandbox_write = _as_dict(raw.get("sandbox_workspace_write"))
    env_policy = _as_dict(raw.get("shell_environment_policy"))
    history = _as_dict(raw.get("history"))
    agents, max_threads, max_depth = _parse_agents(raw)

    routes, routing_issues = _routing_routes(root, raw)
    if base_error:
        routing_issues.append(base_error)
    return CodexConfig(
        root=root,
        harness_type=HARNESS_TYPE_CODEX,
        model=str(raw["model"]) if "model" in raw else None,
        review_model=str(raw["review_model"]) if "review_model" in raw else None,
        model_reasoning_effort=(
            str(raw["model_reasoning_effort"]) if "model_reasoning_effort" in raw else None
        ),
        approval_policy=_approval_policy(raw),
        sandbox_mode=str(raw.get("sandbox_mode", SANDBOX_READ_ONLY)),
        web_search=str(raw.get("web_search", "off")),
        network_access=_as_bool(sandbox_write.get("network_access")),
        writable_roots=_as_str_list(sandbox_write.get("writable_roots")),
        env_inherit=str(env_policy["inherit"]) if "inherit" in env_policy else None,
        env_ignore_default_excludes=bool(env_policy.get("ignore_default_excludes", False)),
        env_exclude=_as_str_list(env_policy.get("exclude")),
        env_set={str(k): str(v) for k, v in _as_dict(env_policy.get("set")).items()},
        mcp_servers=sorted(_as_dict(raw.get("mcp_servers"))),
        agents=agents,
        agents_max_threads=max_threads,
        agents_max_depth=max_depth,
        trusted_projects=_parse_trusted_projects(raw),
        history_persistence=str(history["persistence"]) if "persistence" in history else None,
        notify=_as_str_list(raw.get("notify")),
        hooks=_flatten_hooks(_read_json(root / "hooks.json").get("hooks", {})),
        has_agents_md=agents_md.is_file(),
        agent_files=_inventory_codex_agents(root / "agents"),
        raw_config=raw,
        routing_routes=routes,
        routing_issues=routing_issues,
    )


def _inventory_codex_agents(path: Path) -> list[str]:
    try:
        return sorted(p.name for p in path.iterdir() if p.is_file() and p.name.endswith(".toml"))
    except OSError:
        return []

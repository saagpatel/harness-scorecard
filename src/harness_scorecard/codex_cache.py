"""Parse declared GPT-5.6 prompt-cache syntax from persistent Codex configuration.

Official Responses API contract (OpenAI prompt-caching guide and Responses
``PromptCacheOptions`` schema, inspected 2026-09-10):

- ``prompt_cache_options.mode`` is ``explicit`` or ``implicit``.
- ``prompt_cache_options.ttl`` is ``30m`` when set.
- ``prompt_cache_options.comparison_response_id`` is an optional string diagnostic
  baseline. It does not change cache-write hygiene; a well-typed value is ignored
  for the PASS/FAIL prefix check, while a non-string value is unresolved.
- ``prompt_cache_breakpoint: { "mode": "explicit" }`` marks a supported content block
  (``input_text``, ``input_image``, ``input_file``) inside an ``input`` message.
- Explicit-only mode writes cache only at those breakpoints; content after the last
  breakpoint is ordinary uncached input with no cache-write charge.
- A later user/tool/assistant message may use plain-string ``content`` as a volatile
  suffix. Breakpoints still cannot live on that string; only breakpoint-bearing
  malformed structures are treated as unresolved.

This module reads those fields from TOML. It does not claim Codex serializes them at
runtime: the official Codex config schema currently omits them, so a later check may
still emit UNKNOWN when the surface is unsupported or runtime-only.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

SUPPORTED_CONTENT_TYPES = frozenset({"input_text", "input_image", "input_file"})
STABLE_ROLES = frozenset({"developer"})
VOLATILE_ROLES = frozenset({"user", "tool", "assistant"})
OPTIONS_MODES = frozenset({"explicit", "implicit"})
OPTIONS_FIELDS = frozenset({"mode", "ttl", "comparison_response_id"})
BREAKPOINT_MODE = "explicit"
TTL_30M = "30m"
MAX_CACHE_WRITES = 4

_UNOFFICIAL_CACHE_KEYS = frozenset(
    {
        "cache_control",
        "cache_control_injection_points",
        "prompt_cache_retention",
        "cache_breakpoint",
        "cache_breakpoints",
        "prompt_cache_mode",
        "cache_write",
        "cache_writes",
        "prompt_cache_writes",
        "explicit_cache",
        "explicit_breakpoint",
    }
)


@dataclass(frozen=True, slots=True)
class CodexCacheBlock:
    """One declared Responses-style content block in persistent config."""

    role: str | None
    content_type: str | None
    has_breakpoint: bool
    breakpoint_mode: str | None
    plain_string: bool = False


@dataclass(frozen=True, slots=True)
class CodexCacheDeclaration:
    """Cache-breakpoint fields found on one persistent Codex config layer."""

    mode: str | None = None
    ttl: str | None = None
    comparison_response_id: str | None = None
    key_set: bool = False
    options_present: bool = False
    blocks: tuple[CodexCacheBlock, ...] = ()
    unofficial_markers: tuple[str, ...] = ()
    issues: tuple[str, ...] = ()

    @property
    def declared(self) -> bool:
        """True when official GPT-5.6 cache-control fields are present."""
        return self.options_present or any(block.has_breakpoint for block in self.blocks)


def _walk_keys(value: Any, prefix: str = "") -> Iterable[str]:
    if isinstance(value, dict):
        for key, nested in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            yield path
            yield from _walk_keys(nested, path)
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            yield from _walk_keys(nested, f"{prefix}[{index}]")


def _unofficial_markers(raw: dict[str, Any]) -> tuple[str, ...]:
    found: list[str] = []
    for path in _walk_keys(raw):
        key = path.rsplit(".", 1)[-1]
        key = key.split("[", 1)[0]
        if key.lower() in _UNOFFICIAL_CACHE_KEYS:
            found.append(path)
    return tuple(dict.fromkeys(found))


def _as_str(value: Any) -> str | None:
    return value if isinstance(value, str) else None


def _parse_breakpoint(item: dict[str, Any]) -> tuple[bool, str | None, list[str]]:
    if "prompt_cache_breakpoint" not in item:
        return False, None, []
    raw = item["prompt_cache_breakpoint"]
    if not isinstance(raw, dict):
        return True, None, ["prompt_cache_breakpoint is not an object"]
    issues: list[str] = []
    extra = sorted(key for key in raw if key != "mode")
    if extra:
        issues.append(
            "prompt_cache_breakpoint has undocumented fields: " + ", ".join(extra)
        )
    mode = raw.get("mode")
    if not isinstance(mode, str):
        issues.append("prompt_cache_breakpoint.mode is missing or not a string")
        return True, None, issues
    return True, mode, issues


def _parse_content_item(
    item: Any, role: str | None, issues: list[str]
) -> CodexCacheBlock | None:
    if not isinstance(item, dict):
        issues.append("input content item is not an object")
        return None
    if "prompt_cache_breakpoint" in item and "type" not in item:
        issues.append("prompt_cache_breakpoint is not on a content block")
    has_bp, bp_mode, bp_issues = _parse_breakpoint(item)
    issues.extend(bp_issues)
    content_type = _as_str(item.get("type"))
    return CodexCacheBlock(
        role=role,
        content_type=content_type,
        has_breakpoint=has_bp,
        breakpoint_mode=bp_mode,
    )


def _parse_plain_string_message(
    role: str | None, message: dict[str, Any], issues: list[str]
) -> list[CodexCacheBlock]:
    """Plain-string content is a valid volatile suffix after an explicit breakpoint.

    Official GPT-5.6 explicit caching places the breakpoint on a developer content-block
    list, then lets later user/tool/assistant messages use a string. A breakpoint on
    that string is malformed; the string itself is not.
    """
    role_kind = (role or "").strip().lower()
    if "prompt_cache_breakpoint" in message:
        issues.append("prompt_cache_breakpoint cannot be attached to plain-string content")
        return []
    if role_kind not in STABLE_ROLES and role_kind not in VOLATILE_ROLES:
        issues.append("plain-string content has no classifiable role as policy vs project state")
        return []
    return [
        CodexCacheBlock(
            role=role,
            content_type=None,
            has_breakpoint=False,
            breakpoint_mode=None,
            plain_string=True,
        )
    ]


def _parse_message(message: Any, issues: list[str]) -> list[CodexCacheBlock]:
    if not isinstance(message, dict):
        issues.append("input item is not a message object")
        return []
    role = _as_str(message.get("role"))
    content = message.get("content")
    if isinstance(content, str):
        return _parse_plain_string_message(role, message, issues)
    if "prompt_cache_breakpoint" in message:
        issues.append(
            "prompt_cache_breakpoint must live on a supported content block, not the message"
        )
    if isinstance(content, list):
        blocks: list[CodexCacheBlock] = []
        for item in content:
            block = _parse_content_item(item, role, issues)
            if block is not None:
                blocks.append(block)
        return blocks
    if content is None:
        issues.append("input message has no content array")
        return []
    issues.append("input message content is not an array of content blocks")
    return []


def _parse_options(
    raw: dict[str, Any], issues: list[str]
) -> tuple[bool, str | None, str | None, str | None]:
    if "prompt_cache_options" not in raw:
        return False, None, None, None
    options = raw["prompt_cache_options"]
    if not isinstance(options, dict):
        issues.append("prompt_cache_options is not a table")
        return True, None, None, None
    extra = sorted(key for key in options if key not in OPTIONS_FIELDS)
    if extra:
        issues.append("prompt_cache_options has undocumented fields: " + ", ".join(extra))
    mode = options.get("mode")
    ttl = options.get("ttl")
    comparison = options.get("comparison_response_id")
    if "mode" in options and not isinstance(mode, str):
        issues.append("prompt_cache_options.mode is not a string")
        mode = None
    if "ttl" in options and not isinstance(ttl, str):
        issues.append("prompt_cache_options.ttl is not a string")
        ttl = None
    if "comparison_response_id" in options and not isinstance(comparison, str):
        issues.append("prompt_cache_options.comparison_response_id is not a string")
        comparison = None
    return True, _as_str(mode), _as_str(ttl), _as_str(comparison)


def parse_cache_declaration(raw: dict[str, Any]) -> CodexCacheDeclaration:
    """Extract official GPT-5.6 cache fields from one persistent TOML layer."""
    issues: list[str] = []
    unofficial = _unofficial_markers(raw)

    if "prompt_cache_breakpoint" in raw:
        issues.append(
            "top-level prompt_cache_breakpoint is not official; place it on a content block"
        )

    options_present, mode, ttl, comparison_response_id = _parse_options(raw, issues)
    key_set = "prompt_cache_key" in raw
    if key_set and not isinstance(raw.get("prompt_cache_key"), str):
        issues.append("prompt_cache_key is not a string")
        key_set = False

    blocks: list[CodexCacheBlock] = []
    if "input" in raw:
        input_value = raw["input"]
        if not isinstance(input_value, list):
            issues.append("input is not an array of messages")
        else:
            for message in input_value:
                blocks.extend(_parse_message(message, issues))

    return CodexCacheDeclaration(
        mode=mode,
        ttl=ttl,
        comparison_response_id=comparison_response_id,
        key_set=key_set,
        options_present=options_present,
        blocks=tuple(blocks),
        unofficial_markers=unofficial,
        issues=tuple(dict.fromkeys(issues)),
    )

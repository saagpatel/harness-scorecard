"""D7 (Codex) - Model routing discipline.

Codex launch-preview settings are useful when they are explicit lanes. They get risky when the
base config silently becomes the most expensive/deep route, or when preview delegation appears in
a write-enabled default without bounded fan-out and tracked roles.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from harness_scorecard.checks.base import Check, CheckOutcome, failed, partial, passed
from harness_scorecard.discovery_codex import CodexConfig
from harness_scorecard.models import Detectability, Severity

_NORMAL_REASONING = {"minimal", "low", "medium"}
_DEEP_REASONING = {"high"}
_OVERPOWERED_REASONING = {"xhigh", "max"}


def _normalize(value: str | None) -> str:
    return (value or "").strip().lower()


def _walk_raw_strings(value: Any, prefix: str = "") -> Iterable[str]:
    if isinstance(value, dict):
        for key, nested in value.items():
            key_path = f"{prefix}.{key}" if prefix else str(key)
            yield key_path
            yield from _walk_raw_strings(nested, key_path)
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            yield from _walk_raw_strings(nested, f"{prefix}[{index}]")
    elif isinstance(value, str):
        yield f"{prefix}={value}" if prefix else value


def _default_reasoning_bounded(config: CodexConfig) -> CheckOutcome:
    effort = _normalize(config.model_reasoning_effort)
    if not effort:
        return passed("No explicit default reasoning effort is pinned.")
    if effort in _NORMAL_REASONING:
        return passed(
            f"Default reasoning effort is bounded for ordinary work: {effort}.",
            [f"model_reasoning_effort={effort}"],
        )
    if effort in _DEEP_REASONING:
        return partial(
            "Default reasoning effort is high; reserve deep reasoning for an explicit profile.",
            [f"model_reasoning_effort={effort}"],
        )
    if effort in _OVERPOWERED_REASONING:
        return failed(
            "Default reasoning effort is the deepest available lane; ordinary work should not "
            "inherit launch-preview or maximum-depth settings.",
            [f"model_reasoning_effort={effort}"],
        )
    return partial(
        f"Unrecognized default reasoning effort {effort!r}; cannot confirm it is bounded.",
        [f"model_reasoning_effort={effort}"],
    )


def _preview_delegation_gated(config: CodexConfig) -> CheckOutcome:
    raw_hits = [
        item for item in _walk_raw_strings(config.raw_config) if "ultra" in item.lower()
    ]
    effort = _normalize(config.model_reasoning_effort)
    max_reasoning = effort == "max"

    if not raw_hits and not max_reasoning:
        return passed("No launch-preview max reasoning or ultra-style delegation is configured.")

    evidence = [*raw_hits]
    if max_reasoning:
        evidence.append("model_reasoning_effort=max")

    fanout_bounded = config.agents_max_threads is not None and config.agents_max_depth is not None
    roles_tracked = bool(config.agents) and all(agent.config_file for agent in config.agents)
    write_enabled = not config.sandbox_read_only

    if write_enabled:
        return failed(
            "Launch-preview max/ultra-style delegation appears in a write-enabled default lane.",
            evidence,
        )
    if not fanout_bounded or not roles_tracked:
        return partial(
            "Launch-preview max/ultra-style delegation is read-only but not fully bounded and "
            "provenance-tracked.",
            evidence,
        )
    return passed(
        "Launch-preview max/ultra-style delegation is read-only, bounded, and provenance-tracked.",
        evidence,
    )


CHECKS: list[Check[CodexConfig]] = [
    Check(
        id="CDX-D7-03",
        dimension="D7",
        title="Default reasoning effort is bounded",
        weight=1,
        evaluate=_default_reasoning_bounded,
        severity=Severity.MEDIUM,
        detectability=Detectability.STATIC,
        remediation=(
            "Keep the base config at low/medium reasoning and move high/xhigh/max reasoning into "
            "explicit read-only or task-specific profiles."
        ),
    ),
    Check(
        id="CDX-D7-04",
        dimension="D7",
        title="Launch-preview delegation is gated",
        weight=1,
        evaluate=_preview_delegation_gated,
        severity=Severity.HIGH,
        detectability=Detectability.PARTIAL,
        remediation=(
            "Keep max reasoning and ultra-style delegation out of write-enabled defaults; require "
            "read-only profiles, bounded fan-out, tracked config_file roles, and smoke receipts."
        ),
    ),
]

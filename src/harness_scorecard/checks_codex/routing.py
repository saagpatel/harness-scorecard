"""D7 (Codex) - Effective model and reasoning routing discipline.

The check grades persistent routes after documented precedence: user config, separate profile
files, then trusted project config. Invocation flags and in-session changes remain runtime state
and are surfaced as caveats, never inferred from prose or static files.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from harness_scorecard.checks.base import (
    Check,
    CheckOutcome,
    failed,
    not_applicable,
    partial,
    passed,
    unknown,
)
from harness_scorecard.discovery_codex import CodexConfig, CodexRoutingRoute
from harness_scorecard.models import Detectability, Severity, Status

# Verified against the official Codex config schema/manual and the Codex 0.144.1 model catalog.
# Unknown/custom-provider models remain UNKNOWN because their catalog owns compatibility.
_MODEL_EFFORTS: dict[str, frozenset[str]] = {
    "gpt-5.4": frozenset({"low", "medium", "high", "xhigh"}),
    "gpt-5.5": frozenset({"low", "medium", "high", "xhigh"}),
    "gpt-5.6": frozenset({"low", "medium", "high", "xhigh", "max"}),
    "gpt-5.6-sol": frozenset({"low", "medium", "high", "xhigh", "max", "ultra"}),
    "gpt-5.6-terra": frozenset({"low", "medium", "high", "xhigh", "max", "ultra"}),
    "gpt-5.6-luna": frozenset({"low", "medium", "high", "xhigh", "max"}),
}
_NORMAL_REASONING = frozenset({"none", "minimal", "low", "medium"})
_DEEP_REASONING = frozenset({"high", "xhigh"})
_GATED_REASONING = frozenset({"max", "ultra"})


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


def _route_evidence(route: CodexRoutingRoute) -> str:
    permissions = route.default_permissions or f"sandbox:{route.sandbox_mode}"
    return (
        f"{route.name} ({' -> '.join(route.sources)}): model={route.model or 'runtime-selected'}, "
        f"provider={route.model_provider or 'openai'}, "
        f"effort={route.reasoning_effort or 'runtime-selected'}, "
        f"approval={route.approval_policy}, execution={permissions}"
    )


def _compatibility_issue(route: CodexRoutingRoute) -> str | None:
    model = _normalize(route.model)
    effort = _normalize(route.reasoning_effort)
    if route.issues:
        return "; ".join(route.issues)
    if route.model_provider not in (None, "openai"):
        return f"custom model provider {route.model_provider!r} owns effort compatibility"
    if not model or not effort:
        return "model or reasoning effort is runtime-selected"
    supported = _MODEL_EFFORTS.get(model)
    if supported is None:
        return f"model {model!r} is not in the verified Codex model catalog"
    if effort not in supported:
        return f"effort {effort!r} is not advertised for {model}"
    return None


def _outcome_priority(status: Status) -> int:
    return {
        Status.FAIL: 4,
        Status.UNKNOWN: 3,
        Status.PARTIAL: 2,
        Status.PASS: 1,
        Status.NOT_APPLICABLE: 0,
    }[status]


def _combine(outcomes: list[CheckOutcome], success_message: str) -> CheckOutcome:
    if not outcomes:
        return passed(success_message)
    worst = max(outcomes, key=lambda item: _outcome_priority(item.status))
    evidence = [item for outcome in outcomes for item in outcome.evidence]
    messages = list(dict.fromkeys(outcome.message for outcome in outcomes if outcome.message))
    return CheckOutcome(worst.status, " ".join(messages), evidence)


def _routes(config: CodexConfig) -> list[CodexRoutingRoute]:
    return config.routing_routes or [
        CodexRoutingRoute(
            name="default",
            kind="default",
            sources=("config.toml",),
            model=config.model,
            reasoning_effort=config.model_reasoning_effort,
            approval_policy=config.approval_policy,
            sandbox_mode=config.sandbox_mode,
            default_permissions=None,
            agents_max_threads=config.agents_max_threads,
            agents_max_depth=config.agents_max_depth,
        )
    ]


def _default_reasoning_bounded(config: CodexConfig) -> CheckOutcome:
    outcomes: list[CheckOutcome] = []
    routes = _routes(config)
    for route in routes:
        evidence = [_route_evidence(route)]
        issue = _compatibility_issue(route)
        if issue:
            outcomes.append(unknown(f"{route.name}: {issue}.", evidence))
            continue
        effort = _normalize(route.reasoning_effort)
        if route.kind not in ("profile", "profile+project") and effort in _GATED_REASONING:
            outcomes.append(
                failed(
                    f"{route.name}: {effort} loads implicitly instead of through an explicit "
                    "task profile.",
                    evidence,
                )
            )
        elif route.kind == "default" and effort in _DEEP_REASONING:
            outcomes.append(
                partial(
                    f"{route.name}: {effort} is valid but broad; prefer an explicit profile "
                    "when ordinary work does not need it.",
                    evidence,
                )
            )
        elif effort in _NORMAL_REASONING or route.kind != "default":
            outcomes.append(passed(f"{route.name}: reasoning is explicitly scoped.", evidence))
        else:
            outcomes.append(unknown(f"{route.name}: effort {effort!r} is unresolved.", evidence))
    return _combine(outcomes, "All persistent routing lanes are bounded and explicit.")


def _unsupported_preview_markers(config: CodexConfig) -> list[str]:
    """Non-schema ultra markers are roadmap/prose guesses, not executable configuration."""
    return [
        item
        for item in _walk_raw_strings(config.raw_config)
        if "ultra" in item.lower() and not item.lower().startswith("model_reasoning_effort=ultra")
    ]


def _evaluate_high_cost_route(route: CodexRoutingRoute) -> CheckOutcome:
    evidence = [_route_evidence(route)]
    issue = _compatibility_issue(route)
    if issue:
        return unknown(f"{route.name}: {issue}.", evidence)
    effort = _normalize(route.reasoning_effort)
    if route.kind not in ("profile", "profile+project"):
        return failed(
            f"{route.name}: {effort} loads implicitly; move it to a separately selected profile.",
            evidence,
        )
    if route.write_enabled is None:
        return unknown(
            f"{route.name}: custom default_permissions cannot be reduced to a static write "
            "boundary.",
            evidence,
        )
    if effort != "ultra":
        return passed(
            f"{route.name}: {effort} is behind a separately selected, compatible profile.",
            evidence,
        )

    bounds_explicit = route.agents_max_threads is not None and route.agents_max_depth is not None
    execution_gated = not route.write_enabled or not route.approval_disabled
    if bounds_explicit and execution_gated:
        return passed(
            f"{route.name}: ultra is behind a separately selected, compatible profile.",
            evidence,
        )
    missing = []
    if not bounds_explicit:
        missing.append("explicit max_threads/max_depth")
    if not execution_gated:
        missing.append("read-only execution or an approval gate")
    return failed(f"{route.name}: ultra lacks {' and '.join(missing)}.", evidence)


def _high_cost_gate(config: CodexConfig) -> CheckOutcome:
    guessed = _unsupported_preview_markers(config)
    if guessed:
        return unknown(
            "Unsupported ultra-style configuration markers cannot prove a runnable route.",
            guessed,
        )

    gated_routes = [
        route for route in _routes(config) if _normalize(route.reasoning_effort) in _GATED_REASONING
    ]
    if not gated_routes:
        return not_applicable("No persistent max/ultra route is configured.")

    outcomes = [_evaluate_high_cost_route(route) for route in gated_routes]
    return _combine(outcomes, "Every max/ultra route has an explicit static gate.")


CHECKS: list[Check[CodexConfig]] = [
    Check(
        id="CDX-D7-03",
        dimension="D7",
        title="Persistent reasoning routes are bounded",
        weight=1,
        evaluate=_default_reasoning_bounded,
        severity=Severity.MEDIUM,
        detectability=Detectability.PARTIAL,
        remediation=(
            "Keep ordinary defaults at a supported low/medium effort. Put justified high/xhigh "
            "work in separate profile or trusted-project routes; leave unresolved model/catalog "
            "combinations UNKNOWN."
        ),
    ),
    Check(
        id="CDX-D7-04",
        dimension="D7",
        title="Max and Ultra routes have explicit gates",
        weight=1,
        evaluate=_high_cost_gate,
        severity=Severity.HIGH,
        detectability=Detectability.PARTIAL,
        remediation=(
            "Move max/ultra into a separately selected profile. For Ultra, also set explicit "
            "fan-out bounds and retain read-only execution or a live approval gate."
        ),
    ),
]

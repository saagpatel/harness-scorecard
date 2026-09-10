"""D7 (Codex) — GPT-5.6 cache-breakpoint hygiene on persistent configuration.

Grades declared Responses API cache syntax only. It does not execute Codex, measure
``cache_write_tokens``, or infer runtime prompt assembly.
"""

from __future__ import annotations

from harness_scorecard.checks.base import (
    Check,
    CheckOutcome,
    failed,
    not_applicable,
    passed,
    unknown,
)
from harness_scorecard.codex_cache import (
    BREAKPOINT_MODE,
    MAX_CACHE_WRITES,
    OPTIONS_MODES,
    STABLE_ROLES,
    SUPPORTED_CONTENT_TYPES,
    TTL_30M,
    VOLATILE_ROLES,
    CodexCacheBlock,
    CodexCacheDeclaration,
    parse_cache_declaration,
)
from harness_scorecard.discovery_codex import CodexConfig, CodexRoutingRoute
from harness_scorecard.models import Detectability, Severity, Status

_GPT56_PREFIX = "gpt-5.6"


def _normalize(value: str | None) -> str:
    return (value or "").strip().lower()


def _is_gpt56(model: str | None) -> bool:
    return _normalize(model).startswith(_GPT56_PREFIX)


def _routes(config: CodexConfig) -> list[CodexRoutingRoute]:
    if config.routing_routes:
        return config.routing_routes
    return [
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
            model_provider=(
                str(config.raw_config["model_provider"])
                if "model_provider" in config.raw_config
                else None
            ),
            cache=parse_cache_declaration(config.raw_config),
        )
    ]


def _block_evidence(block: CodexCacheBlock) -> str:
    role = block.role or "untyped-role"
    content_type = block.content_type or "untyped-block"
    if block.has_breakpoint:
        return f"{role}/{content_type} breakpoint={block.breakpoint_mode or 'missing'}"
    return f"{role}/{content_type}"


def _route_evidence(route: CodexRoutingRoute) -> str:
    cache = route.cache
    mode = cache.mode or ("declared" if cache.options_present else "absent")
    return (
        f"{route.name} ({' -> '.join(route.sources)}): model={route.model or 'runtime-selected'}, "
        f"provider={route.model_provider or 'openai'}, cache_mode={mode}, "
        f"blocks={len(cache.blocks)}"
    )


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


def _kind(block: CodexCacheBlock) -> str | None:
    role = _normalize(block.role)
    if role in STABLE_ROLES:
        return "stable"
    if role in VOLATILE_ROLES:
        return "volatile"
    return None


def _unresolved_block_issue(block: CodexCacheBlock) -> str | None:
    if block.has_breakpoint and block.breakpoint_mode != BREAKPOINT_MODE:
        return (
            f"prompt_cache_breakpoint.mode={block.breakpoint_mode!r} is not the documented "
            f"{BREAKPOINT_MODE!r} value"
        )
    if block.has_breakpoint and block.content_type not in SUPPORTED_CONTENT_TYPES:
        return (
            f"prompt_cache_breakpoint on {block.content_type!r} is not a supported GPT-5.6 "
            "content type"
        )
    if _kind(block) is None or not block.role or not block.content_type:
        return "content block role or type cannot be classified as policy vs project state"
    if block.content_type not in SUPPORTED_CONTENT_TYPES:
        return (
            f"content type {block.content_type!r} is outside the GPT-5.6 "
            "cache-breakpoint contract"
        )
    return None


def _classify_blocks(
    blocks: tuple[CodexCacheBlock, ...],
) -> tuple[list[tuple[str, CodexCacheBlock]] | None, str | None]:
    classified: list[tuple[str, CodexCacheBlock]] = []
    for block in blocks:
        issue = _unresolved_block_issue(block)
        if issue:
            return None, issue
        kind = _kind(block)
        if kind is None:
            return None, "content block role is unresolved"
        classified.append((kind, block))
    return classified, None


def _prefix_hygiene_issue(
    classified: list[tuple[str, CodexCacheBlock]],
) -> tuple[Status, str] | None:
    has_stable = any(kind == "stable" for kind, _ in classified)
    breakpoint_indexes = [
        index for index, (_, block) in enumerate(classified) if block.has_breakpoint
    ]
    last_breakpoint = breakpoint_indexes[-1] if breakpoint_indexes else -1
    last_stable = (
        max(index for index, (kind, _) in enumerate(classified) if kind == "stable")
        if has_stable
        else -1
    )
    first_volatile = next(
        (index for index, (kind, _) in enumerate(classified) if kind == "volatile"),
        None,
    )
    findings: tuple[tuple[bool, Status, str], ...] = (
        (
            not has_stable,
            Status.FAIL,
            "No developer/policy block is declared before volatile project state.",
        ),
        (
            has_stable and not breakpoint_indexes,
            Status.UNKNOWN,
            "explicit mode has no prompt_cache_breakpoint on a supported content block, so "
            "cache-write accounting cannot be proven.",
        ),
        (
            len(breakpoint_indexes) > MAX_CACHE_WRITES,
            Status.UNKNOWN,
            "More than four declared cache writes are outside the documented GPT-5.6 limit.",
        ),
        (
            last_breakpoint >= 0
            and any(kind == "volatile" for kind, _ in classified[: last_breakpoint + 1]),
            Status.FAIL,
            "Cached prefix includes volatile project state before the last explicit breakpoint.",
        ),
        (
            bool(breakpoint_indexes) and last_stable != last_breakpoint,
            Status.FAIL,
            "Cache breakpoint is not at the end of stable policy/rubric context.",
        ),
        (
            first_volatile is not None and first_volatile < last_stable,
            Status.FAIL,
            "Volatile project state is declared before stable policy/rubric context.",
        ),
    )
    for matches, status, message in findings:
        if matches:
            return status, message
    return None


def _ordering_outcome(
    blocks: tuple[CodexCacheBlock, ...], evidence: list[str]
) -> CheckOutcome:
    block_evidence = evidence + [_block_evidence(block) for block in blocks]
    classified, issue = _classify_blocks(blocks)
    if issue is not None or classified is None:
        return unknown(f"{issue}.", block_evidence)
    hygiene = _prefix_hygiene_issue(classified)
    if hygiene is None:
        return passed(
            "Stable policy/rubric context is declared before volatile project state, with "
            "explicit cache-write accounting.",
            block_evidence,
        )
    status, message = hygiene
    if status is Status.FAIL:
        return failed(message, block_evidence)
    return unknown(message, block_evidence)


def _declared_explicit_outcome(
    cache: CodexCacheDeclaration, evidence: list[str]
) -> CheckOutcome:
    if cache.mode is None:
        return failed(
            "prompt_cache_options.mode is omitted, so GPT-5.6 implicit cache writes through "
            "the latest eligible message remain unaccounted.",
            evidence,
        )
    if cache.mode not in OPTIONS_MODES:
        return unknown(
            f"prompt_cache_options.mode={cache.mode!r} is not a documented GPT-5.6 value.",
            evidence,
        )
    if cache.mode == "implicit":
        return failed(
            "prompt_cache_options.mode=implicit writes through the latest eligible message, "
            "hiding cache-write cost on volatile project state.",
            evidence,
        )
    if cache.ttl not in (None, TTL_30M):
        return unknown(
            f"prompt_cache_options.ttl={cache.ttl!r} is not the documented GPT-5.6 value.",
            evidence,
        )
    if not cache.blocks:
        return unknown(
            "explicit mode has no declared input content blocks, so prefix ordering cannot "
            "be proven from persistent configuration.",
            evidence,
        )
    return _ordering_outcome(cache.blocks, evidence)


def _surface_unknown(route: CodexRoutingRoute, evidence: list[str]) -> CheckOutcome | None:
    cache = route.cache
    if route.model_provider not in (None, "openai"):
        return unknown(
            f"{route.name}: custom model provider {route.model_provider!r} owns "
            "cache-breakpoint support.",
            evidence,
        )
    if route.issues:
        return unknown(f"{route.name}: {'; '.join(route.issues)}.", evidence)
    if cache.unofficial_markers:
        return unknown(
            f"{route.name}: unsupported cache-breakpoint markers cannot prove GPT-5.6 hygiene.",
            [*evidence, *cache.unofficial_markers],
        )
    if cache.issues:
        return unknown(
            f"{route.name}: persistent cache-breakpoint syntax is ambiguous or malformed.",
            [*evidence, *cache.issues],
        )
    return None


def _applicability_outcome(
    route: CodexRoutingRoute, evidence: list[str]
) -> CheckOutcome | None:
    model = _normalize(route.model)
    cache = route.cache
    if _is_gpt56(model):
        if cache.declared:
            return None
        return unknown(
            f"{route.name}: no persistent GPT-5.6 cache-breakpoint syntax; cache writes are "
            "runtime-only.",
            evidence,
        )
    if cache.declared:
        return unknown(
            f"{route.name}: cache-breakpoint syntax is not the GPT-5.6 Responses contract "
            "on this model.",
            evidence,
        )
    if not model:
        return unknown(
            f"{route.name}: model is runtime-selected; cache-breakpoint placement cannot "
            "be proven.",
            evidence,
        )
    return not_applicable(f"{route.name}: no GPT-5.6 persistent route is configured.")


def _evaluate_route(route: CodexRoutingRoute) -> CheckOutcome:
    evidence = [_route_evidence(route)]
    blocked = _surface_unknown(route, evidence)
    if blocked is not None:
        return blocked
    applicability = _applicability_outcome(route, evidence)
    if applicability is not None:
        return applicability
    return _declared_explicit_outcome(route.cache, evidence)


def _cache_breakpoint_hygiene(config: CodexConfig) -> CheckOutcome:
    outcomes = [_evaluate_route(route) for route in _routes(config)]
    return _combine(
        outcomes,
        "Stable policy/rubric context is declared before volatile project state, with "
        "explicit cache-write accounting.",
    )


CHECKS: list[Check[CodexConfig]] = [
    Check(
        id="CDX-D7-05",
        dimension="D7",
        title="GPT-5.6 cache-breakpoint hygiene",
        weight=1,
        evaluate=_cache_breakpoint_hygiene,
        severity=Severity.MEDIUM,
        detectability=Detectability.PARTIAL,
        remediation=(
            "In persistent Codex config, declare prompt_cache_options.mode=explicit and place "
            "prompt_cache_breakpoint={mode=explicit} on the last stable developer input_text "
            "block before volatile project state. Do not use implicit mode or unofficial "
            "cache_control markers. This grades declared syntax only; it does not prove "
            "runtime cache hits."
        ),
    ),
]

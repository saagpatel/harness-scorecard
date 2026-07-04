"""D5 (Codex) - Harness self-protection & integrity.

A harness must stop the agent from rewriting its own guardrails (``~/.codex`` config, hooks,
AGENTS.md). Codex protects these by default because ``~/.codex`` lives outside the workspace, so
``workspace-write`` / ``read-only`` sandboxes cannot write it -- unless the sandbox is disabled
or the codex home is added to ``writable_roots``. The self-mutation gate caps the grade at C when
neither the sandbox nor a hook protects the harness.
"""

from __future__ import annotations

from pathlib import Path

from harness_scorecard.checks.base import (
    Check,
    CheckOutcome,
    failed,
    not_applicable,
    partial,
    passed,
)
from harness_scorecard.claims import ENFORCED_STATUSES, ClaimStatus, audit_claims
from harness_scorecard.discovery_codex import CodexConfig
from harness_scorecard.models import Detectability, Grade, Severity

# "integrity" was dropped: it credits unrelated hooks (referential-integrity, data-integrity).
_SELF_PROTECT_NEEDLES = (
    "self-protect",
    "config-guard",
    "harness-guard",
    "protect-config",
)


def _codex_home_writable(config: CodexConfig) -> bool:
    """True if a writable_root exposes the codex home (or an ancestor of it) to writes.

    Roots are tilde-expanded first so ``writable_roots = ["~"]`` (home, which contains
    ``~/.codex``) and ``["/"]`` are caught rather than slipping past a raw substring test.
    """
    codex_home = config.root.expanduser()
    for raw in config.writable_roots:
        try:
            writable = Path(raw).expanduser()
        except (ValueError, OSError):
            continue
        if ".codex" in writable.parts:
            return True
        if codex_home == writable or codex_home.is_relative_to(writable):
            return True
    return False


def _has_self_protect_hook(config: CodexConfig) -> bool:
    return any(config.has_hook("PreToolUse", needle) for needle in _SELF_PROTECT_NEEDLES)


def _self_mutation_floor(config: CodexConfig) -> CheckOutcome:
    sandbox_protects = not config.sandbox_disabled and not _codex_home_writable(config)
    has_guard = _has_self_protect_hook(config)
    if sandbox_protects or has_guard:
        sources = []
        if sandbox_protects:
            sources.append(f"sandbox_mode={config.sandbox_mode} keeps ~/.codex out of write scope")
        if has_guard:
            sources.append("hook:self-protect")
        return passed("The agent cannot rewrite its own harness config.", sources)
    return failed(
        "The harness is mutable by the agent: danger-full-access (or a writable_root covering "
        "~/.codex) with no self-protection hook.",
    )


def _agents_md_present(config: CodexConfig) -> CheckOutcome:
    if config.has_agents_md:
        return passed("AGENTS.md establishes an operating contract for the harness.")
    return failed(
        "No AGENTS.md: the harness has no declared operating contract to anchor behavior."
    )


def _self_protect_hook(config: CodexConfig) -> CheckOutcome:
    if _has_self_protect_hook(config):
        return passed("A PreToolUse hook guards writes to the harness configuration.")
    return failed("No hook guards writes to ~/.codex config, hooks, or AGENTS.md.")


def _check_stated_guarantees(config: CodexConfig) -> CheckOutcome:
    report = audit_claims(config)
    hard = [f for f in report.findings if f.claim.hard_deny]
    if not hard:
        return not_applicable(
            "The Codex instructions state no hard guarantees; nothing to verify. A harness "
            "must never score worse for documenting its rules."
        )
    backed = [f for f in hard if f.status in ENFORCED_STATUSES]
    prose_only = [f for f in hard if f.status is ClaimStatus.PROSE_ONLY]
    pending = [f for f in hard if f.status is ClaimStatus.CANDIDATE_LOGIC]
    if not prose_only and not pending:
        return passed(
            f"All {len(hard)} stated hard guarantees have enforcement backing under "
            f"{report.mode}.",
            evidence=[f"{f.claim.source}: {f.status.value}" for f in hard],
        )
    if not backed and prose_only:
        return failed(
            "Stated hard guarantees have no surviving enforcement under "
            f"{report.mode} -- the instructions promise blocks that nothing backs.",
            evidence=[f"{f.claim.source}: prose-only -- {f.claim.text[:80]}" for f in prose_only],
        )
    evidence = [f"{f.claim.source}: prose-only -- {f.claim.text[:80]}" for f in prose_only]
    evidence.extend(
        f"{f.claim.source}: logic-guard candidate, needs manual review" for f in pending
    )
    return partial(
        f"{len(backed)}/{len(hard)} stated hard guarantees are backed; "
        f"{len(prose_only)} prose-only, {len(pending)} pending manual review.",
        evidence=evidence,
    )


CHECKS: list[Check[CodexConfig]] = [
    Check(
        id="CDX-D5-01",
        dimension="D5",
        title="Agent cannot mutate its own harness",
        weight=3,
        evaluate=_self_mutation_floor,
        severity=Severity.CRITICAL,
        detectability=Detectability.STATIC,
        is_gate=True,
        gate_cap=Grade.C,
        remediation=(
            "Keep sandbox_mode off 'danger-full-access' and keep ~/.codex out of writable_roots, "
            "or add a PreToolUse hook that blocks writes to the harness config."
        ),
    ),
    Check(
        id="CDX-D5-02",
        dimension="D5",
        title="Operating contract is declared (AGENTS.md)",
        weight=1,
        evaluate=_agents_md_present,
        severity=Severity.MEDIUM,
        detectability=Detectability.STATIC,
        remediation="Add an AGENTS.md declaring branch/commit/verification rules for the agent.",
    ),
    Check(
        id="CDX-D5-03",
        dimension="D5",
        title="Self-protection hook guards the config",
        weight=1,
        evaluate=_self_protect_hook,
        severity=Severity.MEDIUM,
        detectability=Detectability.STATIC,
        remediation="Add a PreToolUse hook that rejects edits/writes targeting ~/.codex.",
        dispatcher_evidence=(
            r"\bCODEX_SELF_WRITE_RE\b",
            r"self[_\s-]?protect",
            r"\.codex/(?:hooks|agents|config)",
        ),
    ),
    Check(
        id="CDX-D5-04",
        dimension="D5",
        title="Stated hard guarantees have enforcement backing",
        weight=4,
        evaluate=_check_stated_guarantees,
        severity=Severity.HIGH,
        detectability=Detectability.PARTIAL,
        remediation=(
            "For every prose-only hard guarantee, add real Codex backing under the active "
            "approval/sandbox mode: a hooks.json shell deny hook or an effective config gate. "
            "Run `harness-scorecard claims <path>` for the per-claim ledger."
        ),
    ),
]

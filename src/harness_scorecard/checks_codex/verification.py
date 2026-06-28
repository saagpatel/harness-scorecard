"""D6 (Codex) - Verification gates.

Completion claims should be checked before the agent yields: a Stop hook that runs a
verification gate at turn end, and ideally a dedicated QA / closeout agent role that
independently audits the work.
"""

from __future__ import annotations

import re

from harness_scorecard.checks.base import Check, CheckOutcome, failed, passed
from harness_scorecard.discovery_codex import CodexConfig
from harness_scorecard.models import Detectability, Severity

# Bare "verify" credits unrelated Stop hooks (verify-ssl); use compound/specific terms.
_STOP_GATE_NEEDLES = ("stop-gate", "closeout", "qa-gate", "verify-gate", "verification")
# Verification role names, matched with a leading-letter boundary so "review" credits
# "code-reviewer" but not "preview-builder". "release"/"test" are excluded as too ambiguous.
_VERIFY_AGENT_NEEDLES = ("qa", "closeout", "verify", "review", "audit")
_VERIFY_AGENT_RE = re.compile(
    r"(?<![a-z])(?:" + "|".join(_VERIFY_AGENT_NEEDLES) + r")", re.IGNORECASE
)


def _has_stop_gate(config: CodexConfig) -> bool:
    return any(config.has_hook("Stop", needle) for needle in _STOP_GATE_NEEDLES)


def _has_verification_agent(config: CodexConfig) -> bool:
    return any(_VERIFY_AGENT_RE.search(agent.name) for agent in config.agents)


def _stop_gate(config: CodexConfig) -> CheckOutcome:
    if _has_stop_gate(config):
        return passed("A Stop hook runs a verification gate when the agent finishes a turn.")
    return failed("No Stop-gate hook verifies completion before the agent yields.")


def _verification_agent(config: CodexConfig) -> CheckOutcome:
    if _has_verification_agent(config):
        return passed("A dedicated verification / QA / closeout agent role is declared.")
    return failed("No QA / closeout / review agent role independently verifies completion claims.")


CHECKS: list[Check[CodexConfig]] = [
    Check(
        id="CDX-D6-01",
        dimension="D6",
        title="Stop-gate verifies completion",
        weight=2,
        evaluate=_stop_gate,
        severity=Severity.MEDIUM,
        detectability=Detectability.STATIC,
        remediation="Add a Stop hook that runs build/test/verification before the agent yields.",
    ),
    Check(
        id="CDX-D6-02",
        dimension="D6",
        title="Independent verification agent role",
        weight=1,
        evaluate=_verification_agent,
        severity=Severity.LOW,
        detectability=Detectability.STATIC,
        remediation="Declare a QA or closeout-auditor agent that verifies completion claims.",
    ),
]

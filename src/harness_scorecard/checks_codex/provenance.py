"""D9 (Codex) - Memory / provenance hygiene.

Where do the agent's behavior and history come from? Subagent roles defined in tracked config
files are auditable; a persisted session history keeps a durable record of what the agent did.
"""

from __future__ import annotations

from harness_scorecard.checks.base import (
    Check,
    CheckOutcome,
    failed,
    not_applicable,
    partial,
    passed,
)
from harness_scorecard.discovery_codex import CodexConfig
from harness_scorecard.models import Detectability, Severity

_PERSISTED = ("save-all", "save")


def _agent_provenance(config: CodexConfig) -> CheckOutcome:
    if not config.agents:
        return not_applicable("No subagent roles are declared.")
    with_files = [agent.name for agent in config.agents if agent.config_file]
    if len(with_files) == len(config.agents):
        return passed(
            "Every subagent role is defined in a tracked config file.", evidence=with_files
        )
    if with_files:
        return partial(
            f"Only {len(with_files)} of {len(config.agents)} subagent roles have a config_file.",
            evidence=with_files,
        )
    return failed("Subagent roles carry no config_file; their behavior is not provenance-tracked.")


def _history_persisted(config: CodexConfig) -> CheckOutcome:
    persistence = config.history_persistence
    normalized = persistence.lower() if persistence else persistence
    if normalized in _PERSISTED:
        return passed(f"Session history is persisted (history.persistence={persistence}).")
    if normalized in (None, "none"):
        return failed("Session history is not persisted; no durable record of agent actions.")
    return partial(f"Unrecognized history.persistence={persistence!r}; cannot confirm a record.")


CHECKS: list[Check[CodexConfig]] = [
    Check(
        id="CDX-D9-01",
        dimension="D9",
        title="Subagent roles are provenance-tracked",
        weight=1,
        evaluate=_agent_provenance,
        severity=Severity.LOW,
        detectability=Detectability.STATIC,
        remediation="Define each [agents.*] role in a tracked config_file rather than inline.",
    ),
    Check(
        id="CDX-D9-02",
        dimension="D9",
        title="Session history is persisted",
        weight=1,
        evaluate=_history_persisted,
        severity=Severity.MEDIUM,
        detectability=Detectability.STATIC,
        remediation='Set [history].persistence = "save-all" to keep a durable record of actions.',
    ),
]

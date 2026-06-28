"""D2 (Codex) - Egress / exfiltration control.

The agent's primary outbound channel is the command sandbox's network access, which Codex
denies by default in read-only and workspace-write modes. Web search is a second, narrower
channel. Defense in depth adds an egress-monitoring hook on top of the sandbox.
"""

from __future__ import annotations

from harness_scorecard.checks.base import Check, CheckOutcome, failed, partial, passed
from harness_scorecard.discovery_codex import CodexConfig
from harness_scorecard.models import Detectability, Severity

_SAFE_WEB_SEARCH = ("off", "disabled", "cached")
# Compound/specific needles only: bare "outbound" credits webhook dispatchers that *initiate*
# egress rather than guard it.
_EGRESS_NEEDLES = ("egress", "exfil", "network-guard", "outbound-guard")


def _has_egress_hook(config: CodexConfig) -> bool:
    return any(config.has_hook("PreToolUse", needle) for needle in _EGRESS_NEEDLES)


def _network_blocked(config: CodexConfig) -> CheckOutcome:
    if config.network_blocked:
        return passed(
            "The sandbox denies outbound network to spawned commands.",
            evidence=[
                f"sandbox_mode={config.sandbox_mode}",
                f"network_access={config.network_access}",
            ],
        )
    return failed(
        "Outbound network is open: danger-full-access sandbox or "
        "[sandbox_workspace_write].network_access = true.",
        evidence=[f"sandbox_mode={config.sandbox_mode}"],
    )


def _web_search_channel(config: CodexConfig) -> CheckOutcome:
    if config.web_search in _SAFE_WEB_SEARCH:
        return passed(f"web_search={config.web_search} does not fetch live pages.")
    if config.web_search == "live":
        return failed("web_search=live fetches live web pages -- an ingestion/egress channel.")
    return partial(f"Unrecognized web_search={config.web_search!r}; cannot confirm it is bounded.")


def _egress_monitoring(config: CodexConfig) -> CheckOutcome:
    if _has_egress_hook(config):
        return passed("An egress-guard hook monitors or blocks outbound network calls.")
    if config.network_blocked:
        return partial(
            "Network is blocked by the sandbox, but no hook independently monitors egress.",
        )
    return failed("Network is open and no egress-guard hook monitors outbound traffic.")


CHECKS: list[Check[CodexConfig]] = [
    Check(
        id="CDX-D2-01",
        dimension="D2",
        title="Sandbox denies outbound network",
        weight=2,
        evaluate=_network_blocked,
        severity=Severity.HIGH,
        detectability=Detectability.STATIC,
        remediation=(
            "Use read-only or workspace-write sandbox and leave "
            "[sandbox_workspace_write].network_access unset (false)."
        ),
    ),
    Check(
        id="CDX-D2-02",
        dimension="D2",
        title="Web search does not fetch live pages",
        weight=1,
        evaluate=_web_search_channel,
        severity=Severity.MEDIUM,
        detectability=Detectability.STATIC,
        remediation="Set web_search to 'cached' or 'disabled' unless live fetching is required.",
    ),
    Check(
        id="CDX-D2-03",
        dimension="D2",
        title="Egress is independently monitored",
        weight=1,
        evaluate=_egress_monitoring,
        severity=Severity.MEDIUM,
        detectability=Detectability.STATIC,
        remediation=(
            "Add a hook that audits or blocks outbound network commands as defense in depth."
        ),
    ),
]

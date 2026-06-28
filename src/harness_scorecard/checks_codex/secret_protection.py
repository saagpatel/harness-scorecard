"""D1 (Codex) - Secret protection & credential isolation.

Codex's filesystem sandbox bounds *writes* but lets the agent *read* most of the disk, so
credential protection rests on three things: keeping secrets out of the subprocess environment
(the default-exclude scrubbing), guarding reads of credential stores with a hook, and bounding
write blast-radius with a real sandbox. The env-scrub gate caps the grade at D when secrets are
exposed to every command the agent runs.
"""

from __future__ import annotations

from harness_scorecard.checks.base import Check, CheckOutcome, failed, passed
from harness_scorecard.discovery_codex import CodexConfig
from harness_scorecard.models import Detectability, Grade, Severity

# Specific enough that an incidental collision in an unrelated hook name is implausible.
# Bare "ssh" was dropped: it credits access-expanding hooks (ssh-tunnel, setup-ssh-keys).
_CRED_NEEDLES = ("credential", "secret", "redact", "gnupg", "aws")


def _has_credential_read_guard(config: CodexConfig) -> bool:
    return any(config.has_hook("PreToolUse", needle) for needle in _CRED_NEEDLES)


def _env_secret_exposure(config: CodexConfig) -> CheckOutcome:
    if config.env_secrets_scrubbed:
        return passed(
            "Secret-looking env vars are kept out of the spawned subprocess environment.",
            evidence=[f"shell_environment_policy.inherit = {config.env_inherit or 'default'}"],
        )
    return failed(
        "Secrets leak into every command the agent runs: the default secret excludes are "
        "disabled or a secret-named var is set explicitly.",
        evidence=[
            f"ignore_default_excludes = {config.env_ignore_default_excludes}",
            f"inherit = {config.env_inherit or 'default'}",
        ],
    )


def _credential_read_guard(config: CodexConfig) -> CheckOutcome:
    if _has_credential_read_guard(config):
        return passed("A PreToolUse hook guards reads of credential stores.")
    return failed(
        "No hook guards credential reads; Codex's sandbox permits reading ~/.ssh, ~/.aws, etc.",
    )


def _sandbox_bounds_writes(config: CodexConfig) -> CheckOutcome:
    if not config.sandbox_disabled:
        return passed(
            f"The {config.sandbox_mode} sandbox bounds where exfiltrated secrets can be written.",
        )
    return failed(
        "sandbox_mode = danger-full-access removes the sandbox; secrets can be written anywhere.",
    )


CHECKS: list[Check[CodexConfig]] = [
    Check(
        id="CDX-D1-01",
        dimension="D1",
        title="Keep secrets out of the subprocess environment",
        weight=3,
        evaluate=_env_secret_exposure,
        severity=Severity.CRITICAL,
        detectability=Detectability.STATIC,
        is_gate=True,
        gate_cap=Grade.D,
        remediation=(
            "Leave shell_environment_policy.ignore_default_excludes unset (false) and do not "
            "place secret-named vars in [shell_environment_policy.set]."
        ),
    ),
    Check(
        id="CDX-D1-02",
        dimension="D1",
        title="Guard reads of credential stores",
        weight=2,
        evaluate=_credential_read_guard,
        severity=Severity.HIGH,
        detectability=Detectability.STATIC,
        remediation=(
            "Add a PreToolUse hook that blocks reading ~/.ssh, ~/.aws, ~/.gnupg, and similar "
            "credential paths (the sandbox alone does not stop reads)."
        ),
        dispatcher_evidence=(
            r"\bSENSITIVE_PATH_RE\b",
            r"home-level credential",
            r"\.ssh\b.{0,40}\.aws\b",
        ),
    ),
    Check(
        id="CDX-D1-03",
        dimension="D1",
        title="Bound write blast-radius with a sandbox",
        weight=2,
        evaluate=_sandbox_bounds_writes,
        severity=Severity.HIGH,
        detectability=Detectability.STATIC,
        remediation=(
            "Use sandbox_mode = workspace-write (or read-only) instead of danger-full-access."
        ),
    ),
]

"""D1 - Secret protection & credential isolation."""

from __future__ import annotations

from harness_scorecard.checks.base import Check, CheckOutcome, failed, partial, passed
from harness_scorecard.discovery import HarnessConfig
from harness_scorecard.models import Detectability, Grade, Severity

# Core sensitive paths a mature harness denies for read. Each entry: (label, needles)
# where any needle appearing in a deny entry counts the path as covered.
_CORE_SECRET_PATHS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("~/.ssh", (".ssh",)),
    ("~/.aws", (".aws",)),
    ("~/.gnupg", (".gnupg",)),
    ("1Password/op", ("/op/", ".op", "1password")),
    ("gcloud", ("gcloud",)),
    (".env files", (".env",)),
)


def _check_sensitive_paths_denied(config: HarnessConfig) -> CheckOutcome:
    covered: list[str] = []
    missing: list[str] = []
    for label, needles in _CORE_SECRET_PATHS:
        if config.deny_matches(*needles):
            covered.append(label)
        else:
            missing.append(label)
    if not covered:
        return failed(
            "No sensitive credential paths are denied for read; secrets are readable.",
            evidence=[f"missing: {', '.join(missing)}"],
        )
    if missing:
        return partial(
            f"{len(covered)}/{len(_CORE_SECRET_PATHS)} core credential paths denied.",
            evidence=[f"covered: {', '.join(covered)}", f"missing: {', '.join(missing)}"],
        )
    return passed(
        "All core credential paths are denied for read.",
        evidence=[f"covered: {', '.join(covered)}"],
    )


def _check_sensitive_read_backstop(config: HarnessConfig) -> CheckOutcome:
    if config.has_hook("PreToolUse", "protect-sensitive-reads", matcher="Bash") or config.has_hook(
        "PreToolUse", "bash-secret", matcher="Bash"
    ):
        return passed("A PreToolUse Bash hook backstops sensitive-file reads.")
    return failed(
        "No Bash-level backstop for sensitive reads; deny lists cover only the Read tool.",
    )


def _check_write_time_secret_scan(config: HarnessConfig) -> CheckOutcome:
    if config.has_hook("PreToolUse", "detect-secrets", matcher="Write") or config.has_hook(
        "PostToolUse", "semgrep"
    ):
        return passed("Secrets are scanned at write/commit time.")
    return failed("No write-time secret scanning (detect-secrets / semgrep) is configured.")


def _check_token_store_protected(config: HarnessConfig) -> CheckOutcome:
    if config.deny_matches(".tokens", ".state", ".credentials"):
        return passed("The harness's own token/state store is read-protected.")
    return failed("The harness token/state store is not denied; approval tokens are forgeable.")


def _check_telemetry_disabled(config: HarnessConfig) -> CheckOutcome:
    telemetry = config.env_flag_enabled("DISABLE_TELEMETRY")
    error_report = config.env_flag_enabled("DISABLE_ERROR_REPORTING")
    if telemetry and error_report:
        return passed("Telemetry and error reporting are both disabled.")
    if telemetry or error_report:
        return partial("Only one of telemetry / error reporting is disabled.")
    return failed("Telemetry and error reporting are not disabled; payloads may ship off-box.")


def _check_wallet_protected(config: HarnessConfig) -> CheckOutcome:
    if config.deny_matches("metamask", "phantom", "wallet", "keystore"):
        return passed("Crypto-wallet keystore paths are denied for read.")
    return failed("Browser-extension wallet storage is not denied for read.")


CHECKS: list[Check] = [
    Check(
        id="HS-D1-01",
        dimension="D1",
        title="Sensitive credential paths denied for read",
        weight=5,
        evaluate=_check_sensitive_paths_denied,
        severity=Severity.CRITICAL,
        is_gate=True,
        gate_cap=Grade.D,
        remediation=(
            "Add Read(...) deny globs for ~/.ssh, ~/.aws, ~/.gnupg, op/gcloud configs, "
            "and **/.env*."
        ),
    ),
    Check(
        id="HS-D1-02",
        dimension="D1",
        title="Sensitive-read Bash backstop",
        weight=3,
        evaluate=_check_sensitive_read_backstop,
        severity=Severity.HIGH,
        remediation="Add a PreToolUse Bash hook that re-blocks reads of sensitive files.",
        dispatcher_evidence=(
            r"\.ssh\b",
            r"\.aws\b",
            r"protect[_-]?sensitive[_-]?read",
        ),
    ),
    Check(
        id="HS-D1-03",
        dimension="D1",
        title="Write-time secret scanning",
        weight=3,
        evaluate=_check_write_time_secret_scan,
        severity=Severity.HIGH,
        remediation="Add a PreToolUse Edit/Write secret detector and/or a PostToolUse secret scan.",
    ),
    Check(
        id="HS-D1-04",
        dimension="D1",
        title="Harness token/state store protected",
        weight=2,
        evaluate=_check_token_store_protected,
        severity=Severity.MEDIUM,
        remediation="Deny Read/Write/Glob on the harness approval-token and state directories.",
    ),
    Check(
        id="HS-D1-05",
        dimension="D1",
        title="Telemetry & error-reporting disabled",
        weight=2,
        evaluate=_check_telemetry_disabled,
        severity=Severity.MEDIUM,
        remediation="Set env DISABLE_TELEMETRY=1 and DISABLE_ERROR_REPORTING=1.",
    ),
    Check(
        id="HS-D1-06",
        dimension="D1",
        title="Wallet/keystore paths protected",
        weight=1,
        evaluate=_check_wallet_protected,
        severity=Severity.LOW,
        detectability=Detectability.STATIC,
        remediation="Deny Read on browser-extension wallet storage directories.",
    ),
]

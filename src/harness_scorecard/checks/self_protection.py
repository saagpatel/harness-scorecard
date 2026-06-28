"""D5 - Harness self-protection & integrity.

Guards the harness against tampering with its own enforcement layer: write/read protection
of the config surface, hook-integrity verification, and snapshot/validate around edits.
"""

from __future__ import annotations

from harness_scorecard.checks.base import Check, CheckOutcome, failed, partial, passed
from harness_scorecard.discovery import HarnessConfig
from harness_scorecard.models import Grade, Severity


def _has_write_protection(config: HarnessConfig) -> bool:
    # The config-write vector is guarded only if BOTH the Edit and Write tools are covered
    # by a file guard, OR a dedicated Bash write guard is present. A file guard that covers
    # just one of Edit/Write leaves the other tool able to mutate the config.
    files_cover_both = config.has_hook(
        "PreToolUse", "protect-files", matcher="Edit"
    ) and config.has_hook("PreToolUse", "protect-files", matcher="Write")
    bash_write_guard = config.has_hook("PreToolUse", "protect-claude-writes", matcher="Bash")
    return files_cover_both or bash_write_guard


def _has_read_protection(config: HarnessConfig) -> bool:
    return config.has_hook("PreToolUse", "protect-files", matcher="Read")


def _check_config_write_protected(config: HarnessConfig) -> CheckOutcome:
    has_write = _has_write_protection(config)
    has_read = _has_read_protection(config)
    if has_write and has_read:
        return passed(
            "Harness config is protected on both the write and read paths.",
            evidence=["write-path guard present", "read-path guard present"],
        )
    if has_write or has_read:
        covered = "write-path" if has_write else "read-path"
        missing = "read-path" if has_write else "write-path"
        return partial(
            f"Only the {covered} guard protects the harness config; {missing} is unguarded.",
            evidence=[f"{missing} guard missing (parity gap)"],
        )
    return failed(
        "The harness config surface (hooks/settings/agents/skills) is unprotected.",
        evidence=["no read-path or write-path guard found"],
    )


def _check_hook_integrity(config: HarnessConfig) -> CheckOutcome:
    has_verify = config.has_hook("SessionStart", "hook-integrity-verify")
    has_self_heal = config.has_hook("SessionStart", "harness-self-heal") or config.has_hook(
        "SessionStart", "hook-integrity-regen"
    )
    if has_verify and has_self_heal:
        return passed("Hook integrity is verified and self-healed at session start.")
    if has_verify:
        return partial(
            "Hook integrity is verified at session start, but there is no self-heal.",
            evidence=["self-heal/regen hook missing"],
        )
    return failed(
        "No hook-integrity verification; a silently disabled hook would go undetected.",
        evidence=["no SessionStart hook-integrity-verify found"],
    )


def _check_config_snapshot(config: HarnessConfig) -> CheckOutcome:
    # Only a per-edit snapshot counts; a SessionStart validator (e.g. settings-guard) is a
    # startup check, not a pre-mutation backup, so it is not credited here.
    has_snapshot = config.has_hook(
        "PreToolUse", "harness-config-snapshot", matcher="Edit"
    ) or config.has_hook("PreToolUse", "harness-config-snapshot", matcher="Write")
    has_validate = config.has_hook("PostToolUse", "harness-config-validate")
    if has_snapshot and has_validate:
        return passed("Config edits are snapshotted before and validated after.")
    if has_snapshot or has_validate:
        present = "snapshot-before-edit" if has_snapshot else "post-edit validation"
        missing = "post-edit validation" if has_snapshot else "snapshot-before-edit"
        return partial(
            f"Only {present} is configured around harness-config edits.",
            evidence=[f"{missing} missing"],
        )
    return failed(
        "No snapshot/validate around config edits; a truncation to a bypass stub is unrecoverable.",
        evidence=["no harness-config-snapshot or harness-config-validate hook found"],
    )


CHECKS: list[Check] = [
    Check(
        id="HS-D5-01",
        dimension="D5",
        title="Harness config write/read protected",
        weight=5,
        evaluate=_check_config_write_protected,
        severity=Severity.CRITICAL,
        is_gate=True,
        gate_cap=Grade.C,
        remediation=(
            "Guard the harness config on BOTH paths: a PreToolUse Bash write guard and a "
            "PreToolUse Read/Edit/Write file guard over hooks/settings/agents/skills."
        ),
        # Gate (cap C): introspection only ever *suggests* this; a gate is never auto-credited.
        # Anchored to protection-verb guard names, not a bare ".claude/" path -- integrity (D5-02)
        # and snapshot (D5-03) code also reference those paths, so a path alone cross-credits.
        dispatcher_evidence=(
            r"protect[_-]?claude",
            r"protect[_-]?files\b",
            r"protect[_-]?(?:config|settings)\b",
        ),
    ),
    Check(
        id="HS-D5-02",
        dimension="D5",
        title="Hook integrity verify + self-heal",
        weight=4,
        evaluate=_check_hook_integrity,
        severity=Severity.HIGH,
        remediation=(
            "Add a SessionStart hook-integrity verification (and a self-heal/regen) so a "
            "disabled or edited guard is detected and repaired."
        ),
        dispatcher_evidence=(
            r"(?:hook|harness)[_-]?integrity",
            r"self[_-]?heal",
            r"integrity[_-]?(?:verify|regen|check)",
        ),
    ),
    Check(
        id="HS-D5-03",
        dimension="D5",
        title="Config snapshot/validate around edits",
        weight=3,
        evaluate=_check_config_snapshot,
        severity=Severity.MEDIUM,
        remediation=(
            "Snapshot settings.json before edits and validate it after, so a truncation to a "
            "bypass-accept stub is caught and reversible."
        ),
        dispatcher_evidence=(
            r"config[_-]?snapshot",
            r"config[_-]?validate",
            r"snapshot[_-]?before[_-]?edit",
        ),
    ),
]

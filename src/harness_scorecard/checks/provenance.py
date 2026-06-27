"""D9 - Memory / provenance hygiene."""

from __future__ import annotations

from harness_scorecard.checks.base import Check, CheckOutcome, failed, partial, passed
from harness_scorecard.discovery import HarnessConfig
from harness_scorecard.models import Severity


def _check_skill_install_gate(config: HarnessConfig) -> CheckOutcome:
    # Both Write (create/replace) and Edit (patch) can clobber a skill, so both must be gated.
    has_write = config.has_hook("PreToolUse", "skill-install", matcher="Write")
    has_edit = config.has_hook("PreToolUse", "skill-install", matcher="Edit")
    if has_write and has_edit:
        return passed("A skill-install gate guards both the Write and Edit channels.")
    if has_write or has_edit:
        covered = "Write" if has_write else "Edit"
        return partial(f"The skill-install gate covers only the {covered} channel.")
    return failed("No skill-install gate; a skill pack can overwrite a user skill unnoticed.")


def _check_skill_catalog_bounds(config: HarnessConfig) -> CheckOutcome:
    has_budget = config.has_setting("skillListingBudgetFraction")
    has_desc_cap = config.has_setting("maxSkillDescriptionChars")
    if has_budget and has_desc_cap:
        return passed("Skill-catalog injection is bounded (budget fraction + description cap).")
    if has_budget or has_desc_cap:
        covered = "budget fraction" if has_budget else "description cap"
        return partial(f"Only the skill-catalog {covered} is set.")
    return failed("Skill-catalog injection is unbounded; re-injection can blow the context budget.")


CHECKS: list[Check] = [
    Check(
        id="HS-D9-01",
        dimension="D9",
        title="Skill-install provenance gate",
        weight=3,
        evaluate=_check_skill_install_gate,
        severity=Severity.MEDIUM,
        remediation="Add a PreToolUse Write/Edit skill-install gate plus a skill-provenance rule.",
    ),
    Check(
        id="HS-D9-02",
        dimension="D9",
        title="Skill-catalog injection bounds",
        weight=2,
        evaluate=_check_skill_catalog_bounds,
        severity=Severity.LOW,
        remediation="Set skillListingBudgetFraction and maxSkillDescriptionChars in settings.",
    ),
]

"""Codex check registry: assembles the Codex adapter's checks into one ordered list.

The rubric dimensions (and the scoring engine) are shared with Claude Code; only the check
*implementations* differ, because Codex's guard surface is a sandbox + approval policy + trust
levels + hooks rather than a permission mode + deny globs.
"""

from __future__ import annotations

from harness_scorecard.checks.base import Check
from harness_scorecard.checks_codex import (
    destructive_git,
    secret_protection,
    self_protection,
)
from harness_scorecard.discovery_codex import CodexConfig

# Order = rubric dimension order. New Codex dimension modules append here as they land.
CODEX_CHECKS: list[Check[CodexConfig]] = [
    *secret_protection.CHECKS,
    *destructive_git.CHECKS,
    *self_protection.CHECKS,
]

__all__ = ["CODEX_CHECKS"]

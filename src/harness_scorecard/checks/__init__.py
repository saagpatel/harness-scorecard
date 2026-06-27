"""Check registry: assembles every dimension's checks into one ordered list."""

from __future__ import annotations

from harness_scorecard.checks import (
    destructive_git,
    egress,
    secret_protection,
    self_protection,
    tool_surface,
)
from harness_scorecard.checks.base import DIMENSIONS, Check, Dimension

# Order = dimension order in the rubric. New dimension modules append here as they land.
ALL_CHECKS: list[Check] = [
    *secret_protection.CHECKS,
    *egress.CHECKS,
    *tool_surface.CHECKS,
    *destructive_git.CHECKS,
    *self_protection.CHECKS,
]

# Dimensions that actually have checks this version (used to report coverage honestly).
IMPLEMENTED_DIMENSION_IDS: list[str] = list(dict.fromkeys(check.dimension for check in ALL_CHECKS))

__all__ = ["ALL_CHECKS", "DIMENSIONS", "IMPLEMENTED_DIMENSION_IDS", "Check", "Dimension"]

"""Detect the harness type at a path and select the matching adapter + check set.

Claude Code is identified by ``settings.json`` / ``settings.local.json``; Codex by
``config.toml`` / ``AGENTS.md``. The caller can force a type to override auto-detection.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from harness_scorecard.checks import ALL_CHECKS
from harness_scorecard.checks_codex import CODEX_CHECKS
from harness_scorecard.discovery import HARNESS_TYPE_CLAUDE_CODE, load_harness
from harness_scorecard.discovery_codex import HARNESS_TYPE_CODEX, load_codex_harness

if TYPE_CHECKING:
    from collections.abc import Sequence
    from typing import Any

    from harness_scorecard.checks.base import Check
    from harness_scorecard.scoring import ScorableConfig

AUTO = "auto"
HARNESS_TYPES = (AUTO, HARNESS_TYPE_CLAUDE_CODE, HARNESS_TYPE_CODEX)


def detect_harness_type(root: Path) -> str | None:
    """Return the detected harness type, or ``None`` if nothing identifiable is present.

    ``settings.json`` is the definitive Claude Code marker and takes precedence: ``config.toml``
    is a generic filename many tools use, so a directory carrying both is treated as Claude
    Code. Pass an explicit ``--type`` to override this on an unusual layout.
    """
    if (root / "settings.json").exists() or (root / "settings.local.json").exists():
        return HARNESS_TYPE_CLAUDE_CODE
    if (root / "config.toml").exists() or (root / "AGENTS.md").exists():
        return HARNESS_TYPE_CODEX
    return None


def select_adapter(
    root: Path,
    harness_type: str = AUTO,
) -> tuple[ScorableConfig, Sequence[Check[Any]]]:
    """Load the right config and return it with the matching check set.

    Raises ``FileNotFoundError`` when auto-detection finds no recognizable harness.
    """
    resolved = harness_type
    if resolved == AUTO:
        detected = detect_harness_type(root)
        if detected is None:
            msg = f"No Claude Code or Codex harness found at {root}"
            raise FileNotFoundError(msg)
        resolved = detected

    if resolved == HARNESS_TYPE_CODEX:
        return load_codex_harness(root), CODEX_CHECKS
    return load_harness(root), ALL_CHECKS

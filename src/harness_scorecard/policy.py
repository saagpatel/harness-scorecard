"""Operator policy file (`.harness-scorecard.toml`): accepted gaps and declared enforcements.

Two mechanisms, one file, both transparent in the report:

- ``[[waiver]]`` accepts a known finding (with a reason) so it stops dragging the grade. A
  waived finding is excluded from scoring and its gate cap is suppressed, but it is always
  listed in the report -- a waiver is a documented decision, never a silent suppression.
- ``[dispatcher].credits`` lets a harness whose guards live behind an opaque dispatcher declare
  which checks that dispatcher enforces. A declared check that would FAIL is upgraded to PARTIAL
  (half credit, flagged "declared, not statically verified") -- the honest middle between
  under-crediting an invisible guard and trusting an unverifiable claim outright.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

POLICY_FILENAME = ".harness-scorecard.toml"


@dataclass(frozen=True, slots=True)
class Waiver:
    """One accepted finding: a check id and the reason it is deliberately tolerated."""

    check: str
    reason: str


@dataclass(frozen=True, slots=True)
class Policy:
    """The parsed operator policy: accepted waivers + dispatcher-declared check credits."""

    waivers: tuple[Waiver, ...] = ()
    dispatcher_credits: tuple[str, ...] = ()

    @property
    def waiver_map(self) -> dict[str, str]:
        """Check id -> waiver reason. Later entries win on a duplicate id."""
        return {waiver.check: waiver.reason for waiver in self.waivers}

    @property
    def is_empty(self) -> bool:
        return not self.waivers and not self.dispatcher_credits


EMPTY_POLICY = Policy()


def find_policy(harness_root: Path) -> Path | None:
    """The auto-discovered policy file in a harness root, or ``None`` if absent."""
    candidate = harness_root / POLICY_FILENAME
    return candidate if candidate.is_file() else None


def _parse_waivers(raw: Any) -> list[Waiver]:
    if not isinstance(raw, list):
        msg = "'waiver' must be an array of tables ([[waiver]])"
        raise ValueError(msg)
    waivers: list[Waiver] = []
    for entry in raw:
        if not isinstance(entry, dict):
            msg = "each [[waiver]] must be a table with a 'check' key"
            raise ValueError(msg)
        check = entry.get("check")
        if not isinstance(check, str) or not check:
            msg = "each [[waiver]] needs a non-empty 'check' id"
            raise ValueError(msg)
        waivers.append(Waiver(check=check, reason=str(entry.get("reason", ""))))
    return waivers


def _parse_credits(raw: Any) -> list[str]:
    if not isinstance(raw, dict):
        msg = "'dispatcher' must be a table"
        raise ValueError(msg)
    credit_ids = raw.get("credits", [])
    if not isinstance(credit_ids, list):
        msg = "[dispatcher].credits must be a list of check ids"
        raise ValueError(msg)
    return [str(item) for item in credit_ids]


def load_policy(path: Path) -> Policy:
    """Parse a ``.harness-scorecard.toml`` policy file. Raises ``ValueError`` if malformed."""
    try:
        with path.open("rb") as handle:
            data = tomllib.load(handle)
    except tomllib.TOMLDecodeError as exc:
        msg = f"malformed policy file: {exc}"
        raise ValueError(msg) from exc
    return Policy(
        waivers=tuple(_parse_waivers(data.get("waiver", []))),
        dispatcher_credits=tuple(_parse_credits(data.get("dispatcher", {}))),
    )

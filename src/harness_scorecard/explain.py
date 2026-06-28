"""``harness-scorecard explain <CHECK_ID>`` — the why-and-fix behind a single check.

Bridges a scan finding to its rationale: given a check id (``HS-D4-01``, ``CDX-D1-01``, …),
it surfaces the check's metadata, the documented red-team **failure mode** it guards against,
the **remediation**, and — for the gated checks — a pointer to the vulnerable/guarded
**proof** pair in ``examples/redteam/``. Pure and read-only: it reads the in-code check
catalog and narrative registry, never the audited harness, so there is nothing to redact.
"""

from __future__ import annotations

import json
import textwrap
from itertools import chain
from typing import TYPE_CHECKING, Any

from harness_scorecard.checks import ALL_CHECKS
from harness_scorecard.checks.base import DIMENSIONS
from harness_scorecard.checks_codex import CODEX_CHECKS
from harness_scorecard.failure_modes import FAILURE_MODES

if TYPE_CHECKING:
    from harness_scorecard.checks.base import Check

# The gated checks each have a vulnerable/guarded proof pair under examples/redteam/.
# Value = the corpus directory (relative to the repo root); its ATTACK.md is the writeup.
CORPUS_ENTRIES: dict[str, str] = {
    "HS-D1-01": "examples/redteam/claude-d1-credential-exposure",
    "HS-D4-01": "examples/redteam/claude-d4-inert-harddeny",
    "HS-D5-01": "examples/redteam/claude-d5-unprotected-config",
    "CDX-D1-01": "examples/redteam/codex-d1-env-secret-leak",
    "CDX-D4-01": "examples/redteam/codex-d4-full-access",
    "CDX-D5-01": "examples/redteam/codex-d5-self-mutable",
}

_WIDTH = 88
# Shown when a check somehow has no narrative; the registry meta-test makes this unreachable
# today, but the console and JSON renderers must agree so the representation never diverges.
_MISSING_NARRATIVE = "(no failure mode on file)"


def _catalog() -> dict[str, Check[Any]]:
    """Every registered check (both adapters) keyed by id. Ids never collide across suites."""
    return {check.id: check for check in chain(ALL_CHECKS, CODEX_CHECKS)}


def find_check(check_id: str) -> Check[Any] | None:
    """Resolve a check by id, case-insensitively. Returns ``None`` if no such check exists."""
    return _catalog().get(check_id.strip().upper())


def all_check_ids() -> list[str]:
    """Every registered check id, in catalog order — used to suggest valid ids on a miss."""
    return [check.id for check in chain(ALL_CHECKS, CODEX_CHECKS)]


def to_explain_dict(check: Check[Any]) -> dict[str, Any]:
    """A JSON-serializable explanation of one check. No harness input, so nothing to redact."""
    dimension = DIMENSIONS.get(check.dimension)
    return {
        "id": check.id,
        "title": check.title,
        "dimension": {
            "id": check.dimension,
            "name": dimension.name if dimension else check.dimension,
        },
        "weight": check.weight,
        "severity": check.severity.value,
        "detectability": check.detectability.value,
        "is_gate": check.is_gate,
        "gate_cap": check.gate_cap.value if check.gate_cap else None,
        "failure_mode": FAILURE_MODES.get(check.id, _MISSING_NARRATIVE),
        "remediation": check.remediation,
        "redteam_proof": CORPUS_ENTRIES.get(check.id),
    }


def _wrap(body: str) -> str:
    return textwrap.fill(body, width=_WIDTH, initial_indent="  ", subsequent_indent="  ")


def render_explain_console(check: Check[Any]) -> str:
    dimension = DIMENSIONS.get(check.dimension)
    dim_name = dimension.name if dimension else check.dimension
    out: list[str] = [
        f"{check.id}  ·  {check.title}",
        f"{check.dimension} — {dim_name}  ·  weight {check.weight}  ·  "
        f"{check.severity.value}  ·  {check.detectability.value}",
    ]
    if check.is_gate and check.gate_cap is not None:
        out.append(f"GATE: a failing result caps the grade at {check.gate_cap.value}.")

    out += ["", "Why it matters", _wrap(FAILURE_MODES.get(check.id, _MISSING_NARRATIVE))]
    if check.remediation:
        out += ["", "How to fix it", _wrap(check.remediation)]

    proof = CORPUS_ENTRIES.get(check.id)
    if proof:
        out += [
            "",
            "Proof it's caught",
            f"  writeup:  {proof}/ATTACK.md",
            f"  FAIL it:  harness-scorecard scan {proof}/vulnerable",
            f"  PASS it:  harness-scorecard scan {proof}/guarded",
        ]
    return "\n".join(out)


def render_explain_json(check: Check[Any]) -> str:
    return json.dumps(to_explain_dict(check), indent=2)

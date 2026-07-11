"""Render a :class:`Scorecard` as a GitHub-flavored Markdown summary.

Intended for a CI step summary (``scan --summary "$GITHUB_STEP_SUMMARY"``): a PR reviewer sees
the grade, the capability gates that capped it, and every finding that needs attention — each
with the red-team **failure mode** it guards against and the fix — without leaving the run page.
Self-explanatory by design, so it always carries the failure modes (no ``--explain`` needed).

Dependency-free and redacted, like every other renderer: dynamic text passes through
``redact_text`` and nothing here reads or writes the audited harness.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from harness_scorecard.checks import DIMENSIONS
from harness_scorecard.failure_modes import FAILURE_MODES
from harness_scorecard.models import Status
from harness_scorecard.redaction import redact_text

if TYPE_CHECKING:
    from harness_scorecard.models import CheckResult, Scorecard

_STATUS_LABEL = {
    Status.FAIL: "FAIL",
    Status.PARTIAL: "PARTIAL",
    Status.UNKNOWN: "UNKNOWN",
}


def _actionable_findings(card: Scorecard) -> list[CheckResult]:
    """Every actionable or unresolved, non-waived finding, in dimension order."""
    return [
        check
        for dim in card.dimensions
        for check in dim.checks
        if check.status in (Status.FAIL, Status.PARTIAL, Status.UNKNOWN) and not check.waived
    ]


def _gate_table(card: Scorecard) -> list[str]:
    if not card.gate_caps:
        return []
    rows = [
        "### Capability gates tripped",
        "",
        "| Gate | Caps at | Check |",
        "| --- | :---: | --- |",
    ]
    for result in card.gate_caps:
        cap = result.triggered_gate_cap
        cap_value = cap.value if cap is not None else "?"
        rows.append(f"| `{result.id}` | **{cap_value}** | {_cell(result.title)} |")
    rows.append("")
    return rows


def _cell(text: str) -> str:
    """Redact, then escape ``|`` so a value can't break out of a GFM table cell."""
    return redact_text(text).replace("|", "\\|")


def _quote(label: str, text: str) -> list[str]:
    """A blockquoted ``**label:** text`` whose every line carries the ``>`` prefix.

    Splitting on newlines keeps a multi-line value (e.g. a multi-step fix) inside the
    blockquote instead of letting continuation lines escape as plain paragraphs.
    """
    lines = redact_text(text).splitlines() or [""]
    return [f"> **{label}:** {lines[0]}", *(f"> {line}" for line in lines[1:])]


def _finding_block(check: CheckResult) -> list[str]:
    label = _STATUS_LABEL.get(check.status, check.status.value.upper())
    gate = f" · gate→{check.gate_cap.value}" if check.is_gate and check.gate_cap else ""
    block = [f"**`{check.id}`** · {label}{gate} — {redact_text(check.title)}", ""]
    quoted: list[str] = []
    failure_mode = FAILURE_MODES.get(check.id) if check.status is not Status.UNKNOWN else None
    if failure_mode:
        quoted += _quote("Why", failure_mode)
    if check.status is Status.UNKNOWN:
        quoted += _quote("Unknown", check.message)
    if check.remediation:
        if quoted:
            quoted.append(">")
        quoted += _quote("Fix", check.remediation)
    block += [*quoted, ""]
    return block


def render_github_summary(card: Scorecard) -> str:
    """A GitHub-flavored Markdown report suitable for ``$GITHUB_STEP_SUMMARY``."""
    out: list[str] = [
        f"## Harness Scorecard — Grade {card.grade.value}",
        "",
        f"**{redact_text(card.harness_path)}** · `{card.harness_type}` · "
        f"overall **{card.overall_score:.2f} / 1.00** · "
        f"scored {len(card.dimensions)} of {len(DIMENSIONS)} dimensions · "
        f"rubric `{card.rubric_version}`",
        "",
    ]

    if card.caveats:
        out.append("> **Note:** a low score may be a static-analysis limit, not a missing guard:")
        out.extend(f"> - {redact_text(caveat)}" for caveat in card.caveats)
        out.append("")

    out.extend(_gate_table(card))

    findings = _actionable_findings(card)
    if not findings:
        out.append("**No findings to address** — every scored check passes. ")
        return "\n".join(out).rstrip() + "\n"

    out.append(f"### Findings to address ({len(findings)})")
    out.append("")
    for check in findings:
        out.extend(_finding_block(check))
    return "\n".join(out).rstrip() + "\n"

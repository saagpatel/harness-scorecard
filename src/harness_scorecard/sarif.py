"""Render a :class:`Scorecard` to SARIF 2.1.0 so CI (e.g. GitHub code scanning) can ingest it.

Mapping: every rubric check becomes a driver *rule*; every check that did not fully pass
(``FAIL`` or ``PARTIAL``) becomes a *result* — standard static-analysis semantics where a
clean subject emits no findings. SARIF ``level`` is derived from the check's severity, with a
``PARTIAL`` outcome downgraded one notch (a partial mitigation is less alarming than none).

Stdlib-only (``json``, ``hashlib``, ``re``). Privacy boundary: every human-facing free-text
field read from or about the scanned harness (rule/finding titles, messages, evidence,
remediation, and the harness path) passes through :func:`redact_text` before it reaches the
document. Structural machine identifiers (check/rule ids, dimension codes, severity/status/
grade enum values, the tool-controlled harness-type label, and the rubric version) are closed
tool-defined vocabularies, not harness-sourced text, and are emitted verbatim.
"""

from __future__ import annotations

import json
import re
from hashlib import sha256
from typing import Any

from harness_scorecard.models import CheckResult, Scorecard, Severity, Status
from harness_scorecard.redaction import redact_text

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
)
_TOOL_NAME = "harness-scorecard"
_INFORMATION_URI = "https://github.com/saagpatel/harness-scorecard"

# Only non-passing checks surface as findings; PASS / N/A leave the subject clean.
_RESULT_STATUSES = (Status.FAIL, Status.PARTIAL)

# SARIF level for a FAIL, by severity. A PARTIAL downgrades one notch (see _result_level).
_SEVERITY_LEVEL: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
}
_DOWNGRADE: dict[str, str] = {"error": "warning", "warning": "note", "note": "note"}

# GitHub code scanning ranks alerts by this numeric rule property.
_SECURITY_SEVERITY: dict[Severity, str] = {
    Severity.CRITICAL: "9.0",
    Severity.HIGH: "7.0",
    Severity.MEDIUM: "4.0",
    Severity.LOW: "1.0",
}

_WORD = re.compile(r"[A-Za-z0-9]+")


def _result_level(check: CheckResult) -> str:
    base = _SEVERITY_LEVEL[check.severity]
    return _DOWNGRADE[base] if check.status is Status.PARTIAL else base


def _rule_name(title: str, fallback_id: str) -> str:
    """A PascalCase opaque identifier SARIF viewers show beside the rule id.

    Derived from the already-redacted title so no harness-sourced text leaks via the name.
    """
    name = "".join(word[:1].upper() + word[1:] for word in _WORD.findall(title))
    return name or fallback_id.replace("-", "")


def _fingerprint(check: CheckResult, harness_type: str) -> str:
    """Stable per-(check, harness) id so CI can track an alert across runs."""
    return sha256(f"{check.id}\0{harness_type}".encode()).hexdigest()


def _all_checks(card: Scorecard) -> list[CheckResult]:
    return [check for dim in card.dimensions for check in dim.checks]


def _make_rule(check: CheckResult) -> dict[str, Any]:
    properties: dict[str, Any] = {
        "dimension": check.dimension,
        "severity": check.severity.value,
        "detectability": check.detectability.value,
        "is_gate": check.is_gate,
        "security-severity": _SECURITY_SEVERITY[check.severity],
    }
    if check.gate_cap is not None:
        properties["gate_cap"] = check.gate_cap.value
    title = redact_text(check.title)
    return {
        "id": check.id,
        "name": _rule_name(title, check.id),
        "shortDescription": {"text": title},
        "fullDescription": {"text": title},
        "help": {"text": redact_text(check.remediation) if check.remediation else title},
        "helpUri": _INFORMATION_URI,
        "properties": properties,
    }


def _make_result(check: CheckResult, harness_type: str, uri: str) -> dict[str, Any]:
    message = redact_text(check.message)
    if check.remediation:
        message = f"{message} Suggested fix: {redact_text(check.remediation)}"
    properties: dict[str, Any] = {
        "dimension": check.dimension,
        "status": check.status.value,
        "severity": check.severity.value,
        "is_gate": check.is_gate,
    }
    cap = check.triggered_gate_cap
    if cap is not None:
        properties["caps_grade_at"] = cap.value
    if check.dispatcher_credited:
        properties["dispatcher_credited"] = True
    if check.evidence:
        properties["evidence"] = [redact_text(item) for item in check.evidence]
    result: dict[str, Any] = {
        "ruleId": check.id,
        "level": _result_level(check),
        "message": {"text": message},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}}}],
        "partialFingerprints": {"harnessScorecardStableId": _fingerprint(check, harness_type)},
        "properties": properties,
    }
    if check.waived:
        # A waived finding stays in the report but is marked suppressed so it doesn't alert --
        # the SARIF-native way to represent an accepted, triaged finding.
        result["suppressions"] = [
            {"kind": "external", "justification": redact_text(check.waiver_reason)}
        ]
    return result


def to_sarif(card: Scorecard) -> dict[str, Any]:
    """Build a SARIF 2.1.0 document (as a dict) from a scorecard. All strings are redacted."""
    uri = redact_text(card.harness_path)
    checks = _all_checks(card)
    return {
        "version": SARIF_VERSION,
        "$schema": SARIF_SCHEMA,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": _TOOL_NAME,
                        "version": card.rubric_version,
                        "informationUri": _INFORMATION_URI,
                        "rules": [_make_rule(check) for check in checks],
                    }
                },
                "results": [
                    _make_result(check, card.harness_type, uri)
                    for check in checks
                    if check.status in _RESULT_STATUSES
                ],
                "properties": {
                    "grade": card.grade.value,
                    "overall_score": round(card.overall_score, 4),
                    "harness_type": card.harness_type,
                    "rubric_version": card.rubric_version,
                    "caveats": [redact_text(caveat) for caveat in card.caveats],
                    "policy_notes": [redact_text(note) for note in card.policy_notes],
                },
            }
        ],
    }


def render_sarif(card: Scorecard) -> str:
    return json.dumps(to_sarif(card), indent=2)

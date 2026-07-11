"""UNKNOWN stays visible in every report while remaining outside the grade."""

import unittest

from harness_scorecard.htmlreport import render_html
from harness_scorecard.models import (
    CheckResult,
    Detectability,
    DimensionResult,
    Grade,
    Scorecard,
    Severity,
    Status,
)
from harness_scorecard.report import from_dict, render_console, to_dict
from harness_scorecard.sarif import to_sarif
from harness_scorecard.summary import render_github_summary


def _card() -> Scorecard:
    check = CheckResult(
        id="CDX-D7-03",
        dimension="D7",
        title="Persistent reasoning routes are bounded",
        status=Status.UNKNOWN,
        weight=1,
        message="The active invocation cannot be proven from static files.",
        severity=Severity.MEDIUM,
        detectability=Detectability.PARTIAL,
        remediation="Capture opt-in runtime evidence.",
    )
    return Scorecard(
        harness_path="~/.codex",
        harness_type="codex",
        rubric_version="1.5.0",
        overall_score=0.0,
        grade=Grade.F,
        dimensions=[
            DimensionResult(
                id="D7",
                name="Subagent isolation & governance",
                weight=3,
                score=0.0,
                checks=[check],
            )
        ],
    )


class TestUnknownOutputContracts(unittest.TestCase):
    def test_console_json_and_roundtrip(self) -> None:
        card = _card()
        console = render_console(card)
        data = to_dict(card)
        self.assertIn("[UNKN] CDX-D7-03", console)
        self.assertIn("Unknown checks excluded from the grade: 1", console)
        self.assertEqual(data["dimensions"][0]["checks"][0]["status"], "unknown")
        self.assertEqual(from_dict(data).dimensions[0].checks[0].status, Status.UNKNOWN)

    def test_sarif_html_and_summary(self) -> None:
        card = _card()
        result = to_sarif(card)["runs"][0]["results"][0]
        self.assertEqual(result["level"], "note")
        self.assertEqual(result["properties"]["status"], "unknown")
        self.assertIn("UNKNOWN", render_html(card))
        summary = render_github_summary(card)
        self.assertIn("UNKNOWN", summary)
        self.assertIn("**Unknown:**", summary)


if __name__ == "__main__":
    unittest.main()

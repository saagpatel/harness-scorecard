"""SARIF 2.1.0 output: envelope, rule/result mapping, level downgrade, redaction, CLI."""

import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path

from harness_scorecard.cli import main
from harness_scorecard.discovery import load_harness
from harness_scorecard.models import (
    CheckResult,
    DimensionResult,
    Grade,
    Scorecard,
    Severity,
    Status,
)
from harness_scorecard.sarif import render_sarif, to_sarif
from harness_scorecard.scoring import score_harness

FIXTURES = Path(__file__).parent / "fixtures"


def _all_check_ids(card: Scorecard) -> list[str]:
    return [check.id for dim in card.dimensions for check in dim.checks]


def _synthetic_card(
    message: str,
    *,
    status: Status = Status.FAIL,
    severity: Severity = Severity.HIGH,
    evidence: list[str] | None = None,
    title: str = "Block reading credential stores",
) -> Scorecard:
    check = CheckResult(
        id="HS-D1-01",
        dimension="D1",
        title=title,
        status=status,
        weight=3,
        message=message,
        severity=severity,
        is_gate=True,
        gate_cap=Grade.D,
        remediation="Add a permissions.deny rule for ~/.ssh.",
        evidence=evidence or [],
    )
    dim = DimensionResult(id="D1", name="Secret Protection", weight=3, score=0.0, checks=[check])
    return Scorecard(
        harness_path=os.path.expanduser("~") + "/.claude",  # noqa: PTH111 - test wants the literal home
        harness_type="claude-code",
        rubric_version="1.0.0",
        overall_score=0.0,
        grade=Grade.F,
        dimensions=[dim],
        gate_caps=[check],
    )


class TestSarifEnvelope(unittest.TestCase):
    def setUp(self) -> None:
        self.card = score_harness(load_harness(FIXTURES / "strong_harness"))
        self.doc = to_sarif(self.card)

    def test_is_sarif_210_document(self) -> None:
        self.assertEqual(self.doc["version"], "2.1.0")
        self.assertTrue(self.doc["$schema"].endswith("sarif-schema-2.1.0.json"))
        self.assertEqual(len(self.doc["runs"]), 1)

    def test_driver_identifies_the_tool(self) -> None:
        driver = self.doc["runs"][0]["tool"]["driver"]
        self.assertEqual(driver["name"], "harness-scorecard")
        self.assertEqual(driver["version"], self.card.rubric_version)

    def test_run_properties_carry_grade_and_score(self) -> None:
        props = self.doc["runs"][0]["properties"]
        self.assertEqual(props["grade"], "A")
        self.assertEqual(props["overall_score"], 1.0)

    def test_render_sarif_is_valid_json(self) -> None:
        parsed = json.loads(render_sarif(self.card))
        self.assertEqual(parsed["version"], "2.1.0")


class TestRuleCatalog(unittest.TestCase):
    def setUp(self) -> None:
        self.card = score_harness(load_harness(FIXTURES / "strong_harness"))
        self.doc = to_sarif(self.card)

    def test_one_rule_per_check_with_unique_ids(self) -> None:
        rules = self.doc["runs"][0]["tool"]["driver"]["rules"]
        rule_ids = [rule["id"] for rule in rules]
        self.assertEqual(sorted(rule_ids), sorted(_all_check_ids(self.card)))
        self.assertEqual(len(rule_ids), len(set(rule_ids)))

    def test_every_result_ruleid_resolves_to_a_rule(self) -> None:
        run = self.doc["runs"][0]
        rule_ids = {rule["id"] for rule in run["tool"]["driver"]["rules"]}
        for result in run["results"]:
            self.assertIn(result["ruleId"], rule_ids)

    def test_gate_rule_advertises_its_cap(self) -> None:
        rules = {r["id"]: r for r in self.doc["runs"][0]["tool"]["driver"]["rules"]}
        self.assertEqual(rules["HS-D1-01"]["properties"]["gate_cap"], "D")


class TestResultsAreFindings(unittest.TestCase):
    def test_strong_harness_emits_no_findings(self) -> None:
        card = score_harness(load_harness(FIXTURES / "strong_harness"))
        self.assertEqual(to_sarif(card)["runs"][0]["results"], [])

    def test_weak_harness_findings_are_all_nonpass(self) -> None:
        card = score_harness(load_harness(FIXTURES / "weak_harness"))
        by_id = {c.id: c for dim in card.dimensions for c in dim.checks}
        results = to_sarif(card)["runs"][0]["results"]
        self.assertGreater(len(results), 0)
        for result in results:
            self.assertIn(by_id[result["ruleId"]].status, (Status.FAIL, Status.PARTIAL))
            self.assertIn(result["level"], ("error", "warning", "note"))

    def test_tripped_gate_is_an_error_with_cap_property(self) -> None:
        card = score_harness(load_harness(FIXTURES / "weak_harness"))
        results = to_sarif(card)["runs"][0]["results"]
        gate_results = [r for r in results if r["properties"].get("caps_grade_at")]
        self.assertTrue(gate_results)
        for result in gate_results:
            self.assertEqual(result["level"], "error")
            self.assertTrue(result["properties"]["is_gate"])


class TestLevelMapping(unittest.TestCase):
    def test_failed_high_is_error(self) -> None:
        doc = to_sarif(_synthetic_card("boom", status=Status.FAIL, severity=Severity.HIGH))
        self.assertEqual(doc["runs"][0]["results"][0]["level"], "error")

    def test_partial_high_downgrades_to_warning(self) -> None:
        doc = to_sarif(_synthetic_card("half", status=Status.PARTIAL, severity=Severity.HIGH))
        self.assertEqual(doc["runs"][0]["results"][0]["level"], "warning")

    def test_failed_low_is_note(self) -> None:
        doc = to_sarif(_synthetic_card("minor", status=Status.FAIL, severity=Severity.LOW))
        self.assertEqual(doc["runs"][0]["results"][0]["level"], "note")


class TestRedaction(unittest.TestCase):
    def test_secrets_and_home_path_are_scrubbed(self) -> None:
        home = os.path.expanduser("~")  # noqa: PTH111 - asserting the literal home is gone
        message = (
            f"found token ABCDEFGHIJKLMNOP1234567890 for foo@example.com "
            f"under {home}/.claude/settings.json"
        )
        card = _synthetic_card(message, evidence=["leaked sk-ABCDEFGH12345678"])
        text = render_sarif(card)
        self.assertNotIn("ABCDEFGHIJKLMNOP1234567890", text)
        self.assertNotIn("foo@example.com", text)
        self.assertNotIn("sk-ABCDEFGH12345678", text)
        self.assertNotIn(home + "/.claude", text)
        self.assertIn("[redacted-token]", text)
        self.assertIn("[redacted-email]", text)
        self.assertIn("[redacted-secret]", text)

    def test_title_derived_rule_name_does_not_leak_home_path(self) -> None:
        # A check title containing a home path must not surface the username via rules[].name.
        home = os.path.expanduser("~")  # noqa: PTH111 - asserting the literal home is gone
        card = _synthetic_card("boom", title=f"Guard the file at {home}/.ssh/id_rsa")
        doc = to_sarif(card)
        rule = doc["runs"][0]["tool"]["driver"]["rules"][0]
        self.assertNotIn(home, rule["name"])
        self.assertNotIn(home, json.dumps(doc))


class TestStableFingerprints(unittest.TestCase):
    def test_same_card_yields_same_fingerprints(self) -> None:
        card = score_harness(load_harness(FIXTURES / "weak_harness"))
        first = to_sarif(card)["runs"][0]["results"]
        second = to_sarif(card)["runs"][0]["results"]
        self.assertEqual(
            [r["partialFingerprints"] for r in first],
            [r["partialFingerprints"] for r in second],
        )

    def test_distinct_checks_have_distinct_fingerprints(self) -> None:
        card = score_harness(load_harness(FIXTURES / "weak_harness"))
        results = to_sarif(card)["runs"][0]["results"]
        prints = [next(iter(r["partialFingerprints"].values())) for r in results]
        self.assertEqual(len(prints), len(set(prints)))


class TestCliSarifFlag(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.out_path = Path(self._tmp.name) / "scorecard_test.sarif"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_sarif_flag_writes_valid_document(self) -> None:
        with contextlib.redirect_stdout(io.StringIO()):
            code = main(["scan", str(FIXTURES / "weak_harness"), "--sarif", str(self.out_path)])
        self.assertEqual(code, 1)
        self.assertTrue(self.out_path.exists())
        doc = json.loads(self.out_path.read_text(encoding="utf-8"))
        self.assertEqual(doc["version"], "2.1.0")
        self.assertGreater(len(doc["runs"][0]["results"]), 0)


if __name__ == "__main__":
    unittest.main()

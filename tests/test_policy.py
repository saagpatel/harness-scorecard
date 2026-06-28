"""Tests for the operator policy file: parsing, waiver exclusion, and dispatcher credit."""

import json
import tempfile
import unittest
from dataclasses import dataclass, field
from pathlib import Path

from harness_scorecard.cli import main
from harness_scorecard.htmlreport import render_html
from harness_scorecard.models import CheckResult, Grade, Status
from harness_scorecard.policy import Policy, Waiver, find_policy, load_policy
from harness_scorecard.report import from_dict, render_console, render_json, to_dict
from harness_scorecard.sarif import to_sarif
from harness_scorecard.scoring import _apply_policy, _weighted_score, score_harness


def _check(
    cid: str, dim: str, status: Status, *, is_gate: bool = False, gate_cap=None
) -> CheckResult:
    return CheckResult(
        id=cid,
        dimension=dim,
        title=f"{cid} title",
        status=status,
        weight=1,
        message="msg",
        is_gate=is_gate,
        gate_cap=gate_cap,
    )


@dataclass
class _FakeConfig:
    root: Path = field(default_factory=lambda: Path("examples/harness"))
    harness_type: str = "claude-code"
    caveats: list[str] = field(default_factory=list)


class _FakeCheck:
    """A check that returns a fresh CheckResult each run (score_harness mutates results)."""

    def __init__(self, cid: str, dim: str, status: Status, *, is_gate=False, gate_cap=None) -> None:
        self._args = (cid, dim, status)
        self._kw = {"is_gate": is_gate, "gate_cap": gate_cap}
        self.dimension = dim

    def run(self, _config: object) -> CheckResult:
        return _check(*self._args, **self._kw)


class TestPolicyParsing(unittest.TestCase):
    def _write(self, body: str) -> Path:
        tmp = Path(tempfile.mkdtemp())
        path = tmp / ".harness-scorecard.toml"
        path.write_text(body, encoding="utf-8")
        return path

    def test_parses_waivers_and_credits(self) -> None:
        path = self._write(
            '[[waiver]]\ncheck = "HS-D1-03"\nreason = "handled by pre-commit"\n'
            '[dispatcher]\ncredits = ["HS-D1-02", "HS-D4-03"]\n'
        )
        policy = load_policy(path)
        self.assertEqual(policy.waiver_map, {"HS-D1-03": "handled by pre-commit"})
        self.assertEqual(policy.dispatcher_credits, ("HS-D1-02", "HS-D4-03"))

    def test_empty_file_is_empty_policy(self) -> None:
        policy = load_policy(self._write(""))
        self.assertTrue(policy.is_empty)

    def test_malformed_toml_raises_valueerror(self) -> None:
        with self.assertRaises(ValueError):
            load_policy(self._write("[[waiver]\ncheck = "))

    def test_waiver_without_check_id_raises(self) -> None:
        with self.assertRaises(ValueError):
            load_policy(self._write('[[waiver]]\nreason = "no check id"\n'))

    def test_find_policy_discovers_in_root(self) -> None:
        path = self._write("")
        self.assertEqual(find_policy(path.parent), path)
        self.assertIsNone(find_policy(path.parent / "nope"))


class TestWaiverApplication(unittest.TestCase):
    def test_waived_check_excluded_from_weighted_score(self) -> None:
        checks = [_check("A", "D1", Status.PASS), _check("B", "D1", Status.FAIL)]
        self.assertAlmostEqual(_weighted_score(checks), 0.5)
        checks[1].waived = True
        self.assertAlmostEqual(_weighted_score(checks), 1.0)  # the FAIL no longer counts

    def test_waived_gate_does_not_cap(self) -> None:
        gate = _check("G", "D1", Status.FAIL, is_gate=True, gate_cap=Grade.D)
        self.assertEqual(gate.triggered_gate_cap, Grade.D)
        gate.waived = True
        self.assertIsNone(gate.triggered_gate_cap)

    def test_apply_policy_marks_and_notes(self) -> None:
        results = [
            _check("HS-D1-01", "D1", Status.FAIL),
            _check("HS-D1-02", "D1", Status.PASS),
        ]
        policy = Policy(
            waivers=(
                Waiver("HS-D1-01", "accepted"),
                Waiver("HS-D1-02", "redundant"),
                Waiver("HS-D9-99", "ghost"),
            )
        )
        notes = _apply_policy(results, policy)
        self.assertTrue(results[0].waived)
        self.assertEqual(results[0].waiver_reason, "accepted")
        self.assertFalse(results[1].waived)  # waiving a PASS is a no-op
        self.assertTrue(any("unnecessary" in n for n in notes))
        self.assertTrue(any("unknown check HS-D9-99" in n for n in notes))


class TestDispatcherCredit(unittest.TestCase):
    def test_credit_upgrades_fail_to_partial(self) -> None:
        results = [_check("HS-D4-03", "D4", Status.FAIL)]
        _apply_policy(results, Policy(dispatcher_credits=("HS-D4-03",)))
        self.assertEqual(results[0].status, Status.PARTIAL)
        self.assertTrue(results[0].dispatcher_credited)

    def test_credit_on_passing_check_is_noted_not_applied(self) -> None:
        results = [_check("HS-D4-01", "D4", Status.PASS)]
        notes = _apply_policy(results, Policy(dispatcher_credits=("HS-D4-01",)))
        self.assertEqual(results[0].status, Status.PASS)
        self.assertFalse(results[0].dispatcher_credited)
        self.assertTrue(any("did not fail" in n for n in notes))

    def test_credited_gate_no_longer_caps(self) -> None:
        config = _FakeConfig()
        checks = [_FakeCheck("HS-D1-01", "D1", Status.FAIL, is_gate=True, gate_cap=Grade.D)]
        capped = score_harness(config, checks)
        self.assertEqual([g.id for g in capped.gate_caps], ["HS-D1-01"])  # gate trips
        credited = score_harness(config, checks, Policy(dispatcher_credits=("HS-D1-01",)))
        self.assertEqual(credited.gate_caps, [])  # PARTIAL now, gate cleared


class TestScoreHarnessWithPolicy(unittest.TestCase):
    def test_waiver_lifts_grade_and_records_note(self) -> None:
        config = _FakeConfig()
        checks = [
            _FakeCheck("HS-D1-01", "D1", Status.PASS),
            _FakeCheck("HS-D1-02", "D1", Status.FAIL),
        ]
        without = score_harness(config, checks)
        withw = score_harness(config, checks, Policy(waivers=(Waiver("HS-D1-02", "ok"),)))
        self.assertGreater(withw.overall_score, without.overall_score)
        waived = [c for d in withw.dimensions for c in d.checks if c.waived]
        self.assertEqual(len(waived), 1)

    def test_console_and_json_surface_policy(self) -> None:
        config = _FakeConfig()
        checks = [_FakeCheck("HS-D1-01", "D1", Status.FAIL)]
        card = score_harness(config, checks, Policy(waivers=(Waiver("HS-D1-01", "accepted gap"),)))
        console = render_console(card)
        self.assertIn("[WAIV]", console)
        self.assertIn("accepted gap", console)
        self.assertIn("Policy applied", console)
        payload = json.loads(render_json(card))
        check = payload["dimensions"][0]["checks"][0]
        self.assertTrue(check["waived"])
        self.assertEqual(check["waiver_reason"], "accepted gap")

    def test_all_waived_does_not_crash(self) -> None:
        config = _FakeConfig()
        checks = [
            _FakeCheck("HS-D1-01", "D1", Status.FAIL),
            _FakeCheck("HS-D1-02", "D1", Status.FAIL),
        ]
        card = score_harness(
            config,
            checks,
            Policy(waivers=(Waiver("HS-D1-01", "a"), Waiver("HS-D1-02", "b"))),
        )
        self.assertEqual(card.overall_score, 0.0)  # no counting checks -> 0.0, no ZeroDivision
        self.assertEqual(card.grade, Grade.F)
        self.assertEqual(card.gate_caps, [])

    def test_html_and_sarif_surface_waiver(self) -> None:
        config = _FakeConfig()
        checks = [_FakeCheck("HS-D1-01", "D1", Status.FAIL, is_gate=True, gate_cap=Grade.D)]
        card = score_harness(config, checks, Policy(waivers=(Waiver("HS-D1-01", "accepted gap"),)))
        html = render_html(card)
        self.assertIn("WAIVED", html)
        self.assertIn("accepted gap", html)
        sarif = to_sarif(card)
        waived_result = next(r for r in sarif["runs"][0]["results"] if r["ruleId"] == "HS-D1-01")
        self.assertIn("suppressions", waived_result)
        self.assertEqual(waived_result["suppressions"][0]["justification"], "accepted gap")

    def test_roundtrip_preserves_policy_fields(self) -> None:
        config = _FakeConfig()
        checks = [
            _FakeCheck("HS-D1-01", "D1", Status.FAIL),
            _FakeCheck("HS-D1-02", "D1", Status.FAIL),
        ]
        card = score_harness(
            config,
            checks,
            Policy(waivers=(Waiver("HS-D1-01", "x"),), dispatcher_credits=("HS-D1-02",)),
        )
        restored = from_dict(to_dict(card))
        flat = {c.id: c for d in restored.dimensions for c in d.checks}
        self.assertTrue(flat["HS-D1-01"].waived)
        self.assertTrue(flat["HS-D1-02"].dispatcher_credited)


class TestPolicyCli(unittest.TestCase):
    def _harness(self, root: Path) -> None:
        (root / "settings.json").write_text(
            json.dumps({"permissions": {"defaultMode": "default"}, "hooks": {}}), encoding="utf-8"
        )

    def test_auto_discovered_waiver_suppresses_gate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._harness(root)
            # HS-D5-01 (harness config protection) fails on a bare harness and caps the grade.
            (root / ".harness-scorecard.toml").write_text(
                '[[waiver]]\ncheck = "HS-D5-01"\nreason = "config guarded out-of-band"\n',
                encoding="utf-8",
            )
            json_out = root / "out.json"
            self.assertIn(main(["scan", tmp, "--json", str(json_out), "--min-grade", "F"]), (0, 1))
            payload = json.loads(json_out.read_text(encoding="utf-8"))
            capped_ids = [g["id"] for g in payload["gate_caps"]]
            self.assertNotIn("HS-D5-01", capped_ids)
            waived = [c["id"] for d in payload["dimensions"] for c in d["checks"] if c["waived"]]
            self.assertIn("HS-D5-01", waived)

    def test_malformed_policy_file_exits_two(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._harness(root)
            (root / ".harness-scorecard.toml").write_text("[[waiver]\nbroken", encoding="utf-8")
            self.assertEqual(main(["scan", tmp]), 2)


if __name__ == "__main__":
    unittest.main()

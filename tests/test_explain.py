"""The ``explain`` command: check resolution, rendering, and registry completeness.

The meta-tests here are load-bearing: they assert every registered check carries a failure-mode
narrative and that the corpus-proof map stays in lock-step with the actual gates and the on-disk
corpus -- so the explanatory layer cannot silently fall out of sync with the rubric.
"""

from __future__ import annotations

import contextlib
import io
import json
import unittest
from itertools import chain
from pathlib import Path

from harness_scorecard.checks import ALL_CHECKS
from harness_scorecard.checks_codex import CODEX_CHECKS
from harness_scorecard.cli import main
from harness_scorecard.explain import (
    CORPUS_ENTRIES,
    find_check,
    render_explain_console,
    render_explain_json,
    to_explain_dict,
)
from harness_scorecard.failure_modes import FAILURE_MODES

REPO_ROOT = Path(__file__).parent.parent
_ALL = tuple(chain(ALL_CHECKS, CODEX_CHECKS))
_MIN_NARRATIVE_LEN = 40  # a real sentence, not a stub


class TestRegistryCompleteness(unittest.TestCase):
    def test_every_check_has_a_failure_mode(self) -> None:
        self.assertGreater(len(_ALL), 0, "check catalog is empty")
        missing = [check.id for check in _ALL if not FAILURE_MODES.get(check.id, "").strip()]
        self.assertEqual(missing, [], f"checks with no failure-mode narrative: {missing}")

    def test_no_orphan_failure_modes(self) -> None:
        # A narrative for an id that no longer exists is dead weight that drifts out of sync.
        ids = {check.id for check in _ALL}
        orphans = sorted(set(FAILURE_MODES) - ids)
        self.assertEqual(orphans, [], f"failure modes for unknown check ids: {orphans}")

    def test_failure_modes_are_substantive(self) -> None:
        thin = [cid for cid, text in FAILURE_MODES.items() if len(text) < _MIN_NARRATIVE_LEN]
        self.assertEqual(thin, [], f"failure modes too thin to be useful: {thin}")


class TestCorpusProofMap(unittest.TestCase):
    def test_proof_map_matches_the_gates_exactly(self) -> None:
        # Every gate has a proof entry, and every proof entry points at a gate -- no more, no less.
        gate_ids = {check.id for check in _ALL if check.is_gate}
        self.assertEqual(set(CORPUS_ENTRIES), gate_ids)

    def test_proof_paths_exist_on_disk(self) -> None:
        self.assertGreater(len(CORPUS_ENTRIES), 0, "corpus map is empty — no paths to verify")
        for check_id, rel in CORPUS_ENTRIES.items():
            with self.subTest(check_id=check_id):
                entry = REPO_ROOT / rel
                self.assertTrue((entry / "ATTACK.md").is_file(), f"{rel}/ATTACK.md missing")
                self.assertTrue((entry / "vulnerable").is_dir())
                self.assertTrue((entry / "guarded").is_dir())


class TestFindCheck(unittest.TestCase):
    def test_resolves_known_id_case_insensitively(self) -> None:
        for raw in ("HS-D4-01", "hs-d4-01", "  cdx-d1-01  "):
            with self.subTest(raw=raw):
                check = find_check(raw)
                self.assertIsNotNone(check)
                assert check is not None  # narrow for the type checker
                self.assertEqual(check.id, raw.strip().upper())

    def test_unknown_id_returns_none(self) -> None:
        self.assertIsNone(find_check("HS-D9-99"))
        self.assertIsNone(find_check("D4"))


class TestRendering(unittest.TestCase):
    def test_gated_check_dict_carries_gate_and_proof(self) -> None:
        check = find_check("HS-D4-01")
        assert check is not None
        data = to_explain_dict(check)
        self.assertTrue(data["is_gate"])
        self.assertEqual(data["gate_cap"], "C")
        self.assertEqual(data["redteam_proof"], "examples/redteam/claude-d4-inert-harddeny")
        self.assertEqual(data["dimension"]["name"], "Destructive-action & git safety")
        self.assertEqual(data["failure_mode"], FAILURE_MODES["HS-D4-01"])

    def test_non_gated_check_has_no_proof(self) -> None:
        check = find_check("HS-D10-01")
        assert check is not None
        data = to_explain_dict(check)
        self.assertFalse(data["is_gate"])
        self.assertIsNone(data["gate_cap"])
        self.assertIsNone(data["redteam_proof"])

    def test_console_shows_gate_and_proof_for_a_gate(self) -> None:
        check = find_check("CDX-D1-01")
        assert check is not None
        text = render_explain_console(check)
        self.assertIn("GATE: a failing result caps the grade at D.", text)
        self.assertIn("Why it matters", text)
        self.assertIn("examples/redteam/codex-d1-env-secret-leak", text)

    def test_console_omits_proof_for_a_non_gate(self) -> None:
        check = find_check("HS-D7-02")
        assert check is not None
        text = render_explain_console(check)
        self.assertNotIn("Proof it's caught", text)
        self.assertNotIn("GATE:", text)
        self.assertIn("Why it matters", text)

    def test_json_is_valid_and_complete(self) -> None:
        check = find_check("CDX-D4-01")
        assert check is not None
        data = json.loads(render_explain_json(check))
        expected_keys = {
            "id",
            "title",
            "dimension",
            "weight",
            "severity",
            "detectability",
            "is_gate",
            "gate_cap",
            "failure_mode",
            "remediation",
            "redteam_proof",
        }
        self.assertEqual(set(data), expected_keys)


class TestCliIntegration(unittest.TestCase):
    def _exit(self, argv: list[str]) -> int:
        """Run the CLI with stdout+stderr captured, so the suite output stays clean."""
        with (
            contextlib.redirect_stdout(io.StringIO()),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            return main(argv)

    def test_explain_known_check_exits_zero(self) -> None:
        self.assertEqual(self._exit(["explain", "HS-D4-01"]), 0)
        self.assertEqual(self._exit(["explain", "cdx-d5-01", "--format", "json"]), 0)

    def test_explain_unknown_check_exits_two(self) -> None:
        self.assertEqual(self._exit(["explain", "HS-NOPE"]), 2)


if __name__ == "__main__":
    unittest.main()

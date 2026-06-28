"""Red-team validation corpus: prove each gated check catches the attack it claims.

Each entry under ``examples/redteam/<mode>/`` is a vulnerable/guarded pair of static config
fixtures that differ by exactly one guard. This module is the mechanical proof behind the
rubric's central claim -- "every gated check traces to a documented red-team failure mode":
the scorer must FAIL the gated check on ``vulnerable/`` and PASS it on ``guarded/``, the gate
must appear in ``gate_caps``, and it must actually cap the grade. Nothing here executes an
exploit; the corpus demonstrates *detection*, not exploitation.
"""

from __future__ import annotations

import re
import unittest
from dataclasses import dataclass
from pathlib import Path

from harness_scorecard.dispatch import select_adapter
from harness_scorecard.models import (
    CheckResult,
    Grade,
    Scorecard,
    Status,
    grade_from_score,
    grade_rank,
)
from harness_scorecard.scoring import score_harness

CORPUS = Path(__file__).parent.parent / "examples" / "redteam"
if not CORPUS.is_dir():  # fail fast with the resolved path, not a confusing per-case "missing"
    msg = f"red-team corpus not found at {CORPUS}"
    raise FileNotFoundError(msg)


@dataclass(frozen=True)
class RedTeamCase:
    """One gated failure mode, proven by a vulnerable/guarded pair."""

    mode: str  # directory under examples/redteam/
    check_id: str  # the gated check the pair exercises
    gate_cap: Grade  # the cap the gate imposes when it trips
    # True when the gate is the *sole* reason the grade is low: the vulnerable harness scores in
    # a higher raw band and is dragged to the cap only by this gate -- the strongest form of the
    # proof. False for codex-d4, where the effective-bypass knobs (sandbox + approval) are
    # load-bearing across D1/D4/D5 at once, so that harness is low on raw signal too (its
    # ATTACK.md explains the cascade). The gate still fires and still caps in both cases.
    gate_is_sole_cause: bool = True


CASES: tuple[RedTeamCase, ...] = (
    RedTeamCase("claude-d1-credential-exposure", "HS-D1-01", Grade.D),
    RedTeamCase("claude-d4-inert-harddeny", "HS-D4-01", Grade.C),
    RedTeamCase("claude-d5-unprotected-config", "HS-D5-01", Grade.C),
    RedTeamCase("codex-d1-env-secret-leak", "CDX-D1-01", Grade.D),
    RedTeamCase("codex-d4-full-access", "CDX-D4-01", Grade.C, gate_is_sole_cause=False),
    RedTeamCase("codex-d5-self-mutable", "CDX-D5-01", Grade.C),
)


def _score(harness_dir: Path) -> Scorecard:
    config, checks = select_adapter(harness_dir, "auto")
    return score_harness(config, checks)


def _check(card: Scorecard, check_id: str) -> CheckResult:
    for dimension in card.dimensions:
        for result in dimension.checks:
            if result.id == check_id:
                return result
    msg = f"check {check_id} not present in scorecard for {card.harness_path}"
    raise AssertionError(msg)


def _gate_ids(card: Scorecard) -> set[str]:
    return {result.id for result in card.gate_caps}


def _snapshot(harness_dir: Path) -> dict[str, str]:
    """Every file under a harness dir, keyed by relative path -- for an equality comparison."""
    return {
        str(path.relative_to(harness_dir)): path.read_text(encoding="utf-8")
        for path in sorted(harness_dir.rglob("*"))
        if path.is_file()
    }


class TestCorpusLayout(unittest.TestCase):
    def test_every_case_has_a_pair_and_an_attack_doc(self) -> None:
        for case in CASES:
            with self.subTest(mode=case.mode):
                root = CORPUS / case.mode
                self.assertTrue((root / "ATTACK.md").is_file(), "ATTACK.md missing")
                self.assertTrue((root / "vulnerable").is_dir(), "vulnerable/ missing")
                self.assertTrue((root / "guarded").is_dir(), "guarded/ missing")

    def test_attack_doc_names_its_check_and_cap(self) -> None:
        # The narrative and the test table must agree, so a doc can't silently drift from the
        # gate it claims to prove. Require the check id and its cap to appear *tied together*
        # on one line (the "Gated by:" line) -- a bolded letter loose somewhere in the file
        # would otherwise satisfy a bare substring match.
        for case in CASES:
            with self.subTest(mode=case.mode):
                text = (CORPUS / case.mode / "ATTACK.md").read_text(encoding="utf-8")
                pattern = rf"{re.escape(case.check_id)}.*?\*\*{re.escape(case.gate_cap.value)}\*\*"
                self.assertRegex(text, pattern)

    def test_pair_actually_differs(self) -> None:
        # A byte-identical vulnerable/guarded pair would prove nothing.
        for case in CASES:
            with self.subTest(mode=case.mode):
                root = CORPUS / case.mode
                self.assertNotEqual(_snapshot(root / "vulnerable"), _snapshot(root / "guarded"))


class TestVulnerableTripsGate(unittest.TestCase):
    def test_gated_check_fails_and_caps_the_grade(self) -> None:
        for case in CASES:
            with self.subTest(mode=case.mode):
                card = _score(CORPUS / case.mode / "vulnerable")
                result = _check(card, case.check_id)
                self.assertEqual(result.status, Status.FAIL)
                self.assertIn(case.check_id, _gate_ids(card))
                # the tripped gate carries the cap the table declares...
                self.assertEqual(result.triggered_gate_cap, case.gate_cap)
                # ...and the final grade is at or below that cap.
                self.assertLessEqual(grade_rank(card.grade), grade_rank(case.gate_cap))
                # for the independent gates the harness is otherwise A-grade, so it lands
                # *exactly* at the cap -- not merely at-or-below (which a second tripped gate
                # capping lower would also satisfy). codex-d4 cascades below the cap by design.
                if case.gate_is_sole_cause:
                    self.assertEqual(card.grade, case.gate_cap)

    def test_gate_alone_caps_an_otherwise_strong_harness(self) -> None:
        # For the independent gates, the vulnerable harness scores in a higher raw band and is
        # pulled down to the cap purely by this gate -- the gate, not general weakness, is what bit.
        ran = 0
        for case in CASES:
            if not case.gate_is_sole_cause:
                continue
            ran += 1
            with self.subTest(mode=case.mode):
                card = _score(CORPUS / case.mode / "vulnerable")
                raw_band = grade_from_score(card.overall_score)
                self.assertGreater(grade_rank(raw_band), grade_rank(card.grade))
        # guard against a future CASES table that is all-cascade: this proof must exercise
        # at least one sole-cause gate or it has silently stopped proving anything.
        self.assertGreater(ran, 0, "no sole-cause cases were exercised")


class TestGuardedClearsGate(unittest.TestCase):
    def test_gated_check_passes_and_gate_is_gone(self) -> None:
        for case in CASES:
            with self.subTest(mode=case.mode):
                card = _score(CORPUS / case.mode / "guarded")
                result = _check(card, case.check_id)
                self.assertEqual(result.status, Status.PASS)
                self.assertNotIn(case.check_id, _gate_ids(card))

    def test_adding_the_guard_strictly_improves_the_grade(self) -> None:
        for case in CASES:
            with self.subTest(mode=case.mode):
                vulnerable = _score(CORPUS / case.mode / "vulnerable")
                guarded = _score(CORPUS / case.mode / "guarded")
                self.assertGreater(grade_rank(guarded.grade), grade_rank(vulnerable.grade))


if __name__ == "__main__":
    unittest.main()

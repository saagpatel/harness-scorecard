"""CLI smoke tests: scan exits with the right code and emits the grade."""

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from harness_scorecard.cli import main
from harness_scorecard.models import RUBRIC_VERSION
from tests.test_claims import GIT_GUARD

FIXTURES = Path(__file__).parent / "fixtures"


class TestVersion(unittest.TestCase):
    def test_version_reports_both_package_and_rubric(self):
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer), self.assertRaises(SystemExit) as ctx:
            main(["--version"])
        self.assertEqual(ctx.exception.code, 0)
        out = buffer.getvalue()
        self.assertIn("rubric", out)
        self.assertIn(RUBRIC_VERSION, out)


def run_cli(argv: list[str]) -> tuple[int, str]:
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        code = main(argv)
    return code, buffer.getvalue()


class TestScanCommand(unittest.TestCase):
    def test_strong_harness_exits_zero_and_grades_a(self):
        code, out = run_cli(["scan", str(FIXTURES / "strong_harness")])
        self.assertEqual(code, 0)
        self.assertIn("GRADE:  A", out)

    def test_weak_harness_exits_one_and_grades_f(self):
        code, out = run_cli(["scan", str(FIXTURES / "weak_harness")])
        self.assertEqual(code, 1)
        self.assertIn("GRADE:  F", out)
        self.assertIn("Capability gates tripped", out)

    def test_missing_harness_exits_two(self):
        code, _ = run_cli(["scan", str(FIXTURES / "nope")])
        self.assertEqual(code, 2)

    def test_codex_harness_is_auto_detected(self):
        code, out = run_cli(["scan", str(FIXTURES / "codex_weak")])
        self.assertEqual(code, 1)
        self.assertIn("(codex)", out)
        self.assertIn("Capability gates tripped", out)

    def test_codex_strong_grades_a(self):
        code, out = run_cli(["scan", str(FIXTURES / "codex_strong"), "--type", "codex"])
        self.assertEqual(code, 0)
        self.assertIn("GRADE:  A", out)
        self.assertIn("Scored 10 of 10", out)

    def test_json_format_is_valid_json(self):
        _, out = run_cli(["scan", str(FIXTURES / "strong_harness"), "--format", "json"])
        payload = json.loads(out)
        self.assertEqual(payload["grade"], "A")
        self.assertEqual(payload["dimensions_total"], 10)
        self.assertEqual(payload["dimensions_scored"], 10)


class TestScanExplain(unittest.TestCase):
    def test_explain_annotates_failing_findings_with_the_failure_mode(self):
        code, out = run_cli(
            ["scan", str(FIXTURES / "weak_harness"), "--explain", "--min-grade", "F"]
        )
        self.assertEqual(code, 0)
        self.assertIn("why:", out)
        # the annotation is the documented failure mode for the failing bypass-aware gate
        self.assertIn("hard_deny is inert", out)

    def test_without_explain_there_are_no_why_lines(self):
        _, out = run_cli(["scan", str(FIXTURES / "weak_harness"), "--min-grade", "F"])
        self.assertNotIn("why:", out)

    def test_explain_annotates_nothing_on_an_all_passing_harness(self):
        # strong_harness is all PASS, so there is no actionable finding to annotate.
        _, out = run_cli(["scan", str(FIXTURES / "strong_harness"), "--explain"])
        self.assertNotIn("why:", out)

    def test_explain_is_console_only_and_leaves_json_untouched(self):
        _, out = run_cli(
            [
                "scan",
                str(FIXTURES / "weak_harness"),
                "--explain",
                "--format",
                "json",
                "--min-grade",
                "F",
            ]
        )
        payload = json.loads(out)
        self.assertEqual(payload["grade"], "F")
        self.assertNotIn("why:", out)


class TestMinGradeGate(unittest.TestCase):
    def test_min_grade_f_passes_a_failing_harness(self):
        # Loosening the bar to F means even the weak harness clears the gate.
        code, _ = run_cli(["scan", str(FIXTURES / "weak_harness"), "--min-grade", "F"])
        self.assertEqual(code, 0)

    def test_min_grade_a_still_passes_the_strong_harness(self):
        code, _ = run_cli(["scan", str(FIXTURES / "strong_harness"), "--min-grade", "A"])
        self.assertEqual(code, 0)

    def test_default_bar_is_b_so_weak_harness_fails(self):
        code, _ = run_cli(["scan", str(FIXTURES / "weak_harness")])
        self.assertEqual(code, 1)

    def test_invalid_min_grade_is_rejected(self):
        with self.assertRaises(SystemExit) as ctx:
            run_cli(["scan", str(FIXTURES / "strong_harness"), "--min-grade", "Z"])
        self.assertEqual(ctx.exception.code, 2)


HARD_GUARANTEE_RULE = "# Rules\n\n## Hard-Deny\n\n- Push to `main` or `master`\n"
SOFT_ENFORCEMENT_RULE = "\n## Git\n\n- Never `git commit --amend` after a hook failure\n"


def write_claims_harness(root: Path, *, include_guard: bool = True, extra_rule: str = "") -> None:
    """A synthetic claims-audit harness: one hard guarantee, optionally its guard."""
    (root / "rules").mkdir()
    (root / "rules" / "git.md").write_text(HARD_GUARANTEE_RULE + extra_rule, encoding="utf-8")
    hooks: dict = {}
    if include_guard:
        (root / "hooks").mkdir()
        (root / "hooks" / "git-safety.sh").write_text(GIT_GUARD, encoding="utf-8")
        hooks = {
            "PreToolUse": [{"matcher": "Bash", "hooks": [{"command": "bash hooks/git-safety.sh"}]}]
        }
    settings = {"permissions": {"defaultMode": "default", "deny": []}, "hooks": hooks}
    (root / "settings.json").write_text(json.dumps(settings), encoding="utf-8")


def write_codex_claims_harness(root: Path) -> None:
    (root / "AGENTS.md").write_text(
        "# AGENTS\n\n## Hard-Deny\n\n- Push to `main` or `master`\n",
        encoding="utf-8",
    )
    (root / "config.toml").write_text(
        'approval_policy = "on-request"\nsandbox_mode = "workspace-write"\nweb_search = "off"\n',
        encoding="utf-8",
    )
    # The push guarantee needs a real hook: sandbox/approval config does not enforce
    # git semantics, so a hook-less Codex harness would honestly gate exit 1.
    (root / "hooks").mkdir()
    (root / "hooks" / "git-safety.sh").write_text(GIT_GUARD, encoding="utf-8")
    hooks = {
        "PreToolUse": [
            {
                "matcher": "Bash",
                "hooks": [{"type": "command", "command": "bash hooks/git-safety.sh"}],
            }
        ]
    }
    (root / "hooks.json").write_text(json.dumps({"hooks": hooks}), encoding="utf-8")


class TestClaimsCommand(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def test_backed_guarantee_exits_zero(self):
        write_claims_harness(self.root)
        code, out = run_cli(["claims", str(self.root)])
        self.assertEqual(code, 0)
        self.assertIn("ENFORCED (hook)", out)

    def test_prose_only_hard_guarantee_gates_exit_one(self):
        write_claims_harness(self.root, include_guard=False)
        code, out = run_cli(["claims", str(self.root)])
        self.assertEqual(code, 1)
        self.assertIn("PROSE-ONLY", out)
        self.assertIn("[HARD-DENY]", out)

    def test_strict_widens_gate_to_all_enforcement_claims(self):
        write_claims_harness(self.root, extra_rule=SOFT_ENFORCEMENT_RULE)
        code, _ = run_cli(["claims", str(self.root)])
        self.assertEqual(code, 0)  # the hard guarantee is backed; soft claim doesn't gate
        code, out = run_cli(["claims", str(self.root), "--strict"])
        self.assertEqual(code, 1)
        self.assertIn("PROSE-ONLY", out)

    def test_json_format_emits_ledger_and_coverage(self):
        write_claims_harness(self.root)
        code, out = run_cli(["claims", str(self.root), "--format", "json"])
        self.assertEqual(code, 0)
        payload = json.loads(out)
        self.assertEqual(payload["coverage"]["deny_blocks_found"], 1)
        self.assertIn("enforced_hook", {f["status"] for f in payload["findings"]})

    def test_codex_harness_is_auto_detected(self):
        write_codex_claims_harness(self.root)
        code, out = run_cli(["claims", str(self.root)])
        self.assertEqual(code, 0)
        self.assertIn("AGENTS.md", out)
        self.assertIn("ENFORCED (hook)", out)

    def test_missing_harness_exits_two(self):
        code, _ = run_cli(["claims", str(self.root / "nope")])
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()

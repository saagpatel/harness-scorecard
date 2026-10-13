"""Regression coverage for the end-of-repo review fixes."""

import json
import tempfile
import unittest
from pathlib import Path

from harness_scorecard.checks import ALL_CHECKS
from harness_scorecard.checks.base import effective_block
from harness_scorecard.checks_codex import CODEX_CHECKS
from harness_scorecard.claims import ClaimStatus, audit_claims
from harness_scorecard.cli import main
from harness_scorecard.discovery import load_harness
from harness_scorecard.discovery_codex import load_codex_harness
from harness_scorecard.models import Status
from harness_scorecard.parsing import HookEntry
from harness_scorecard.report import from_dict
from tests.test_checks_codex import make_codex_config


class TestReviewRegressions(unittest.TestCase):
    def test_deny_rules_keep_tool_and_argument_separate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "settings.json").write_text(
                json.dumps({"permissions": {"deny": ["Bash(echo Read(~/.ssh/**))"]}}),
                encoding="utf-8",
            )
            config = load_harness(root)
        self.assertFalse(config.deny_covers_path("Read", "~/.ssh"))
        self.assertTrue(config.deny_matches("echo Read", tool="Bash"))

    def test_credential_deny_must_cover_path_glob(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "settings.json").write_text(
                json.dumps({"permissions": {"deny": ["Read(~/.ssh/id_rsa)"]}}),
                encoding="utf-8",
            )
            config = load_harness(root)
        self.assertFalse(config.deny_covers_path("Read", "~/.ssh"))

    def test_disabled_claude_hooks_are_removed_from_effective_surface(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "settings.json").write_text(
                json.dumps(
                    {
                        "disableAllHooks": True,
                        "hooks": {
                            "PreToolUse": [{"matcher": "*", "hooks": [{"command": "guard.sh"}]}]
                        },
                    }
                ),
                encoding="utf-8",
            )
            config = load_harness(root)
        self.assertEqual(config.hooks, [])
        self.assertFalse(config.has_event("PreToolUse"))

    def test_async_pretool_hook_does_not_protect(self) -> None:
        config = make_codex_config(hooks=[HookEntry("PreToolUse", "", "guard.py", async_hook=True)])
        self.assertFalse(config.has_event("PreToolUse"))

    def test_claude_self_protection_requires_bash_edit_and_write(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "settings.json").write_text(
                json.dumps(
                    {
                        "permissions": {"defaultMode": "default"},
                        "hooks": {
                            "PreToolUse": [
                                {"matcher": "Bash|Edit", "hooks": [{"command": "protect-files"}]}
                            ]
                        },
                    }
                ),
                encoding="utf-8",
            )
            config = load_harness(root)
        check = next(c for c in ALL_CHECKS if c.id == "HS-D5-01")
        self.assertEqual(check.run(config).status, Status.PARTIAL)

    def test_builtin_permission_profile_overrides_legacy_sandbox(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "config.toml").write_text(
                'default_permissions = ":danger-full-access"\nsandbox_mode = "read-only"\n',
                encoding="utf-8",
            )
            config = load_codex_harness(root)
        self.assertTrue(config.sandbox_disabled)
        self.assertEqual(config.sandbox_mode, "danger-full-access")
        self.assertEqual(
            next(c for c in CODEX_CHECKS if c.id == "CDX-D8-01").run(config).status, Status.FAIL
        )

    def test_unresolved_permission_profile_is_unknown_for_sandbox_checks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "config.toml").write_text(
                'default_permissions = "custom"\nsandbox_mode = "workspace-write"\n',
                encoding="utf-8",
            )
            config = load_codex_harness(root)
        for check_id in ("CDX-D1-03", "CDX-D2-01", "CDX-D8-01"):
            self.assertEqual(
                next(c for c in CODEX_CHECKS if c.id == check_id).run(config).status, Status.UNKNOWN
            )

    def test_unresolved_sandbox_makes_unbacked_claims_unknown(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "config.toml").write_text('default_permissions = "custom"\n', encoding="utf-8")
            (root / "AGENTS.md").write_text(
                "# Hard-Deny\n- Never transmit credentials\n", encoding="utf-8"
            )
            report = audit_claims(load_codex_harness(root))
        self.assertIn(ClaimStatus.UNKNOWN, {finding.status for finding in report.findings})

    def test_claim_deny_requires_bash_tool_rule(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "settings.json").write_text(
                json.dumps({"permissions": {"deny": ["Read(rm -rf *)"]}}), encoding="utf-8"
            )
            config = load_harness(root)
        self.assertFalse(effective_block(config, deny_needles=("rm -rf",)).blocked)

    def test_stop_only_deny_guard_is_not_claim_backing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "settings.json").write_text(
                json.dumps(
                    {
                        "permissions": {"defaultMode": "default"},
                        "hooks": {"Stop": [{"hooks": [{"command": "guard.sh"}]}]},
                    }
                ),
                encoding="utf-8",
            )
            (root / "CLAUDE.md").write_text("# Hard-Deny\n- Never push to main\n", encoding="utf-8")
            (root / "guard.sh").write_text(
                "CMD=$(cat | jq -r '.tool_input.command // empty')\n"
                "if echo \"$CMD\" | grep -qE 'git push.*(main|master)'; then\n"
                '  deny "no push"\nfi\n',
                encoding="utf-8",
            )
            config = load_harness(root)
            report = audit_claims(config)
        self.assertNotIn(ClaimStatus.ENFORCED_HOOK, {finding.status for finding in report.findings})

    def test_fleet_emits_partial_report_and_exits_two_for_bad_target(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            good = root / "good"
            bad = root / "bad"
            good.mkdir()
            bad.mkdir()
            (good / "settings.json").write_text('{"permissions": {}}', encoding="utf-8")
            self.assertEqual(main(["fleet", str(good), str(bad), "--min-grade", "F"]), 2)

    def test_saved_reports_reject_invalid_nested_numeric_fields(self) -> None:
        malformed = {
            "harness_path": "fixture",
            "harness_type": "claude-code",
            "rubric_version": "1.0.0",
            "overall_score": 0.5,
            "grade": "C",
            "dimensions": [
                {"id": "D1", "name": "Secrets", "weight": 1, "score": "NaN", "checks": []}
            ],
        }
        with self.assertRaises(ValueError):
            from_dict(malformed)

    def test_diff_returns_two_for_malformed_saved_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bad = root / "bad.json"
            good = root / "good.json"
            bad.write_text(
                json.dumps(
                    {
                        "harness_path": "fixture",
                        "harness_type": "claude-code",
                        "rubric_version": "1.0.0",
                        "overall_score": 0.5,
                        "grade": "C",
                        "dimensions": [
                            {
                                "id": "D1",
                                "name": "Secrets",
                                "weight": 1,
                                "score": "NaN",
                                "checks": [],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            good.write_text(
                json.dumps(
                    {
                        "harness_path": "fixture",
                        "harness_type": "claude-code",
                        "rubric_version": "1.0.0",
                        "overall_score": 0.5,
                        "grade": "C",
                        "dimensions": [],
                    }
                ),
                encoding="utf-8",
            )
            self.assertEqual(main(["diff", str(bad), str(good)]), 2)


if __name__ == "__main__":
    unittest.main()

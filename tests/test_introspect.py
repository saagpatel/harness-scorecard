"""Tests for dispatcher introspection: evidence detection + its credit/suggest application."""

import json
import re
import tempfile
import unittest
from pathlib import Path
from typing import ClassVar

from harness_scorecard.checks import ALL_CHECKS
from harness_scorecard.checks_codex import CODEX_CHECKS
from harness_scorecard.discovery import load_harness
from harness_scorecard.discovery_codex import load_codex_harness
from harness_scorecard.introspect import Evidence, detect_evidence
from harness_scorecard.models import CheckResult, Grade, Status
from harness_scorecard.parsing import HookEntry
from harness_scorecard.report import _check_line, render_console
from harness_scorecard.scoring import _apply_detection, score_harness

_DISPATCHER = """\
import re

CODEX_SELF_WRITE_RE = re.compile(r"\\.codex/(?:hooks|config)")


def analyze(command):
    if re.search(r"git push --force", command):
        return "deny", "Force push blocked"
    return "allow", ""
"""

_COMMON = """\
HOOK_AUDIT_LOG = "audit.jsonl"


def append_audit(event):
    return event
"""

_PROMPT_DISPATCH = """\
from common import injection_signals


def main(prompt):
    hits = injection_signals(prompt)
    return hits
"""

# A Claude dispatcher that bundles several guards (injection screen, config-write protection,
# sensitive-read backstop, force-push block) behind one opaque entrypoint -- the case named-guard
# detection misses and dispatcher introspection is meant to recover.
_CLAUDE_DISPATCH = """\
import re

INJECTION_RE = re.compile(r"ignore (?:all|previous) instructions")
SENSITIVE_PATH_RE = re.compile(r"\\.ssh|\\.aws|\\.gnupg")


def content_sentinel(text):
    return bool(INJECTION_RE.search(text)) or sanitize(text)


def sanitize(text):
    return text


def protect_claude_writes(path):
    return ".claude/hooks" in path or ".claude/settings" in path


def guard(command, tool):
    if SENSITIVE_PATH_RE.search(command):
        return "deny", "protect-sensitive-reads triggered"
    if "git push --force" in command:
        return "deny", "force-push blocked"
    return "allow", ""


def secret_scan(content):
    return detect_secrets(content)


def block_egress(command):
    return "exfil" in command or re.search(r"curl .*--data @host", command)


def database_guard(command):
    return re.search(r"DROP TABLE", command)


def dependency_gate(command):
    return "--frozen-lockfile" in command or "--locked" in command


def skill_install_gate(path):
    return ".claude/skills" in path


def scope_linter(task):
    return subagent_scope_ok(task)


def defer_destructive(command):
    return "rm -rf" in command and require_confirm()
"""

# The dispatcher's sibling, where shared integrity/snapshot/audit helpers live.
_CLAUDE_COMMON = """\
HOOK_INTEGRITY_MANIFEST = "hooks.sha256"


def verify_hook_integrity():
    return True


def harness_self_heal():
    return True


def config_snapshot(path):
    return path


def config_validate(path):
    return path


def append_audit(event):
    with open("audit.jsonl", "a", encoding="utf-8") as fh:
        fh.write(event)
"""


def _hook(event: str, command: str) -> HookEntry:
    return HookEntry(event=event, matcher="", command=command)


def _result(check_id: str, status: Status = Status.FAIL) -> CheckResult:
    return CheckResult(
        id=check_id,
        dimension=check_id.rsplit("-", 1)[0].replace("CDX-", ""),
        title=check_id,
        status=status,
        weight=2,
        message="",
    )


class TestDetectEvidence(unittest.TestCase):
    def _harness(self, tmp: str) -> Path:
        root = Path(tmp)
        hooks = root / "hooks"
        hooks.mkdir()
        (hooks / "pre_tool_use_dispatch.py").write_text(_DISPATCHER, encoding="utf-8")
        (hooks / "common.py").write_text(_COMMON, encoding="utf-8")
        return root

    def test_finds_guards_in_dispatcher_and_siblings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = self._harness(tmp)
            hooks = [_hook("PreToolUse", "python3 hooks/pre_tool_use_dispatch.py")]
            found = detect_evidence(root, hooks, CODEX_CHECKS)
        # D4-02 (force-push) + D5-03 (self-write regex) from the dispatcher; D10-01 from common.py.
        self.assertEqual({"CDX-D4-02", "CDX-D5-03", "CDX-D10-01"}, set(found))
        self.assertIn("common.py", found["CDX-D10-01"].location)
        self.assertIn("pre_tool_use_dispatch.py", found["CDX-D5-03"].location)

    def test_comment_only_mention_is_not_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "hooks").mkdir()
            (root / "hooks" / "pre_tool_use_dispatch.py").write_text(
                "# we should call injection_signals(prompt) someday\nx = 1\n", encoding="utf-8"
            )
            found = detect_evidence(
                root,
                [_hook("PreToolUse", "python3 hooks/pre_tool_use_dispatch.py")],
                CODEX_CHECKS,
            )
        self.assertNotIn("CDX-D3-02", found)

    def test_injection_call_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "hooks").mkdir()
            (root / "hooks" / "user_prompt_submit_dispatch.py").write_text(
                _PROMPT_DISPATCH, encoding="utf-8"
            )
            found = detect_evidence(
                root,
                [_hook("UserPromptSubmit", "python3 hooks/user_prompt_submit_dispatch.py")],
                CODEX_CHECKS,
            )
        self.assertIn("CDX-D3-02", found)

    def test_non_dispatcher_hook_scans_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = self._harness(tmp)
            # A named guard (no dispatch idiom) is not introspected, even with guards on disk.
            found = detect_evidence(
                root, [_hook("PreToolUse", "bash hooks/git-safety.sh")], CODEX_CHECKS
            )
        self.assertEqual(found, {})

    def test_path_traversal_token_cannot_escape_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = self._harness(tmp)
            # A "../.." token resolves outside the harness root and must be ignored, not read.
            hooks = [_hook("PreToolUse", "python3 hooks/../../pre_tool_use_dispatch.py")]
            found = detect_evidence(root, hooks, CODEX_CHECKS)
        self.assertEqual(found, {})

    def test_lifecycle_event_dispatcher_is_not_scanned(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = self._harness(tmp)
            # A dispatcher on SessionStart routes lifecycle chores, not tool guards -> no evidence.
            found = detect_evidence(
                root,
                [_hook("SessionStart", "python3 hooks/pre_tool_use_dispatch.py")],
                CODEX_CHECKS,
            )
        self.assertEqual(found, {})

    def test_single_line_docstring_mention_is_not_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "hooks").mkdir()
            (root / "hooks" / "pre_tool_use_dispatch.py").write_text(
                '"""This dispatcher blocks git push --force on the Bash lane."""\nx = 1\n',
                encoding="utf-8",
            )
            found = detect_evidence(
                root,
                [_hook("PreToolUse", "python3 hooks/pre_tool_use_dispatch.py")],
                CODEX_CHECKS,
            )
        self.assertNotIn("CDX-D4-02", found)


class TestApplyDetection(unittest.TestCase):
    def test_credit_upgrades_failing_check(self) -> None:
        results = [_result("CDX-D3-02")]
        evidence = {"CDX-D3-02": Evidence("CDX-D3-02", "x.py:1", "injection_signals(")}
        notes = _apply_detection(results, evidence, credit=True)
        self.assertIs(results[0].status, Status.PARTIAL)
        self.assertTrue(results[0].dispatcher_credited)
        self.assertEqual(results[0].credit_source, "detected")
        self.assertTrue(any("auto-credited" in note for note in notes))

    def test_suggest_leaves_status_and_emits_note(self) -> None:
        results = [_result("CDX-D3-02")]
        evidence = {"CDX-D3-02": Evidence("CDX-D3-02", "x.py:1", "injection_signals(")}
        notes = _apply_detection(results, evidence, credit=False)
        self.assertIs(results[0].status, Status.FAIL)
        self.assertFalse(results[0].dispatcher_credited)
        self.assertTrue(any("--credit-detected" in note for note in notes))

    def test_manifest_credited_check_is_not_re_sourced(self) -> None:
        # A manifest credit (operator-verified) must not be overwritten to the lower-trust
        # "detected" source, and detection must add no note for an already-PARTIAL check.
        result = _result("CDX-D3-02", status=Status.PARTIAL)
        result.dispatcher_credited = True
        result.credit_source = "manifest"
        evidence = {"CDX-D3-02": Evidence("CDX-D3-02", "x.py:1", "injection_signals(")}
        notes = _apply_detection([result], evidence, credit=True)
        self.assertEqual(result.credit_source, "manifest")
        self.assertEqual(notes, [])

    def test_gate_check_is_never_auto_credited(self) -> None:
        # Lifting a capability-gate floor on a source-scan heuristic is too consequential.
        result = _result("CDX-D4-01")
        result.is_gate = True
        result.gate_cap = Grade.C
        evidence = {"CDX-D4-01": Evidence("CDX-D4-01", "x.py:1", "")}
        notes = _apply_detection([result], evidence, credit=True)
        self.assertIs(result.status, Status.FAIL)
        self.assertFalse(result.dispatcher_credited)
        self.assertTrue(any("never" in note and "auto-credited" in note for note in notes))

    def test_waived_check_is_not_credited(self) -> None:
        result = _result("CDX-D3-02")
        result.waived = True
        evidence = {"CDX-D3-02": Evidence("CDX-D3-02", "x.py:1", "injection_signals(")}
        notes = _apply_detection([result], evidence, credit=True)
        self.assertFalse(result.dispatcher_credited)
        self.assertEqual(notes, [])

    def test_unknown_check_is_ignored(self) -> None:
        notes = _apply_detection(
            [_result("CDX-D3-02")],
            {"CDX-DOES-NOT-EXIST": Evidence("CDX-DOES-NOT-EXIST", "x.py:1", "")},
            credit=True,
        )
        self.assertEqual(notes, [])


class TestDetectionRendering(unittest.TestCase):
    def test_detected_label_distinct_from_manifest(self) -> None:
        detected = _result("CDX-D3-02", status=Status.PARTIAL)
        detected.dispatcher_credited = True
        detected.credit_source = "detected"
        line = "\n".join(_check_line(detected))
        self.assertIn("(dispatcher-detected)", line)
        self.assertNotIn("(dispatcher-credited)", line)


class TestEndToEndCreditDetected(unittest.TestCase):
    def test_credit_detected_lifts_a_failing_codex_check(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "config.toml").write_text(
                'sandbox_mode = "workspace-write"\n', encoding="utf-8"
            )
            hooks_dir = root / "hooks"
            hooks_dir.mkdir()
            (hooks_dir / "pre_tool_use_dispatch.py").write_text(_DISPATCHER, encoding="utf-8")
            (root / "hooks.json").write_text(
                json.dumps(
                    {
                        "hooks": {
                            "PreToolUse": [
                                {
                                    "matcher": "",
                                    "hooks": [
                                        {"command": "python3 hooks/pre_tool_use_dispatch.py"}
                                    ],
                                }
                            ]
                        }
                    }
                ),
                encoding="utf-8",
            )
            config = load_codex_harness(root)
            detected = detect_evidence(root, config.hooks, CODEX_CHECKS)
            self.assertIn("CDX-D5-03", detected)

            suggested = score_harness(config, CODEX_CHECKS, detected=detected)
            credited = score_harness(config, CODEX_CHECKS, detected=detected, credit_detected=True)

        by_id = {c.id: c for dim in suggested.dimensions for c in dim.checks}
        self.assertIs(by_id["CDX-D5-03"].status, Status.FAIL)  # suggested, not credited
        self.assertTrue(any("CDX-D5-03" in note for note in suggested.policy_notes))

        by_id_credited = {c.id: c for dim in credited.dimensions for c in dim.checks}
        self.assertIs(by_id_credited["CDX-D5-03"].status, Status.PARTIAL)
        self.assertEqual(by_id_credited["CDX-D5-03"].credit_source, "detected")
        self.assertIn("(dispatcher-detected)", render_console(credited))


class TestClaudeCoverage(unittest.TestCase):
    """Introspection covers Claude (HS-*) checks via their dispatcher_evidence, not only Codex."""

    _GUARD = (
        "import re\n\n\n"
        "def analyze(command):\n"
        '    if re.search(r"git push --force", command):\n'
        '        return "deny", "force-push blocked"\n'
        '    return "allow", ""\n'
    )

    @staticmethod
    def _bundle_harness(root: Path) -> Path:
        """Write a Claude harness whose only guard is an opaque dispatcher + its sibling."""
        hooks = root / "hooks"
        hooks.mkdir()
        (hooks / "pre_tool_use_dispatch.py").write_text(_CLAUDE_DISPATCH, encoding="utf-8")
        (hooks / "common.py").write_text(_CLAUDE_COMMON, encoding="utf-8")
        (root / "settings.json").write_text(
            json.dumps(
                {
                    "permissions": {"defaultMode": "default"},
                    "hooks": {
                        "PreToolUse": [
                            {
                                "matcher": "Bash",
                                "hooks": [{"command": "python3 hooks/pre_tool_use_dispatch.py"}],
                            }
                        ]
                    },
                }
            ),
            encoding="utf-8",
        )
        return root

    def test_credit_detected_lifts_a_failing_claude_check(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "hooks").mkdir()
            (root / "hooks" / "pre_tool_use_dispatch.py").write_text(self._GUARD, encoding="utf-8")
            (root / "settings.json").write_text(
                json.dumps(
                    {
                        "permissions": {"defaultMode": "default"},
                        "hooks": {
                            "PreToolUse": [
                                {
                                    "matcher": "Bash",
                                    "hooks": [
                                        {"command": "python3 hooks/pre_tool_use_dispatch.py"}
                                    ],
                                }
                            ]
                        },
                    }
                ),
                encoding="utf-8",
            )
            config = load_harness(root)
            detected = detect_evidence(root, config.hooks, ALL_CHECKS)
            self.assertIn("HS-D4-05", detected)  # force-push policy, found behind the dispatcher
            suggested = score_harness(config, ALL_CHECKS, detected=detected)
            credited = score_harness(config, ALL_CHECKS, detected=detected, credit_detected=True)

        suggested_by_id = {c.id: c for dim in suggested.dimensions for c in dim.checks}
        self.assertIs(suggested_by_id["HS-D4-05"].status, Status.FAIL)  # suggested, not credited
        self.assertTrue(any("HS-D4-05" in note for note in suggested.policy_notes))

        by_id = {c.id: c for dim in credited.dimensions for c in dim.checks}
        self.assertIs(by_id["HS-D4-05"].status, Status.PARTIAL)
        self.assertEqual(by_id["HS-D4-05"].credit_source, "detected")

    def test_all_seeded_claude_guards_detected_in_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = self._bundle_harness(Path(tmp))
            found = detect_evidence(
                root,
                [_hook("PreToolUse", "python3 hooks/pre_tool_use_dispatch.py")],
                ALL_CHECKS,
            )
        seeded = {
            "HS-D1-02",
            "HS-D1-03",
            "HS-D2-01",
            "HS-D3-02",
            "HS-D4-03",
            "HS-D4-04",
            "HS-D5-01",
            "HS-D5-02",
            "HS-D5-03",
            "HS-D7-03",
            "HS-D8-02",
            "HS-D9-01",
            "HS-D10-01",
        }
        self.assertTrue(seeded.issubset(found), f"missing: {seeded - set(found)}")
        # The audit guard lives in the sibling common.py, not the dispatcher entrypoint.
        self.assertIn("common.py", found["HS-D10-01"].location)

    def test_non_gate_guards_suggested_then_credited(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = self._bundle_harness(Path(tmp))
            config = load_harness(root)
            detected = detect_evidence(root, config.hooks, ALL_CHECKS)
            suggested = score_harness(config, ALL_CHECKS, detected=detected)
            credited = score_harness(config, ALL_CHECKS, detected=detected, credit_detected=True)

        s_by_id = {c.id: c for dim in suggested.dimensions for c in dim.checks}
        c_by_id = {c.id: c for dim in credited.dimensions for c in dim.checks}
        for check_id in (
            "HS-D1-02",
            "HS-D1-03",
            "HS-D2-01",
            "HS-D3-02",
            "HS-D4-03",
            "HS-D4-04",
            "HS-D5-02",
            "HS-D5-03",
            "HS-D7-03",
            "HS-D8-02",
            "HS-D9-01",
            "HS-D10-01",
        ):
            self.assertIn(check_id, detected)
            self.assertIs(s_by_id[check_id].status, Status.FAIL)  # suggest-only by default
            self.assertTrue(any(check_id in note for note in suggested.policy_notes))
            self.assertIs(c_by_id[check_id].status, Status.PARTIAL)  # credited on opt-in
            self.assertEqual(c_by_id[check_id].credit_source, "detected")

    def test_config_protection_gate_is_suggested_never_credited(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = self._bundle_harness(Path(tmp))
            config = load_harness(root)
            detected = detect_evidence(root, config.hooks, ALL_CHECKS)
            self.assertIn("HS-D5-01", detected)  # gate evidence IS found...
            credited = score_harness(config, ALL_CHECKS, detected=detected, credit_detected=True)

        gate = {c.id: c for dim in credited.dimensions for c in dim.checks}["HS-D5-01"]
        # ...but a capability gate is never lifted by a source-scan heuristic, even with the flag.
        self.assertIs(gate.status, Status.FAIL)
        self.assertNotEqual(gate.credit_source, "detected")
        self.assertTrue(
            any("HS-D5-01" in note and "never" in note for note in credited.policy_notes)
        )

    # Per-pattern oracle: one representative code line per dispatcher_evidence pattern (IN ORDER)
    # plus look-alike lines that must match NO pattern. This exercises every pattern individually
    # (a bundle test only proves the first match fires) and pins the anti-false-credit boundary the
    # 1.9.0 review drew -- a generic verb (sanitize_path), a bare extension (training_data.jsonl),
    # or a shared path (.claude/hooks for integrity) must not credit a guard it doesn't implement.
    _PATTERN_ORACLE: ClassVar = {
        "HS-D3-02": (
            (
                "    return content_sentinel(text)",
                "INJECTION_PATTERNS = [re.compile(p) for p in raw]",
                "    return sanitize_output(text)",
            ),
            ("    x = sanitize_path(cmd)", "contents = sentinel_value", "inject_dependency(svc)"),
        ),
        "HS-D5-01": (
            (
                "def protect_claude_writes(path):",
                "    if hook_name == 'protect-files':",
                "    register('protect-config')",
            ),
            ("manifest = open('.claude/hooks/sha256')", "protective_layer = build()"),
        ),
        "HS-D5-02": (
            (
                "HOOK_INTEGRITY_MANIFEST = 'hooks.sha256'",
                "def harness_self_heal():",
                "    integrity_verify(manifest)",
            ),
            ("data_integrity_note = 1", "healthy = check_status()"),
        ),
        "HS-D5-03": (
            (
                "    config_snapshot(path)",
                "    config_validate(path)",
                "    snapshot_before_edit(settings)",
            ),
            ("snapshot = take_photo()", "validate_user(payload)"),
        ),
        "HS-D10-01": (
            (
                "def append_audit(event):",
                "    audit_log.write(line)",
                "    with open('audit.jsonl', 'a') as fh:",
            ),
            ("training_data.jsonl", "appended = audit_helper()"),
        ),
        "HS-D1-02": (
            (
                "    if '.ssh' in candidate:",
                "    if '.aws/credentials' in path:",
                "def protect_sensitive_reads():",
            ),
            ("awscli_version = '2'", "protective_reads = 0"),
        ),
        "HS-D1-03": (
            (
                "    return detect_secrets(blob)",
                "    subprocess.run(['semgrep', path])",
                "def secret_scan(content):",
            ),
            (
                "secretary = User()",
                "    self.secrets = vault",
                "    if tool_name == 'semgrep':",
                "    call_context = {'semgrep': config}",
            ),
        ),
        "HS-D2-01": (
            (
                "EGRESS_HOSTS = load_blocklist()",
                "def block_exfil(cmd):",
                "    if re.search(r'curl .*--data', c):",
            ),
            ("progress = 0.5", "    cmd = ['curl', user + '@' + host]", "    run(['curl', url])"),
        ),
        "HS-D4-03": (
            (
                "def database_guard(cmd):",
                "    if 'DROP TABLE' in sql:",
                "DESTRUCTIVE_DB_RE = compile(p)",
            ),
            ("dropdown = render()", "guard_clause(ctx)"),
        ),
        "HS-D4-04": (
            (
                "    if not install_gate.allows(cmd):",
                "    if frozen_lockfile:",
                "    if '--frozen-lockfile' in cmd:",
            ),
            (
                "email_confirm_token = make()",
                "    subprocess.run(['pip', 'install'])",
                "    install_path = base",
                "uninstall_gate = None",
            ),
        ),
        "HS-D7-03": (
            (
                "def scope_linter(task):",
                "SUBAGENT_SCOPE_RE = compile(p)",
                "    if scope_creep(diff):",
            ),
            ("scoped_session()", "    lint_file(path)"),
        ),
        "HS-D8-02": (
            (
                "def defer_destructive(cmd):",
                "DESTRUCTIVE_CONFIRM_RE = p",
                "    if confirm_destructive(op):",
            ),
            ("deferred_jobs = []", "    confirm_email(user)"),
        ),
        "HS-D9-01": (
            (
                "def skill_install_gate(path):",
                "    if '.claude/skills' in p:",
                "SKILL_PROVENANCE = load()",
            ),
            ("skillful = True", "    install_deps()"),
        ),
    }

    def test_each_seeded_pattern_matches_its_construct_not_lookalikes(self) -> None:
        by_id = {c.id: c for c in ALL_CHECKS}
        for check_id, (positives, negatives) in self._PATTERN_ORACLE.items():
            patterns = by_id[check_id].dispatcher_evidence
            self.assertEqual(
                len(positives),
                len(patterns),
                f"{check_id}: oracle covers {len(positives)} of {len(patterns)} patterns",
            )
            compiled = [re.compile(p, re.IGNORECASE) for p in patterns]
            for regex, sample in zip(compiled, positives, strict=True):
                self.assertRegex(sample, regex, f"{check_id}: {regex.pattern!r} should match")
            for neg in negatives:
                self.assertFalse(
                    any(regex.search(neg) for regex in compiled),
                    f"{check_id}: a pattern false-credits on {neg!r}",
                )


if __name__ == "__main__":
    unittest.main()

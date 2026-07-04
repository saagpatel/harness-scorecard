"""Claims extraction + matching. The adversarial negatives here are permanent: each one
reproduces a false backing the feasibility spike actually generated before the matching
design law (word-boundary tokens, canonicalized path substrings, verb+noun co-occurrence,
logic-capped candidates) killed it. Synthetic fixtures only."""

import json
import os
import tempfile
import unittest
from pathlib import Path

from harness_scorecard.claims import (
    Claim,
    ClaimClass,
    ClaimStatus,
    audit_claims,
    extract_claims,
    match_tokens,
    render_claims_json,
)
from harness_scorecard.discovery import HarnessConfig, HookEntry

RULES_MD = """# Sandboxing

## Hard-Deny

- Read or transmit `~/.ssh`, `~/.aws`, or `~/.gnupg`
- Push to `main` or `master`
- `--force` pushes to any remote

## Style

- Do NOT use waitForTimeout in database tests; prefer waitFor queries
"""

GIT_GUARD = """#!/bin/bash
CMD=$(cat | jq -r '.tool_input.command // empty')
if echo "$CMD" | grep -qE 'git push.*(main|master)'; then
  deny "no pushes to protected branches"
fi
"""

BRANCH_AWARE_GUARD = """#!/bin/bash
CMD=$(cat | jq -r '.tool_input.command // empty')
if [ "$(git branch --show-current)" = "main" ] && echo "$CMD" | grep -q 'git push'; then
  exit 2
fi
"""


def make_config(root: Path, **overrides) -> HarnessConfig:
    base = {
        "root": root,
        "harness_type": "claude-code",
        "default_mode": "default",
        "deny": [],
        "allow": [],
        "env": {},
        "hard_deny": [],
        "hooks": [],
        "rule_files": [],
        "agent_files": [],
        "skill_dirs": [],
        "has_claude_md": False,
        "raw_settings": {},
    }
    base.update(overrides)
    return HarnessConfig(**base)


def build_harness(
    root: Path,
    *,
    rules: dict[str, str] | None = None,
    hook_scripts: dict[str, str] | None = None,
    deny: list[str] | None = None,
    hard_deny: list[str] | None = None,
    mode: str = "default",
) -> HarnessConfig:
    """Write a synthetic harness to ``root`` and load it as a config."""
    rules = rules or {}
    hook_scripts = hook_scripts or {}
    (root / "rules").mkdir(exist_ok=True)
    for name, text in rules.items():
        (root / "rules" / name).write_text(text, encoding="utf-8")
    (root / "hooks").mkdir(exist_ok=True)
    hooks = []
    for name, text in hook_scripts.items():
        (root / "hooks" / name).write_text(text, encoding="utf-8")
        hooks.append(HookEntry("PreToolUse", "Bash", f"bash hooks/{name}"))
    return make_config(
        root,
        rule_files=sorted(rules),
        hooks=hooks,
        deny=deny or [],
        hard_deny=hard_deny or [],
        default_mode=mode,
    )


class TestExtraction(unittest.TestCase):
    def setUp(self):
        self.claims = extract_claims([("rules/sandboxing.md", RULES_MD)])

    def find(self, needle: str) -> Claim:
        matches = [c for c in self.claims if needle in c.text]
        self.assertEqual(len(matches), 1, f"expected one claim containing {needle!r}")
        return matches[0]

    def test_hard_deny_bullets_are_enforcement_claims(self):
        claim = self.find("~/.ssh")
        self.assertTrue(claim.hard_deny)
        self.assertIs(claim.claim_class, ClaimClass.ENFORCEMENT)
        self.assertIn("~/.ssh", claim.tokens)

    def test_convention_line_is_style_class(self):
        claim = self.find("waitForTimeout")
        self.assertFalse(claim.hard_deny)
        self.assertIs(claim.claim_class, ClaimClass.STYLE)

    def test_source_cites_file_and_line(self):
        self.assertEqual(self.find("Push to").source, "rules/sandboxing.md:6")


class TestMatchingDesignLaw(unittest.TestCase):
    """The four rules, each anchored to a spike-documented false backing."""

    def test_bare_flag_must_not_substring_match(self):
        # v1 false backing: --force "backed by" a guard matching --force-reset.
        self.assertEqual(match_tokens(["--force"], "git reset --force-reset"), [])

    def test_exact_flag_matches(self):
        self.assertTrue(match_tokens(["--force"], "git push --force origin"))

    def test_tilde_path_meets_absolute_glob(self):
        # v2 recall regression: the path forms must canonicalize both directions.
        self.assertTrue(match_tokens(["~/.ssh"], "Read(/Users/someone/.ssh/**)"))
        self.assertTrue(match_tokens(["/users/someone/.aws"], "Read(~/.aws/**)"))

    def test_single_bare_noun_is_never_backing(self):
        # v1 false backing: a style rule's "database" met the DB guard.
        self.assertEqual(match_tokens(["database"], "DROP DATABASE|TRUNCATE TABLE"), [])

    def test_multiword_span_needs_token_boundaries(self):
        # Review-round regression: `rm -rf` must not meet `confirm -rfile-flag` by
        # character coincidence.
        self.assertEqual(match_tokens(["rm", "rm -rf"], "confirm -rfile-flag"), [])
        self.assertTrue(match_tokens(["rm", "rm -rf"], "Bash(rm -rf /*)"))

    def test_verb_plus_noun_co_occurrence_matches(self):
        hits = match_tokens(["push", "main"], "git push.*(main|master)")
        self.assertIn("push", hits)
        self.assertIn("main", hits)


class TestAuditEndToEnd(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def by_text(self, report, needle: str):
        matches = [f for f in report.findings if needle in f.claim.text]
        self.assertEqual(len(matches), 1)
        return matches[0]

    def test_full_ledger_statuses(self):
        config = build_harness(
            self.root,
            rules={"sandboxing.md": RULES_MD},
            hook_scripts={"git-safety.sh": GIT_GUARD},
            deny=["Read(/Users/someone/.ssh/**)", "Read(/Users/someone/.aws/**)"],
        )
        report = audit_claims(config)
        self.assertIs(self.by_text(report, "~/.ssh").status, ClaimStatus.ENFORCED_DENY)
        self.assertIs(self.by_text(report, "Push to").status, ClaimStatus.ENFORCED_HOOK)
        # The --force hard guarantee has no backing anywhere -> the money finding.
        self.assertIs(self.by_text(report, "--force").status, ClaimStatus.PROSE_ONLY)
        # The style rule shares a noun with nothing creditable and is never matched.
        self.assertIs(self.by_text(report, "waitForTimeout").status, ClaimStatus.STYLE_RULE)
        self.assertEqual(len(report.hard_prose_only()), 1)
        self.assertEqual(report.blocks_found, 1)
        self.assertEqual(report.blocks_extracted, 1)

    def test_logic_guard_caps_at_candidate_never_enforced(self):
        config = build_harness(
            self.root,
            rules={"sandboxing.md": RULES_MD},
            hook_scripts={"branch-aware.sh": BRANCH_AWARE_GUARD},
        )
        report = audit_claims(config)
        finding = self.by_text(report, "Push to")
        self.assertIs(finding.status, ClaimStatus.CANDIDATE_LOGIC)
        self.assertEqual(finding.logic_candidates, ["branch-aware.sh"])
        self.assertEqual(finding.backing, [])

    def test_hard_deny_backs_only_when_effective(self):
        rules = {"sandboxing.md": RULES_MD}
        hard = ["Read or transmit ~/.ssh, ~/.aws"]
        effective = build_harness(self.root, rules=rules, hard_deny=hard, mode="default")
        self.assertIs(
            self.by_text(audit_claims(effective), "~/.ssh").status, ClaimStatus.ENFORCED_DENY
        )
        bypassed = build_harness(self.root, rules=rules, hard_deny=hard, mode="bypassPermissions")
        report = audit_claims(bypassed)
        self.assertIs(self.by_text(report, "~/.ssh").status, ClaimStatus.PROSE_ONLY)
        self.assertTrue(any("INERT" in note for note in report.notes))

    def test_unreadable_script_is_reported_unread_not_analyzed_and_empty(self):
        # Review-round regression: a chmod-0 guard must land in scripts_unread, never
        # masquerade as a successfully analyzed guard with zero deny blocks.
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            self.skipTest("root ignores file permission bits")
        config = build_harness(
            self.root,
            rules={"sandboxing.md": RULES_MD},
            hook_scripts={"git-safety.sh": GIT_GUARD},
        )
        script = self.root / "hooks" / "git-safety.sh"
        script.chmod(0)
        self.addCleanup(script.chmod, 0o644)
        report = audit_claims(config)
        self.assertEqual(report.scripts_read, [])
        self.assertEqual(len(report.scripts_unread), 1)
        self.assertEqual(report.blocks_found, 0)
        self.assertTrue(any("not analyzed" in note for note in report.notes))

    def test_unresolvable_hook_command_is_reported_not_silently_dropped(self):
        config = build_harness(self.root, rules={"sandboxing.md": RULES_MD})
        config.hooks.append(HookEntry("PreToolUse", "Bash", "node dispatcher.mjs"))
        report = audit_claims(config)
        self.assertEqual(report.scripts_unread, ["node dispatcher.mjs"])
        self.assertTrue(any("not analyzed" in note for note in report.notes))

    def test_qualifier_limitation_is_always_stated(self):
        report = audit_claims(build_harness(self.root, rules={"sandboxing.md": RULES_MD}))
        self.assertTrue(any("Qualifiers are not semantically verified" in n for n in report.notes))

    def test_json_render_round_trips(self):
        config = build_harness(
            self.root,
            rules={"sandboxing.md": RULES_MD},
            hook_scripts={"git-safety.sh": GIT_GUARD},
        )
        payload = json.loads(render_claims_json(audit_claims(config)))
        self.assertEqual(payload["mode"], "default")
        self.assertEqual(payload["coverage"]["deny_blocks_found"], 1)
        statuses = {f["status"] for f in payload["findings"]}
        self.assertIn("enforced_hook", statuses)


if __name__ == "__main__":
    unittest.main()

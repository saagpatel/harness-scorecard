"""Codex check suite (D1/D4/D5): fixtures plus targeted gate and partial-credit cases."""

import tempfile
import unittest
from pathlib import Path

from harness_scorecard.checks.base import Check
from harness_scorecard.checks_codex import CODEX_CHECKS
from harness_scorecard.discovery_codex import CodexConfig, load_codex_harness
from harness_scorecard.models import Status
from harness_scorecard.parsing import HookEntry
from tests.test_claims import build_codex_harness

FIXTURES = Path(__file__).parent / "fixtures"

_BY_ID = {check.id: check for check in CODEX_CHECKS}


def get_check(check_id: str) -> Check[CodexConfig]:
    return _BY_ID[check_id]


def make_codex_config(**overrides: object) -> CodexConfig:
    defaults: dict[str, object] = {
        "root": Path("/tmp/codex"),
        "harness_type": "codex",
        "model": "gpt-5.5",
        "review_model": None,
        "model_reasoning_effort": "medium",
        "approval_policy": "on-request",
        "sandbox_mode": "workspace-write",
        "web_search": "off",
        "network_access": False,
        "writable_roots": [],
        "env_inherit": "core",
        "env_ignore_default_excludes": False,
        "env_exclude": [],
        "env_set": {},
        "mcp_servers": [],
        "agents": [],
        "agents_max_threads": None,
        "agents_max_depth": None,
        "trusted_projects": [],
        "history_persistence": None,
        "notify": [],
        "hooks": [],
        "has_agents_md": True,
        "agent_files": [],
        "raw_config": {},
    }
    defaults.update(overrides)
    return CodexConfig(**defaults)  # type: ignore[arg-type]


class TestCodexFixtures(unittest.TestCase):
    def test_strong_passes_all_gates(self) -> None:
        config = load_codex_harness(FIXTURES / "codex_strong")
        for cid in ("CDX-D1-01", "CDX-D4-01", "CDX-D5-01"):
            self.assertEqual(get_check(cid).run(config).status, Status.PASS, cid)

    def test_weak_fails_all_gates(self) -> None:
        config = load_codex_harness(FIXTURES / "codex_weak")
        for cid in ("CDX-D1-01", "CDX-D4-01", "CDX-D5-01"):
            self.assertEqual(get_check(cid).run(config).status, Status.FAIL, cid)


class TestD4TrustedProjectBreadth(unittest.TestCase):
    def _run(self, **overrides: object) -> Status:
        return get_check("CDX-D4-04").run(make_codex_config(**overrides)).status

    def test_no_trusted_projects_passes(self) -> None:
        self.assertEqual(self._run(trusted_projects=[]), Status.PASS)

    def test_bounded_set_passes(self) -> None:
        self.assertEqual(self._run(trusted_projects=[f"/p/{i}" for i in range(10)]), Status.PASS)

    def test_large_set_is_partial(self) -> None:
        self.assertEqual(self._run(trusted_projects=[f"/p/{i}" for i in range(50)]), Status.PARTIAL)

    def test_very_broad_set_fails(self) -> None:
        self.assertEqual(self._run(trusted_projects=[f"/p/{i}" for i in range(150)]), Status.FAIL)

    def test_na_when_approval_already_disabled_globally(self) -> None:
        # approval_policy=never removes the gate everywhere, so trust_level breadth is moot.
        status = self._run(
            approval_policy="never", trusted_projects=[f"/p/{i}" for i in range(150)]
        )
        self.assertEqual(status, Status.NOT_APPLICABLE)


class TestD1SecretProtection(unittest.TestCase):
    def test_env_gate_fails_when_default_excludes_disabled(self) -> None:
        config = make_codex_config(env_ignore_default_excludes=True)
        self.assertEqual(get_check("CDX-D1-01").run(config).status, Status.FAIL)

    def test_credential_read_guard_credited_only_when_present(self) -> None:
        without = make_codex_config()
        self.assertEqual(get_check("CDX-D1-02").run(without).status, Status.FAIL)
        with_hook = make_codex_config(
            hooks=[HookEntry("PreToolUse", "Bash", "hooks/redact-ssh.py")]
        )
        self.assertEqual(get_check("CDX-D1-02").run(with_hook).status, Status.PASS)

    def test_sandbox_blast_radius_fails_on_danger(self) -> None:
        config = make_codex_config(sandbox_mode="danger-full-access")
        self.assertEqual(get_check("CDX-D1-03").run(config).status, Status.FAIL)


class TestD4DestructiveGit(unittest.TestCase):
    def test_gate_fails_only_when_fully_bypassed(self) -> None:
        bypassed = make_codex_config(approval_policy="never", sandbox_mode="danger-full-access")
        self.assertEqual(get_check("CDX-D4-01").run(bypassed).status, Status.FAIL)

    def test_single_layer_is_partial(self) -> None:
        # danger sandbox + approval never, but a Bash git hook is the lone remaining layer.
        config = make_codex_config(
            approval_policy="never",
            sandbox_mode="danger-full-access",
            hooks=[HookEntry("PreToolUse", "Bash", "hooks/git-safety.py")],
        )
        self.assertEqual(get_check("CDX-D4-01").run(config).status, Status.PARTIAL)

    def test_two_layers_pass(self) -> None:
        config = make_codex_config(approval_policy="on-request", sandbox_mode="workspace-write")
        self.assertEqual(get_check("CDX-D4-01").run(config).status, Status.PASS)

    def test_approval_granularity_tiers(self) -> None:
        self.assertEqual(
            get_check("CDX-D4-03").run(make_codex_config(approval_policy="untrusted")).status,
            Status.PASS,
        )
        # Rubric 1.4.0 alignment: on-request is model-discretionary, never full gate credit.
        self.assertEqual(
            get_check("CDX-D4-03").run(make_codex_config(approval_policy="on-request")).status,
            Status.PARTIAL,
        )
        self.assertEqual(
            get_check("CDX-D4-03").run(make_codex_config(approval_policy="on-failure")).status,
            Status.PARTIAL,
        )
        self.assertEqual(
            get_check("CDX-D4-03").run(make_codex_config(approval_policy="never")).status,
            Status.FAIL,
        )

    def test_git_hook_must_be_on_bash_lane(self) -> None:
        wrong_lane = make_codex_config(
            hooks=[HookEntry("PreToolUse", "Read", "hooks/git-safety.py")]
        )
        self.assertEqual(get_check("CDX-D4-02").run(wrong_lane).status, Status.FAIL)

    def test_generic_hook_name_does_not_falsely_satisfy_gate(self) -> None:
        # An unrelated Bash hook (push-notification) must NOT be credited as a git guard,
        # so a fully-bypassed harness still trips the gate.
        bypassed = make_codex_config(
            approval_policy="never",
            sandbox_mode="danger-full-access",
            hooks=[HookEntry("PreToolUse", "Bash", "hooks/push-notification.py")],
        )
        self.assertEqual(get_check("CDX-D4-01").run(bypassed).status, Status.FAIL)


class TestD5SelfProtection(unittest.TestCase):
    def test_claims_check_registered(self) -> None:
        self.assertIn("CDX-D5-04", _BY_ID)

    def test_sandbox_protects_harness_by_default(self) -> None:
        config = make_codex_config(sandbox_mode="workspace-write")
        self.assertEqual(get_check("CDX-D5-01").run(config).status, Status.PASS)

    def test_danger_without_hook_trips_gate(self) -> None:
        config = make_codex_config(sandbox_mode="danger-full-access")
        self.assertEqual(get_check("CDX-D5-01").run(config).status, Status.FAIL)

    def test_danger_with_self_protect_hook_passes(self) -> None:
        config = make_codex_config(
            sandbox_mode="danger-full-access",
            hooks=[HookEntry("PreToolUse", "Bash", "hooks/self-protect.py")],
        )
        self.assertEqual(get_check("CDX-D5-01").run(config).status, Status.PASS)

    def test_writable_root_over_codex_home_defeats_sandbox(self) -> None:
        config = make_codex_config(
            root=Path("/Users/x/.codex"),
            sandbox_mode="workspace-write",
            writable_roots=["/Users/x/.codex"],
        )
        self.assertEqual(get_check("CDX-D5-01").run(config).status, Status.FAIL)

    def test_tilde_home_writable_root_defeats_sandbox(self) -> None:
        # writable_roots = ["~"] exposes home (which contains ~/.codex); must trip the gate.
        config = make_codex_config(
            root=Path.home() / ".codex",
            sandbox_mode="workspace-write",
            writable_roots=["~"],
        )
        self.assertEqual(get_check("CDX-D5-01").run(config).status, Status.FAIL)

    def test_unrelated_integrity_hook_does_not_satisfy_self_protection(self) -> None:
        # A data-integrity hook must not be credited as a harness self-protection guard.
        config = make_codex_config(
            sandbox_mode="danger-full-access",
            hooks=[HookEntry("PreToolUse", "Bash", "hooks/referential-integrity.py")],
        )
        self.assertEqual(get_check("CDX-D5-01").run(config).status, Status.FAIL)

    def test_agents_md_required(self) -> None:
        self.assertEqual(
            get_check("CDX-D5-02").run(make_codex_config(has_agents_md=False)).status,
            Status.FAIL,
        )

    def test_claims_check_na_when_no_hard_guarantees(self) -> None:
        config = make_codex_config(has_agents_md=False)
        self.assertEqual(get_check("CDX-D5-04").run(config).status, Status.NOT_APPLICABLE)

    def test_claims_check_passes_when_config_backs_hard_guarantee(self) -> None:
        # The write-scope sandbox genuinely protects ~/.codex — the one hard guarantee
        # the default config can honestly back.
        with tempfile.TemporaryDirectory() as tmp:
            config = build_codex_harness(
                Path(tmp),
                agents_md="# AGENTS\n\n## Hard-Deny\n\n- Mutate `~/.codex` or its `config.toml`\n",
            )
            self.assertEqual(get_check("CDX-D5-04").run(config).status, Status.PASS)

    def test_claims_check_fails_multiverb_claim_under_default_config(self) -> None:
        # Release-gate regression (2026-07): this exact harness graded PASS because a
        # keyword-bag backing string absorbed the claim's destructive verbs. Nothing in
        # the default config enforces it; the check must FAIL.
        with tempfile.TemporaryDirectory() as tmp:
            config = build_codex_harness(
                Path(tmp),
                agents_md=(
                    "# AGENTS\n\n## Hard-Deny\n\n"
                    "- Never drop, truncate, or delete production database tables\n"
                ),
            )
            self.assertEqual(get_check("CDX-D5-04").run(config).status, Status.FAIL)

    def test_claims_check_fails_when_bypass_leaves_prose_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = build_codex_harness(
                Path(tmp),
                agents_md="# AGENTS\n\n## Hard-Deny\n\n- Push to `main` or `master`\n",
                approval_policy="never",
                sandbox_mode="danger-full-access",
            )
            self.assertEqual(get_check("CDX-D5-04").run(config).status, Status.FAIL)


if __name__ == "__main__":
    unittest.main()

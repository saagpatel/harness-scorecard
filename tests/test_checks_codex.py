"""Codex check suite (D1/D4/D5): fixtures plus targeted gate and partial-credit cases."""

import unittest
from pathlib import Path

from harness_scorecard.checks.base import Check
from harness_scorecard.checks_codex import CODEX_CHECKS
from harness_scorecard.discovery_codex import CodexConfig, load_codex_harness
from harness_scorecard.models import Status
from harness_scorecard.parsing import HookEntry

FIXTURES = Path(__file__).parent / "fixtures"

_BY_ID = {check.id: check for check in CODEX_CHECKS}


def get_check(check_id: str) -> Check[CodexConfig]:
    return _BY_ID[check_id]


def make_codex_config(**overrides: object) -> CodexConfig:
    defaults: dict[str, object] = {
        "root": Path("/tmp/codex"),
        "harness_type": "codex",
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
            get_check("CDX-D4-03").run(make_codex_config(approval_policy="on-request")).status,
            Status.PASS,
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


if __name__ == "__main__":
    unittest.main()

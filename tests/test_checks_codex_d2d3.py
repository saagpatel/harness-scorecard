"""Codex D2 (egress) and D3 (tool-surface / injection) checks."""

import unittest
from pathlib import Path

from harness_scorecard.discovery_codex import load_codex_harness
from harness_scorecard.models import Status
from harness_scorecard.parsing import HookEntry
from tests.test_checks_codex import get_check, make_codex_config

FIXTURES = Path(__file__).parent / "fixtures"


class TestD2OnFixtures(unittest.TestCase):
    def test_strong_passes_network_and_web_search(self) -> None:
        config = load_codex_harness(FIXTURES / "codex_strong")
        self.assertEqual(get_check("CDX-D2-01").run(config).status, Status.PASS)
        self.assertEqual(get_check("CDX-D2-02").run(config).status, Status.PASS)
        # Network blocked by sandbox but no dedicated egress hook -> partial.
        self.assertEqual(get_check("CDX-D2-03").run(config).status, Status.PARTIAL)

    def test_weak_fails_egress(self) -> None:
        config = load_codex_harness(FIXTURES / "codex_weak")
        self.assertEqual(get_check("CDX-D2-01").run(config).status, Status.FAIL)
        self.assertEqual(get_check("CDX-D2-03").run(config).status, Status.FAIL)


class TestD2Network(unittest.TestCase):
    def test_open_network_fails(self) -> None:
        config = make_codex_config(sandbox_mode="danger-full-access")
        self.assertEqual(get_check("CDX-D2-01").run(config).status, Status.FAIL)

    def test_workspace_write_with_network_access_fails(self) -> None:
        config = make_codex_config(sandbox_mode="workspace-write", network_access=True)
        self.assertEqual(get_check("CDX-D2-01").run(config).status, Status.FAIL)


class TestD2WebSearch(unittest.TestCase):
    def test_live_fails(self) -> None:
        # live fully violates "does not fetch live pages" -> FAIL, not PARTIAL.
        config = make_codex_config(web_search="live")
        self.assertEqual(get_check("CDX-D2-02").run(config).status, Status.FAIL)

    def test_cached_passes(self) -> None:
        config = make_codex_config(web_search="cached")
        self.assertEqual(get_check("CDX-D2-02").run(config).status, Status.PASS)

    def test_unknown_value_is_partial(self) -> None:
        config = make_codex_config(web_search="experimental")
        self.assertEqual(get_check("CDX-D2-02").run(config).status, Status.PARTIAL)


class TestD2EgressMonitoring(unittest.TestCase):
    def test_egress_hook_passes_even_when_network_open(self) -> None:
        config = make_codex_config(
            sandbox_mode="danger-full-access",
            hooks=[HookEntry("PreToolUse", "Bash", "hooks/egress-guard.py")],
        )
        self.assertEqual(get_check("CDX-D2-03").run(config).status, Status.PASS)


class TestD3ToolSurface(unittest.TestCase):
    def test_strong_passes_both(self) -> None:
        config = load_codex_harness(FIXTURES / "codex_strong")
        self.assertEqual(get_check("CDX-D3-01").run(config).status, Status.PASS)
        self.assertEqual(get_check("CDX-D3-02").run(config).status, Status.PASS)

    def test_no_hooks_fails_both(self) -> None:
        config = make_codex_config(hooks=[])
        self.assertEqual(get_check("CDX-D3-01").run(config).status, Status.FAIL)
        self.assertEqual(get_check("CDX-D3-02").run(config).status, Status.FAIL)

    def test_permission_request_gates_tools(self) -> None:
        config = make_codex_config(hooks=[HookEntry("PermissionRequest", "", "hooks/approve.py")])
        self.assertEqual(get_check("CDX-D3-01").run(config).status, Status.PASS)

    def test_sanitizing_user_prompt_submit_defends_injection(self) -> None:
        config = make_codex_config(
            hooks=[HookEntry("UserPromptSubmit", "", "hooks/sanitize-prompt.py")]
        )
        self.assertEqual(get_check("CDX-D3-02").run(config).status, Status.PASS)

    def test_bare_user_prompt_submit_audit_hook_is_not_injection_defense(self) -> None:
        # A UserPromptSubmit audit logger does not screen for injection -> no false PASS.
        config = make_codex_config(hooks=[HookEntry("UserPromptSubmit", "", "hooks/log-prompt.py")])
        self.assertEqual(get_check("CDX-D3-02").run(config).status, Status.FAIL)

    def test_sanitization_pretooluse_hook_defends_injection(self) -> None:
        config = make_codex_config(
            hooks=[HookEntry("PreToolUse", "Bash", "hooks/sanitize-content.py")]
        )
        self.assertEqual(get_check("CDX-D3-02").run(config).status, Status.PASS)


if __name__ == "__main__":
    unittest.main()

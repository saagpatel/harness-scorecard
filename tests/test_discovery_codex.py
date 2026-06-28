"""The Codex discovery adapter parses config.toml + hooks.json and resolves the effective floor."""

import tempfile
import unittest
from pathlib import Path

from harness_scorecard.discovery_codex import (
    HARNESS_TYPE_CODEX,
    CodexConfig,
    load_codex_harness,
)

FIXTURES = Path(__file__).parent / "fixtures"


class TestStrongCodexHarness(unittest.TestCase):
    def setUp(self) -> None:
        self.config = load_codex_harness(FIXTURES / "codex_strong")

    def test_core_fields(self) -> None:
        self.assertEqual(self.config.harness_type, HARNESS_TYPE_CODEX)
        self.assertEqual(self.config.approval_policy, "on-request")
        self.assertEqual(self.config.sandbox_mode, "workspace-write")
        self.assertEqual(self.config.web_search, "off")
        # Parsed to a real False (network denied), not None (key absent).
        self.assertIsNotNone(self.config.network_access)
        self.assertFalse(self.config.network_access)

    def test_effective_floor_is_solid(self) -> None:
        self.assertFalse(self.config.sandbox_disabled)
        self.assertFalse(self.config.approval_disabled)
        self.assertFalse(self.config.is_bypass)
        self.assertTrue(self.config.network_blocked)
        self.assertTrue(self.config.env_secrets_scrubbed)

    def test_agents_mcp_and_projects(self) -> None:
        self.assertEqual(self.config.mcp_servers, ["fetch"])
        self.assertEqual(self.config.agents_max_threads, 4)
        self.assertEqual(self.config.agents_max_depth, 1)
        names = {a.name: a for a in self.config.agents}
        self.assertEqual(names["worker"].approval_policy, "on-request")
        self.assertIsNone(names["explorer"].approval_policy)
        self.assertEqual(self.config.trusted_projects, ["/Users/example/Projects/app"])

    def test_docs_hooks_and_inventory(self) -> None:
        self.assertTrue(self.config.has_agents_md)
        self.assertEqual(self.config.agent_files, ["worker.toml"])
        self.assertEqual(self.config.history_persistence, "save-all")
        events = {h.event for h in self.config.hooks}
        self.assertEqual(
            events, {"SessionStart", "UserPromptSubmit", "PreToolUse", "PostToolUse", "Stop"}
        )
        self.assertTrue(any("git-safety" in h.command for h in self.config.hooks))


class TestWeakCodexHarness(unittest.TestCase):
    def setUp(self) -> None:
        self.config = load_codex_harness(FIXTURES / "codex_weak")

    def test_effective_floor_is_bypassed(self) -> None:
        self.assertTrue(self.config.sandbox_disabled)
        self.assertTrue(self.config.approval_disabled)
        self.assertTrue(self.config.is_bypass)
        self.assertFalse(self.config.network_blocked)
        self.assertFalse(self.config.env_secrets_scrubbed)

    def test_no_docs_or_hooks(self) -> None:
        self.assertFalse(self.config.has_agents_md)
        self.assertEqual(self.config.hooks, [])
        self.assertEqual(len(self.config.trusted_projects), 2)


class TestLoadContract(unittest.TestCase):
    def test_missing_both_files_raises(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, self.assertRaises(FileNotFoundError):
            load_codex_harness(tmp)

    def test_agents_md_only_loads_with_defaults(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "AGENTS.md").write_text("# AGENTS\n", encoding="utf-8")
            config = load_codex_harness(tmp)
        self.assertIsInstance(config, CodexConfig)
        self.assertTrue(config.has_agents_md)
        # Codex's documented defaults: read-only sandbox, on-request approval.
        self.assertEqual(config.sandbox_mode, "read-only")
        self.assertTrue(config.network_blocked)

    def test_malformed_toml_degrades_without_crashing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "config.toml").write_text("this is = = not valid toml", encoding="utf-8")
            config = load_codex_harness(tmp)
        self.assertEqual(config.raw_config, {})
        self.assertEqual(config.sandbox_mode, "read-only")

    def test_env_set_with_secret_name_defeats_scrubbing(self) -> None:
        # inherit="none" scrubs inherited env, but an explicit secret-named set still leaks.
        toml = (
            '[shell_environment_policy]\ninherit = "none"\n'
            '[shell_environment_policy.set]\nAWS_SECRET_ACCESS_KEY = "x"\n'
        )
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "config.toml").write_text(toml, encoding="utf-8")
            config = load_codex_harness(tmp)
        self.assertFalse(config.env_secrets_scrubbed)

    def test_benign_env_name_with_key_substring_is_not_a_secret(self) -> None:
        # MONKEY_ID ends in KEY but is not a credential; scrubbing must stay True.
        toml = (
            '[shell_environment_policy]\ninherit = "core"\n'
            '[shell_environment_policy.set]\nMONKEY_ID = "42"\n'
        )
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "config.toml").write_text(toml, encoding="utf-8")
            config = load_codex_harness(tmp)
        self.assertTrue(config.env_secrets_scrubbed)

    def test_bool_not_read_as_int_for_agent_bounds(self) -> None:
        # max_threads omitted -> None, never coerced from an unrelated bool.
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "config.toml").write_text("[agents]\n", encoding="utf-8")
            config = load_codex_harness(tmp)
        self.assertIsNone(config.agents_max_threads)


if __name__ == "__main__":
    unittest.main()

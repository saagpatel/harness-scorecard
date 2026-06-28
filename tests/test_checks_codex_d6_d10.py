"""Codex D6-D10: verification, subagent governance, recovery, provenance, observability."""

import unittest
from pathlib import Path

from harness_scorecard.discovery_codex import CodexAgent, load_codex_harness
from harness_scorecard.models import Status
from harness_scorecard.parsing import HookEntry
from tests.test_checks_codex import get_check, make_codex_config

FIXTURES = Path(__file__).parent / "fixtures"


class TestStrongAndWeakAcrossD6D10(unittest.TestCase):
    def test_strong_passes_each_dimension_lead_check(self) -> None:
        config = load_codex_harness(FIXTURES / "codex_strong")
        for cid in ("CDX-D6-01", "CDX-D7-01", "CDX-D8-01", "CDX-D9-02", "CDX-D10-01"):
            self.assertEqual(get_check(cid).run(config).status, Status.PASS, cid)

    def test_weak_fails_or_na(self) -> None:
        config = load_codex_harness(FIXTURES / "codex_weak")
        self.assertEqual(get_check("CDX-D6-01").run(config).status, Status.FAIL)
        self.assertEqual(get_check("CDX-D8-02").run(config).status, Status.FAIL)
        self.assertEqual(get_check("CDX-D10-01").run(config).status, Status.FAIL)
        # No agents declared -> subagent/provenance agent checks are N/A, not FAIL.
        self.assertEqual(get_check("CDX-D7-02").run(config).status, Status.NOT_APPLICABLE)
        self.assertEqual(get_check("CDX-D9-01").run(config).status, Status.NOT_APPLICABLE)


class TestD6Verification(unittest.TestCase):
    def test_stop_hook_without_gate_intent_is_not_credited(self) -> None:
        config = make_codex_config(hooks=[HookEntry("Stop", "", "hooks/notify.py")])
        self.assertEqual(get_check("CDX-D6-01").run(config).status, Status.FAIL)

    def test_qa_agent_satisfies_verification(self) -> None:
        config = make_codex_config(agents=[CodexAgent("qa", None, "agents/qa.toml")])
        self.assertEqual(get_check("CDX-D6-02").run(config).status, Status.PASS)

    def test_only_non_verification_agents_fails(self) -> None:
        config = make_codex_config(agents=[CodexAgent("worker", None, "agents/worker.toml")])
        self.assertEqual(get_check("CDX-D6-02").run(config).status, Status.FAIL)

    def test_preview_agent_does_not_falsely_match_review(self) -> None:
        # "review" must not match as a substring of "preview-builder".
        config = make_codex_config(agents=[CodexAgent("preview-builder", None, None)])
        self.assertEqual(get_check("CDX-D6-02").run(config).status, Status.FAIL)

    def test_reviewer_agent_is_credited(self) -> None:
        config = make_codex_config(agents=[CodexAgent("code-reviewer", None, "agents/r.toml")])
        self.assertEqual(get_check("CDX-D6-02").run(config).status, Status.PASS)

    def test_verify_ssl_stop_hook_is_not_a_verification_gate(self) -> None:
        config = make_codex_config(hooks=[HookEntry("Stop", "", "hooks/verify-ssl.py")])
        self.assertEqual(get_check("CDX-D6-01").run(config).status, Status.FAIL)


class TestD7Subagents(unittest.TestCase):
    def test_one_bound_is_partial(self) -> None:
        config = make_codex_config(agents_max_threads=4, agents_max_depth=None)
        self.assertEqual(get_check("CDX-D7-01").run(config).status, Status.PARTIAL)

    def test_no_bounds_fails(self) -> None:
        config = make_codex_config(agents_max_threads=None, agents_max_depth=None)
        self.assertEqual(get_check("CDX-D7-01").run(config).status, Status.FAIL)

    def test_agent_with_never_bypass_fails(self) -> None:
        config = make_codex_config(agents=[CodexAgent("rogue", "never", None)])
        self.assertEqual(get_check("CDX-D7-02").run(config).status, Status.FAIL)


class TestD8Recovery(unittest.TestCase):
    def test_danger_sandbox_is_not_recoverable(self) -> None:
        config = make_codex_config(sandbox_mode="danger-full-access")
        self.assertEqual(get_check("CDX-D8-01").run(config).status, Status.FAIL)

    def test_session_start_hook_passes(self) -> None:
        config = make_codex_config(hooks=[HookEntry("SessionStart", "", "hooks/checkpoint.py")])
        self.assertEqual(get_check("CDX-D8-02").run(config).status, Status.PASS)


class TestD9Provenance(unittest.TestCase):
    def test_agents_without_config_files_fail(self) -> None:
        config = make_codex_config(agents=[CodexAgent("worker", None, None)])
        self.assertEqual(get_check("CDX-D9-01").run(config).status, Status.FAIL)

    def test_partial_provenance_when_some_agents_untracked(self) -> None:
        config = make_codex_config(
            agents=[
                CodexAgent("worker", None, "agents/worker.toml"),
                CodexAgent("rogue", None, None),
            ]
        )
        self.assertEqual(get_check("CDX-D9-01").run(config).status, Status.PARTIAL)

    def test_history_none_fails(self) -> None:
        config = make_codex_config(history_persistence="none")
        self.assertEqual(get_check("CDX-D9-02").run(config).status, Status.FAIL)

    def test_history_unset_fails(self) -> None:
        config = make_codex_config(history_persistence=None)
        self.assertEqual(get_check("CDX-D9-02").run(config).status, Status.FAIL)


class TestD10Observability(unittest.TestCase):
    def test_audit_log_needs_audit_intent(self) -> None:
        non_audit = make_codex_config(hooks=[HookEntry("PostToolUse", "Bash", "hooks/format.py")])
        self.assertEqual(get_check("CDX-D10-01").run(non_audit).status, Status.FAIL)

    def test_disable_logging_hook_is_not_an_audit_trail(self) -> None:
        # A hook that *disables* logging must not be credited as an audit trail.
        config = make_codex_config(
            hooks=[HookEntry("PostToolUse", "Bash", "hooks/disable-logging.py")]
        )
        self.assertEqual(get_check("CDX-D10-01").run(config).status, Status.FAIL)

    def test_stop_hook_only_is_partial_observability(self) -> None:
        config = make_codex_config(notify=[], hooks=[HookEntry("Stop", "", "hooks/stop-gate.py")])
        self.assertEqual(get_check("CDX-D10-02").run(config).status, Status.PARTIAL)

    def test_notify_passes_observability(self) -> None:
        config = make_codex_config(notify=["python3 notify.py"])
        self.assertEqual(get_check("CDX-D10-02").run(config).status, Status.PASS)


if __name__ == "__main__":
    unittest.main()

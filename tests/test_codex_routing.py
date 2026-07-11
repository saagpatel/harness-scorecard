"""GPT-5.6-era Codex routing precedence, ambiguity, and red-team calibration."""

from __future__ import annotations

import unittest
from pathlib import Path

from harness_scorecard.checks_codex import CODEX_CHECKS
from harness_scorecard.discovery_codex import load_codex_harness
from harness_scorecard.models import Scorecard, Status
from harness_scorecard.scoring import score_harness
from tests.test_checks_codex import get_check

FIXTURES = Path(__file__).parent / "fixtures" / "codex_routing"
REDTEAM = Path(__file__).parent.parent / "examples" / "redteam" / "codex-d7-routing"


def _status(name: str, check_id: str) -> Status:
    config = load_codex_harness(FIXTURES / name)
    return get_check(check_id).run(config).status


def _score(path: Path) -> Scorecard:
    return score_harness(load_codex_harness(path), CODEX_CHECKS)


def _dimension_score(card: Scorecard, dimension: str) -> float:
    return next(item.score for item in card.dimensions if item.id == dimension)


class TestPersistentRoutingFixtures(unittest.TestCase):
    def test_safe_default_with_explicit_high_exception_passes(self) -> None:
        config = load_codex_harness(FIXTURES / "safe_exception")
        routes = {route.name: route for route in config.routing_routes}
        self.assertEqual(routes["default"].reasoning_effort, "medium")
        self.assertEqual(routes["profile:deep-review"].reasoning_effort, "high")
        self.assertEqual(get_check("CDX-D7-03").run(config).status, Status.PASS)
        self.assertEqual(get_check("CDX-D7-04").run(config).status, Status.NOT_APPLICABLE)

    def test_unguarded_global_ultra_fails(self) -> None:
        self.assertEqual(_status("global_ultra", "CDX-D7-03"), Status.FAIL)
        self.assertEqual(_status("global_ultra", "CDX-D7-04"), Status.FAIL)

    def test_trusted_project_override_wins_over_safe_global_default(self) -> None:
        config = load_codex_harness(FIXTURES / "project_override")
        project = next(route for route in config.routing_routes if route.kind == "project")
        combined = next(route for route in config.routing_routes if route.kind == "profile+project")
        self.assertEqual(project.reasoning_effort, "max")
        self.assertEqual(combined.reasoning_effort, "max")
        self.assertEqual(project.approval_policy, "never")
        self.assertEqual(project.sandbox_mode, "danger-full-access")
        self.assertEqual(get_check("CDX-D7-03").run(config).status, Status.FAIL)
        self.assertEqual(get_check("CDX-D7-04").run(config).status, Status.FAIL)

    def test_prose_only_exception_does_not_back_max_default(self) -> None:
        self.assertEqual(_status("prose_only", "CDX-D7-03"), Status.FAIL)
        self.assertEqual(_status("prose_only", "CDX-D7-04"), Status.FAIL)

    def test_stale_or_unsupported_model_is_unknown(self) -> None:
        self.assertEqual(_status("stale_model", "CDX-D7-03"), Status.UNKNOWN)

    def test_custom_provider_owns_model_compatibility(self) -> None:
        self.assertEqual(_status("custom_provider", "CDX-D7-03"), Status.UNKNOWN)
        self.assertEqual(_status("custom_provider", "CDX-D7-04"), Status.UNKNOWN)

    def test_unsupported_ultra_marker_is_unknown(self) -> None:
        self.assertEqual(_status("unsupported_marker", "CDX-D7-04"), Status.UNKNOWN)

    def test_contradictory_permission_surfaces_are_unknown(self) -> None:
        self.assertEqual(_status("contradictory", "CDX-D7-03"), Status.UNKNOWN)

    def test_unseen_invocation_selection_is_unknown_not_safe(self) -> None:
        config = load_codex_harness(FIXTURES / "invocation_unknown")
        self.assertEqual(get_check("CDX-D7-03").run(config).status, Status.UNKNOWN)
        self.assertTrue(any("invocation flags" in caveat for caveat in config.caveats))


class TestRoutingRedTeamPair(unittest.TestCase):
    def test_vulnerable_pair_has_exact_score_effect(self) -> None:
        vulnerable = _score(REDTEAM / "vulnerable")
        guarded = _score(REDTEAM / "guarded")
        self.assertEqual(_dimension_score(vulnerable, "D7"), 0.5)
        self.assertEqual(_dimension_score(guarded, "D7"), 1.0)
        self.assertGreater(guarded.overall_score, vulnerable.overall_score)


if __name__ == "__main__":
    unittest.main()

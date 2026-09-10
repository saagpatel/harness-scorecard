"""CDX-D7-05 GPT-5.6 cache-breakpoint hygiene: fixtures, UNKNOWN contract, renderers, diffs."""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from harness_scorecard.checks_codex import CODEX_CHECKS
from harness_scorecard.codex_cache import parse_cache_declaration
from harness_scorecard.diff import diff_scorecards, render_diff_console, render_diff_json
from harness_scorecard.discovery_codex import load_codex_harness
from harness_scorecard.htmlreport import render_html
from harness_scorecard.models import Grade, Status
from harness_scorecard.report import render_console, to_dict
from harness_scorecard.sarif import to_sarif
from harness_scorecard.scoring import score_harness
from harness_scorecard.summary import render_github_summary
from tests.test_checks_codex import get_check, make_codex_config

FIXTURES = Path(__file__).parent / "fixtures" / "codex_cache"
REDTEAM = Path(__file__).parent.parent / "examples" / "redteam" / "codex-d7-routing"
STRONG = Path(__file__).parent / "fixtures" / "codex_strong"


def _status(name: str) -> Status:
    return get_check("CDX-D7-05").run(load_codex_harness(FIXTURES / name)).status


def _score(path: Path):
    return score_harness(load_codex_harness(path), CODEX_CHECKS)


def _dimension_score(card, dimension: str) -> float:
    return next(item.score for item in card.dimensions if item.id == dimension)


def _check(card, check_id: str):
    for dim in card.dimensions:
        for result in dim.checks:
            if result.id == check_id:
                return result
    msg = f"{check_id} missing from {card.harness_path}"
    raise AssertionError(msg)


class TestCacheDeclarationParser(unittest.TestCase):
    def test_official_explicit_prefix(self) -> None:
        parsed = parse_cache_declaration(
            {
                "prompt_cache_options": {"mode": "explicit", "ttl": "30m"},
                "input": [
                    {
                        "role": "developer",
                        "content": [
                            {
                                "type": "input_text",
                                "text": "policy",
                                "prompt_cache_breakpoint": {"mode": "explicit"},
                            }
                        ],
                    },
                    {
                        "role": "user",
                        "content": [{"type": "input_text", "text": "project"}],
                    },
                ],
            }
        )
        self.assertTrue(parsed.declared)
        self.assertEqual(parsed.mode, "explicit")
        self.assertEqual(parsed.ttl, "30m")
        self.assertEqual(len(parsed.blocks), 2)
        self.assertTrue(parsed.blocks[0].has_breakpoint)
        self.assertFalse(parsed.blocks[1].has_breakpoint)
        self.assertEqual(parsed.unofficial_markers, ())
        self.assertEqual(parsed.issues, ())

    def test_unofficial_markers_and_malformed_options(self) -> None:
        parsed = parse_cache_declaration(
            {
                "cache_control": {"type": "ephemeral"},
                "prompt_cache_retention": "24h",
                "prompt_cache_options": "explicit",
            }
        )
        self.assertIn("cache_control", parsed.unofficial_markers)
        self.assertIn("prompt_cache_retention", parsed.unofficial_markers)
        self.assertTrue(any("not a table" in issue for issue in parsed.issues))


class TestCacheBreakpointFixtures(unittest.TestCase):
    def test_explicit_stable_first_passes(self) -> None:
        self.assertEqual(_status("explicit_stable_first"), Status.PASS)

    def test_implicit_mode_fails(self) -> None:
        self.assertEqual(_status("implicit_hides_writes"), Status.FAIL)

    def test_volatile_before_policy_fails(self) -> None:
        self.assertEqual(_status("volatile_before_policy"), Status.FAIL)

    def test_runtime_only_is_unknown(self) -> None:
        self.assertEqual(_status("runtime_only"), Status.UNKNOWN)

    def test_unsupported_markers_are_unknown(self) -> None:
        self.assertEqual(_status("unsupported_marker"), Status.UNKNOWN)

    def test_ambiguous_breakpoint_mode_is_unknown(self) -> None:
        self.assertEqual(_status("ambiguous_breakpoint"), Status.UNKNOWN)

    def test_custom_provider_is_unknown(self) -> None:
        self.assertEqual(_status("custom_provider"), Status.UNKNOWN)

    def test_earlier_model_is_not_applicable(self) -> None:
        self.assertEqual(_status("earlier_model"), Status.NOT_APPLICABLE)


class TestCacheBreakpointUnitCases(unittest.TestCase):
    def test_gpt55_default_is_not_applicable(self) -> None:
        self.assertEqual(
            get_check("CDX-D7-05").run(make_codex_config()).status, Status.NOT_APPLICABLE
        )

    def test_runtime_selected_model_is_unknown(self) -> None:
        config = make_codex_config(model=None)
        self.assertEqual(get_check("CDX-D7-05").run(config).status, Status.UNKNOWN)

    def test_omitted_mode_with_options_fails(self) -> None:
        config = make_codex_config(
            model="gpt-5.6-sol",
            raw_config={"prompt_cache_options": {"ttl": "30m"}},
        )
        result = get_check("CDX-D7-05").run(config)
        self.assertEqual(result.status, Status.FAIL)
        self.assertIn("unaccounted", result.message)

    def test_explicit_without_blocks_is_unknown(self) -> None:
        config = make_codex_config(
            model="gpt-5.6-sol",
            raw_config={"prompt_cache_options": {"mode": "explicit"}},
        )
        self.assertEqual(get_check("CDX-D7-05").run(config).status, Status.UNKNOWN)

    def test_earlier_model_with_cache_fields_is_unknown(self) -> None:
        config = make_codex_config(
            model="gpt-5.5",
            raw_config={"prompt_cache_options": {"mode": "explicit"}},
        )
        self.assertEqual(get_check("CDX-D7-05").run(config).status, Status.UNKNOWN)

    def test_breakpoint_on_volatile_block_fails(self) -> None:
        config = make_codex_config(
            model="gpt-5.6-sol",
            raw_config={
                "prompt_cache_options": {"mode": "explicit"},
                "input": [
                    {
                        "role": "developer",
                        "content": [{"type": "input_text", "text": "policy"}],
                    },
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "input_text",
                                "text": "project",
                                "prompt_cache_breakpoint": {"mode": "explicit"},
                            }
                        ],
                    },
                ],
            },
        )
        result = get_check("CDX-D7-05").run(config)
        self.assertEqual(result.status, Status.FAIL)
        self.assertIn("volatile", result.message.lower())

    def test_discovery_attaches_cache_to_persistent_routes(self) -> None:
        config = load_codex_harness(FIXTURES / "explicit_stable_first")
        self.assertEqual(len(config.routing_routes), 1)
        cache = config.routing_routes[0].cache
        self.assertEqual(cache.mode, "explicit")
        self.assertTrue(cache.blocks[0].has_breakpoint)


class TestScoringSemanticsPreserved(unittest.TestCase):
    def test_codex_strong_stays_a_and_check_is_na(self) -> None:
        card = _score(STRONG)
        self.assertEqual(card.grade, Grade.A)
        self.assertEqual(_check(card, "CDX-D7-05").status, Status.NOT_APPLICABLE)

    def test_routing_redteam_scores_unchanged(self) -> None:
        vulnerable = _score(REDTEAM / "vulnerable")
        guarded = _score(REDTEAM / "guarded")
        self.assertEqual(_check(vulnerable, "CDX-D7-05").status, Status.UNKNOWN)
        self.assertEqual(_check(guarded, "CDX-D7-05").status, Status.UNKNOWN)
        self.assertEqual(_dimension_score(vulnerable, "D7"), 0.5)
        self.assertEqual(_dimension_score(guarded, "D7"), 1.0)
        self.assertGreater(guarded.overall_score, vulnerable.overall_score)

    def test_unknown_is_excluded_from_runtime_only_grade_denominator(self) -> None:
        card = _score(FIXTURES / "runtime_only")
        result = _check(card, "CDX-D7-05")
        self.assertEqual(result.status, Status.UNKNOWN)
        self.assertIsNone(result.status.score)


class TestCacheCheckRenderersAndDiff(unittest.TestCase):
    def test_unknown_appears_in_every_renderer(self) -> None:
        card = _score(FIXTURES / "runtime_only")
        console = render_console(card)
        payload = to_dict(card)
        html = render_html(card)
        summary = render_github_summary(card)
        sarif = to_sarif(card)
        self.assertIn("[UNKN] CDX-D7-05", console)
        self.assertIn("Unknown checks excluded from the grade", console)
        check = next(
            item
            for dim in payload["dimensions"]
            if dim["id"] == "D7"
            for item in dim["checks"]
            if item["id"] == "CDX-D7-05"
        )
        self.assertEqual(check["status"], "unknown")
        self.assertIn("CDX-D7-05", html)
        self.assertIn("UNKNOWN", html)
        self.assertIn("CDX-D7-05", summary)
        self.assertIn("**Unknown:**", summary)
        rule_ids = [rule["id"] for rule in sarif["runs"][0]["tool"]["driver"]["rules"]]
        self.assertIn("CDX-D7-05", rule_ids)
        results = [item for item in sarif["runs"][0]["results"] if item["ruleId"] == "CDX-D7-05"]
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["level"], "note")
        self.assertEqual(results[0]["properties"]["status"], "unknown")

    def test_fail_appears_in_console_html_and_summary(self) -> None:
        card = _score(FIXTURES / "implicit_hides_writes")
        self.assertEqual(_check(card, "CDX-D7-05").status, Status.FAIL)
        self.assertIn("[FAIL] CDX-D7-05", render_console(card))
        self.assertIn("CDX-D7-05", render_html(card))
        self.assertIn("**`CDX-D7-05`** · FAIL", render_github_summary(card))

    def test_diff_captures_pass_to_fail(self) -> None:
        old = _score(FIXTURES / "explicit_stable_first")
        new = _score(FIXTURES / "implicit_hides_writes")
        diff = diff_scorecards(old, new)
        cache_delta = next(item for item in diff.check_deltas if item.id == "CDX-D7-05")
        self.assertEqual(cache_delta.old_status, Status.PASS)
        self.assertEqual(cache_delta.new_status, Status.FAIL)
        text = render_diff_console(diff)
        payload = json.loads(render_diff_json(diff))
        self.assertIn("CDX-D7-05", text)
        self.assertIn("PASS -> FAIL", text)
        changed = [item["id"] for item in payload["checks_changed"]]
        self.assertIn("CDX-D7-05", changed)


if __name__ == "__main__":
    unittest.main()

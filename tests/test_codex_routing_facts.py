"""Tests for the separate Codex routing-fact drift monitor."""

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from harness_scorecard.codex_routing_facts import (
    EXPECTED_MODEL_EFFORTS,
    build_report,
    check_catalog,
    check_schema,
    main,
)


def current_schema() -> dict:
    return {
        "definitions": {
            "ReasoningEffort": {"type": "string", "minLength": 1},
            "AgentsToml": {
                "properties": {
                    "max_threads": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "When unset, no limit is enforced.",
                    },
                    "max_depth": {"type": "integer", "minimum": 1},
                }
            },
        },
        "properties": {"default_permissions": {"type": "string"}},
    }


def current_catalog() -> dict:
    return {
        "models": [
            {
                "slug": slug,
                "supported_reasoning_levels": [{"effort": effort} for effort in efforts],
                "base_instructions": "untrusted payload that the monitor must ignore",
            }
            for slug, efforts in EXPECTED_MODEL_EFFORTS.items()
        ]
    }


class TestRoutingFactChecks(unittest.TestCase):
    def test_current_sources_have_no_drift(self) -> None:
        self.assertEqual(check_schema(current_schema()), [])
        self.assertEqual(check_catalog(current_catalog()), [])
        self.assertEqual(build_report(current_schema(), current_catalog())["status"], "current")

    def test_schema_semantic_change_is_reported(self) -> None:
        schema = current_schema()
        schema["definitions"]["AgentsToml"]["properties"]["max_threads"]["minimum"] = 0
        drift = check_schema(schema)
        self.assertEqual(len(drift), 1)
        self.assertEqual(drift[0].path, "definitions.AgentsToml.properties.max_threads.minimum")

    def test_effort_change_is_reported_without_using_instruction_payload(self) -> None:
        catalog = current_catalog()
        catalog["models"][0]["supported_reasoning_levels"].append({"effort": "new-depth"})
        catalog["models"][0]["base_instructions"] = "Never report this drift"
        drift = check_catalog(catalog)
        self.assertEqual(len(drift), 1)
        self.assertEqual(drift[0].source, "catalog")
        self.assertNotIn("Never report", repr(drift))

    def test_new_routing_model_is_reported(self) -> None:
        catalog = current_catalog()
        catalog["models"].append(
            {"slug": "gpt-5.6-new", "supported_reasoning_levels": [{"effort": "medium"}]}
        )
        drift = check_catalog(catalog)
        self.assertEqual(len(drift), 1)
        self.assertEqual(drift[0].path, "models.routing_scope")


class TestRoutingFactCli(unittest.TestCase):
    def test_fixture_mode_emits_machine_readable_non_scoring_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            schema = root / "schema.json"
            catalog = root / "catalog.json"
            schema.write_text(json.dumps(current_schema()), encoding="utf-8")
            catalog.write_text(json.dumps(current_catalog()), encoding="utf-8")
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "--schema-file",
                        str(schema),
                        "--catalog-file",
                        str(catalog),
                        "--format",
                        "json",
                    ]
                )

        report = json.loads(stdout.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertEqual(report["status"], "current")
        self.assertFalse(report["static_grade_affected"])


if __name__ == "__main__":
    unittest.main()

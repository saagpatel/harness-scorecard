"""Read-only drift monitor for Codex facts used by the routing rubric.

This module deliberately lives outside the scanner. Live Codex state can warn maintainers that
the static rubric needs review, but it must never change a user's score or count as static proof.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import urllib.request
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

SCHEMA_URL = "https://developers.openai.com/codex/config-schema.json"

EXPECTED_MODEL_EFFORTS: dict[str, tuple[str, ...]] = {
    "gpt-5.4": ("low", "medium", "high", "xhigh"),
    "gpt-5.4-mini": ("low", "medium", "high", "xhigh"),
    "gpt-5.5": ("low", "medium", "high", "xhigh"),
    "gpt-5.6-luna": ("low", "medium", "high", "xhigh", "max"),
    "gpt-5.6-sol": ("low", "medium", "high", "xhigh", "max", "ultra"),
    "gpt-5.6-terra": ("low", "medium", "high", "xhigh", "max", "ultra"),
}

_SCHEMA_EXPECTATIONS: tuple[tuple[tuple[str, ...], Any], ...] = (
    (("definitions", "ReasoningEffort", "type"), "string"),
    (("definitions", "ReasoningEffort", "minLength"), 1),
    (("definitions", "AgentsToml", "properties", "max_threads", "type"), "integer"),
    (("definitions", "AgentsToml", "properties", "max_threads", "minimum"), 1),
    (("definitions", "AgentsToml", "properties", "max_depth", "type"), "integer"),
    (("definitions", "AgentsToml", "properties", "max_depth", "minimum"), 1),
    (("properties", "default_permissions", "type"), "string"),
)


class SourceUnavailableError(RuntimeError):
    """Raised when an upstream fact source cannot be read or parsed."""


@dataclass(frozen=True)
class Drift:
    source: str
    path: str
    expected: Any
    actual: Any


def _at_path(value: Any, path: tuple[str, ...]) -> Any:
    current = value
    for key in path:
        if not isinstance(current, dict) or key not in current:
            return None
        current = current[key]
    return current


def check_schema(schema: Any) -> list[Drift]:
    """Compare the official schema's routing-adjacent contract with known-good facts."""
    if not isinstance(schema, dict):
        return [Drift("schema", "$", "JSON object", type(schema).__name__)]

    drift: list[Drift] = []
    for path, expected in _SCHEMA_EXPECTATIONS:
        actual = _at_path(schema, path)
        if actual != expected:
            drift.append(Drift("schema", ".".join(path), expected, actual))

    max_threads_description = _at_path(
        schema,
        ("definitions", "AgentsToml", "properties", "max_threads", "description"),
    )
    if not isinstance(max_threads_description, str) or "no limit" not in (
        max_threads_description.lower()
    ):
        drift.append(
            Drift(
                "schema",
                "definitions.AgentsToml.properties.max_threads.description",
                "description containing 'no limit'",
                max_threads_description,
            )
        )
    return drift


def _catalog_efforts(catalog: Any) -> dict[str, tuple[str, ...]]:
    if not isinstance(catalog, dict) or not isinstance(catalog.get("models"), list):
        message = "model catalog is missing a models list"
        raise SourceUnavailableError(message)

    efforts: dict[str, tuple[str, ...]] = {}
    for model in catalog["models"]:
        if not isinstance(model, dict) or not isinstance(model.get("slug"), str):
            continue
        raw_levels = model.get("supported_reasoning_levels")
        if not isinstance(raw_levels, list):
            continue
        levels = tuple(
            item["effort"]
            for item in raw_levels
            if isinstance(item, dict) and isinstance(item.get("effort"), str)
        )
        efforts[model["slug"]] = levels
    return efforts


def check_catalog(catalog: Any) -> list[Drift]:
    """Compare installed model metadata without retaining prompt or instruction payloads."""
    observed = _catalog_efforts(catalog)
    drift: list[Drift] = []

    for slug, expected in EXPECTED_MODEL_EFFORTS.items():
        actual = observed.get(slug)
        if actual != expected:
            drift.append(Drift("catalog", f"models.{slug}.efforts", expected, actual))

    new_routing_models = sorted(
        slug
        for slug in observed
        if slug.startswith(("gpt-5.4", "gpt-5.5", "gpt-5.6")) and slug not in EXPECTED_MODEL_EFFORTS
    )
    if new_routing_models:
        drift.append(
            Drift(
                "catalog",
                "models.routing_scope",
                sorted(EXPECTED_MODEL_EFFORTS),
                sorted([*EXPECTED_MODEL_EFFORTS, *new_routing_models]),
            )
        )
    return drift


def _load_json_file(path: Path, label: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        message = f"cannot read {label} from {path}: {exc}"
        raise SourceUnavailableError(message) from exc


def _load_schema(path: Path | None) -> Any:
    if path is not None:
        return _load_json_file(path, "schema")
    request = urllib.request.Request(  # noqa: S310
        SCHEMA_URL, headers={"User-Agent": "harness-scorecard"}
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:  # noqa: S310
            return json.load(response)
    except (OSError, json.JSONDecodeError) as exc:
        message = f"cannot read official schema: {exc}"
        raise SourceUnavailableError(message) from exc


def _load_catalog(path: Path | None) -> Any:
    if path is not None:
        return _load_json_file(path, "model catalog")
    executable = shutil.which("codex")
    if executable is None:
        message = "codex executable is not available on PATH"
        raise SourceUnavailableError(message)
    try:
        result = subprocess.run(  # noqa: S603
            [executable, "debug", "models"],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
        return json.loads(result.stdout)
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
        message = f"cannot read installed model catalog: {exc}"
        raise SourceUnavailableError(message) from exc


def build_report(schema: Any, catalog: Any) -> dict[str, Any]:
    drift = [*check_schema(schema), *check_catalog(catalog)]
    return {
        "status": "drift" if drift else "current",
        "static_grade_affected": False,
        "drift": [asdict(item) for item in drift],
    }


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Check Codex routing facts without changing harness-scorecard grades."
    )
    parser.add_argument("--schema-file", type=Path, help="Use a schema fixture instead of HTTPS.")
    parser.add_argument(
        "--catalog-file",
        type=Path,
        help="Use a model-catalog fixture instead of `codex debug models`.",
    )
    parser.add_argument("--format", choices=("console", "json"), default="console")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        report = build_report(_load_schema(args.schema_file), _load_catalog(args.catalog_file))
    except SourceUnavailableError as exc:
        if args.format == "json":
            sys.stdout.write(
                json.dumps(
                    {
                        "status": "unavailable",
                        "static_grade_affected": False,
                        "error": str(exc),
                    },
                    sort_keys=True,
                )
                + "\n"
            )
        else:
            sys.stderr.write(f"UNAVAILABLE: {exc}\n")
        return 2

    if args.format == "json":
        sys.stdout.write(json.dumps(report, sort_keys=True) + "\n")
    elif report["status"] == "current":
        sys.stdout.write(
            "CURRENT: official schema and installed Codex routing facts match expectations.\n"
            "Static grade affected: no\n"
        )
    else:
        sys.stdout.write(
            "DRIFT: Codex routing facts need maintainer review.\nStatic grade affected: no\n"
        )
        for item in report["drift"]:
            sys.stdout.write(
                f"- {item['source']} {item['path']}: "
                f"expected {item['expected']!r}, observed {item['actual']!r}\n"
            )
    return 1 if report["status"] == "drift" else 0


if __name__ == "__main__":
    raise SystemExit(main())

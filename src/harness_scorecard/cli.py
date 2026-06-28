"""Command-line entry point: ``harness-scorecard scan <path>``.

Exit codes mirror a linter contract: 0 = grade meets ``--min-grade`` (default B),
1 = grade below the bar, 2 = invalid input (no harness found).
"""

from __future__ import annotations

import argparse
import sys
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

from harness_scorecard.dispatch import HARNESS_TYPES, select_adapter
from harness_scorecard.htmlreport import render_html
from harness_scorecard.models import RUBRIC_VERSION, Grade, grade_rank
from harness_scorecard.redaction import redact_text
from harness_scorecard.report import render_console, render_json
from harness_scorecard.sarif import render_sarif
from harness_scorecard.scoring import score_harness


def _version_string() -> str:
    """Report the installed package version alongside the rubric version they grade against."""
    try:
        package = version("harness-scorecard")
    except PackageNotFoundError:  # running from a source tree without an install
        package = "0+source"
    return f"harness-scorecard {package} (rubric {RUBRIC_VERSION})"


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="harness-scorecard",
        description="Grade a coding-agent harness configuration against the red-team rubric.",
    )
    parser.add_argument("--version", action="version", version=_version_string())
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Scan and grade a harness directory.")
    scan.add_argument("path", help="Path to the harness directory (e.g. ~/.claude or ~/.codex).")
    scan.add_argument(
        "--type",
        dest="harness_type",
        choices=list(HARNESS_TYPES),
        default="auto",
        help="Harness type (default: auto-detect Claude Code vs Codex).",
    )
    scan.add_argument(
        "--format",
        choices=["console", "json"],
        default="console",
        help="Output format for stdout (default: console).",
    )
    scan.add_argument(
        "--json",
        dest="json_out",
        metavar="FILE",
        help="Also write a JSON report to FILE.",
    )
    scan.add_argument(
        "--html",
        dest="html_out",
        metavar="FILE",
        help="Also write a self-contained HTML scorecard to FILE.",
    )
    scan.add_argument(
        "--sarif",
        dest="sarif_out",
        metavar="FILE",
        help="Also write a SARIF 2.1.0 report to FILE (for CI / code scanning).",
    )
    scan.add_argument(
        "--min-grade",
        choices=[grade.value for grade in Grade],
        default=Grade.B.value,
        help="Exit non-zero when the harness grades below this band (default: B).",
    )
    return parser


def _run_scan(args: argparse.Namespace) -> int:
    root = Path(args.path).expanduser()
    try:
        config, checks = select_adapter(root, args.harness_type)
    except FileNotFoundError as exc:
        print(f"error: {redact_text(str(exc))}", file=sys.stderr)
        return 2

    card = score_harness(config, checks)
    output = render_json(card) if args.format == "json" else render_console(card)
    print(output)

    if args.json_out:
        Path(args.json_out).expanduser().write_text(render_json(card), encoding="utf-8")
    if args.html_out:
        Path(args.html_out).expanduser().write_text(render_html(card), encoding="utf-8")
    if args.sarif_out:
        Path(args.sarif_out).expanduser().write_text(render_sarif(card), encoding="utf-8")

    return 0 if grade_rank(card.grade) >= grade_rank(Grade(args.min_grade)) else 1


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        return _run_scan(args)
    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

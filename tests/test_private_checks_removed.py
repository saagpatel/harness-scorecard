"""Regressions for private machine-specific checks removed from the public package."""

import contextlib
import io
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from harness_scorecard.checks import ALL_CHECKS
from harness_scorecard.checks_codex import CODEX_CHECKS
from harness_scorecard.cli import main
from harness_scorecard.discovery_codex import load_codex_harness
from harness_scorecard.sarif import to_sarif
from harness_scorecard.scoring import score_harness

RETIRED_IDS = {"HS-D10-03", "CDX-D7-03", "CDX-D7-04", "CDX-D7-05"}
REPOSITORY = Path(__file__).resolve().parents[1]


class TestRetiredChecks(unittest.TestCase):
    def test_retired_ids_are_not_registered(self) -> None:
        registered = {check.id for check in (*ALL_CHECKS, *CODEX_CHECKS)}
        self.assertTrue(RETIRED_IDS.isdisjoint(registered))
        card = score_harness(
            load_codex_harness(REPOSITORY / "tests/fixtures/codex_strong"), CODEX_CHECKS
        )
        sarif_rule_ids = {
            rule["id"] for rule in to_sarif(card)["runs"][0]["tool"]["driver"]["rules"]
        }
        self.assertTrue(RETIRED_IDS.isdisjoint(sarif_rule_ids))

    def test_source_has_no_bridge_database_reference(self) -> None:
        for path in (REPOSITORY / "src").rglob("*"):
            if path.is_file() and path.suffix == ".py":
                with self.subTest(path=path.relative_to(REPOSITORY)):
                    source = path.read_text(encoding="utf-8").lower()
                    self.assertNotIn("bridge-db", source)
                    self.assertNotIn("bridge.db", source)

    def test_scan_with_empty_home_does_not_write_outside_harness(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            harness = root / "harness"
            home = root / "empty-home"
            shutil.copytree(REPOSITORY / "tests/fixtures/strong_harness", harness)
            home.mkdir()

            def snapshot() -> dict[str, tuple[bool, int, int, bytes]]:
                return {
                    str(path.relative_to(root)): (
                        path.is_dir(),
                        path.stat().st_size,
                        path.stat().st_mtime_ns,
                        path.read_bytes() if path.is_file() else b"",
                    )
                    for path in root.rglob("*")
                }

            before = snapshot()
            with (
                patch.dict("os.environ", {"HOME": str(home)}),
                contextlib.redirect_stdout(io.StringIO()),
                contextlib.redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(main(["scan", str(harness), "--min-grade", "A"]), 0)
            self.assertEqual(snapshot(), before)
            self.assertEqual(list(home.iterdir()), [])


if __name__ == "__main__":
    unittest.main()

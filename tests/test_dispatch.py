"""Harness-type detection and adapter selection."""

import tempfile
import unittest
from pathlib import Path

from harness_scorecard.checks import ALL_CHECKS
from harness_scorecard.checks_codex import CODEX_CHECKS
from harness_scorecard.discovery import HARNESS_TYPE_CLAUDE_CODE
from harness_scorecard.discovery_codex import HARNESS_TYPE_CODEX
from harness_scorecard.dispatch import detect_harness_type, select_adapter

FIXTURES = Path(__file__).parent / "fixtures"


class TestDetect(unittest.TestCase):
    def test_detects_claude_code(self) -> None:
        self.assertEqual(detect_harness_type(FIXTURES / "strong_harness"), HARNESS_TYPE_CLAUDE_CODE)

    def test_detects_codex(self) -> None:
        self.assertEqual(detect_harness_type(FIXTURES / "codex_strong"), HARNESS_TYPE_CODEX)

    def test_unrecognized_returns_none(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.assertIsNone(detect_harness_type(Path(tmp)))


class TestSelectAdapter(unittest.TestCase):
    def test_auto_selects_codex_checkset(self) -> None:
        config, checks = select_adapter(FIXTURES / "codex_strong")
        self.assertEqual(config.harness_type, HARNESS_TYPE_CODEX)
        self.assertIs(checks, CODEX_CHECKS)

    def test_auto_selects_claude_checkset(self) -> None:
        config, checks = select_adapter(FIXTURES / "strong_harness")
        self.assertEqual(config.harness_type, HARNESS_TYPE_CLAUDE_CODE)
        self.assertIs(checks, ALL_CHECKS)

    def test_explicit_type_overrides_detection(self) -> None:
        config, checks = select_adapter(FIXTURES / "codex_strong", HARNESS_TYPE_CODEX)
        self.assertEqual(config.harness_type, HARNESS_TYPE_CODEX)
        self.assertIs(checks, CODEX_CHECKS)

    def test_no_harness_raises(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, self.assertRaises(FileNotFoundError):
            select_adapter(Path(tmp))


if __name__ == "__main__":
    unittest.main()

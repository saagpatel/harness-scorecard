"""Malformed files must not be graded as empty, safe configurations."""

import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from harness_scorecard import parsing
from harness_scorecard.cli import main
from harness_scorecard.discovery_codex import load_codex_harness


class TestInputErrors(unittest.TestCase):
    def test_absent_json_stays_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(parsing.read_json(Path(tmp) / "missing.json"), {})

    def assert_input_error(self, path, reader):
        with self.assertRaises(ValueError) as caught:
            reader(path)
        self.assertEqual(type(caught.exception).__name__, "HarnessInputError")
        self.assertIn(path.name, str(caught.exception))

    def test_invalid_json_and_non_object_roots(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "settings.json"
            for content in ('{"hooks":', "[]", "null", "42"):
                with self.subTest(content=content):
                    path.write_text(content)
                    self.assert_input_error(path, parsing.read_json)
                    out, err = io.StringIO(), io.StringIO()
                    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                        self.assertEqual(main(["scan", tmp]), 2)
                    self.assertEqual(out.getvalue(), "")
                    self.assertIn("error:", err.getvalue())
                    self.assertIn("settings.json", err.getvalue())

    def test_unreadable_and_undecodable_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "settings.json"
            path.write_bytes(b"\xff")
            self.assert_input_error(path, parsing.read_json)
            path.write_text("{}")
            path.chmod(0)
            try:
                self.assert_input_error(path, parsing.read_json)
                with (
                    contextlib.redirect_stdout(io.StringIO()),
                    contextlib.redirect_stderr(io.StringIO()),
                ):
                    self.assertEqual(main(["scan", tmp]), 2)
            finally:
                path.chmod(0o600)

    def test_all_json_config_names_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name, marker in (
                ("settings.local.json", "settings.json"),
                ("hooks.json", "config.toml"),
            ):
                with self.subTest(name=name):
                    (root / marker).write_text("{}" if marker.endswith("json") else "")
                    (root / name).write_text("[]")
                    with (
                        contextlib.redirect_stdout(io.StringIO()),
                        contextlib.redirect_stderr(io.StringIO()),
                    ):
                        self.assertEqual(main(["scan", tmp]), 2)
                    (root / name).unlink()
                    (root / marker).unlink()

    def test_base_toml_errors_raise_but_profile_caveats_remain(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "config.toml"
            for content in (b"invalid = =", b"\xff"):
                path.write_bytes(content)
                self.assert_input_error(path, lambda _: load_codex_harness(root))
                with (
                    contextlib.redirect_stdout(io.StringIO()),
                    contextlib.redirect_stderr(io.StringIO()),
                ):
                    self.assertEqual(main(["scan", tmp]), 2)
            path.write_text("")
            with patch.object(Path, "open", side_effect=PermissionError("denied")):
                self.assert_input_error(path, lambda _: load_codex_harness(root))
            (root / "review.config.toml").write_text("invalid = =")
            self.assertTrue(any(route.issues for route in load_codex_harness(root).routing_routes))

    def test_bad_group_hooks_are_skipped(self):
        for value in (None, "command", {}):
            with self.subTest(value=value):
                hooks = {
                    "PreToolUse": [
                        {"hooks": value},
                        {"matcher": "Bash", "hooks": [{"command": "guard"}]},
                    ]
                }
                self.assertEqual([h.command for h in parsing.flatten_hooks(hooks)], ["guard"])

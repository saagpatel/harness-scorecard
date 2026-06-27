"""Discovery degrades gracefully on malformed settings instead of crashing.

Regression coverage for review findings F1-F4: wrong-typed JSON values (null/string/array
where a dict/list is expected) must yield empty inventories, never an exception or a
char-iterated deny list that silently mis-grades a correct harness.
"""

import json
import tempfile
import unittest
from pathlib import Path

from harness_scorecard.discovery import load_harness


class MalformedSettings(unittest.TestCase):
    def _load(self, payload: dict):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "settings.json").write_text(json.dumps(payload), encoding="utf-8")
            return load_harness(tmp)

    def test_env_null_does_not_crash(self):
        self.assertEqual(self._load({"env": None}).env, {})

    def test_env_as_array_does_not_crash(self):
        self.assertEqual(self._load({"env": ["x"]}).env, {})

    def test_permissions_as_string_does_not_crash(self):
        config = self._load({"permissions": "allow_all"})
        self.assertEqual(config.deny, [])
        self.assertEqual(config.default_mode, "default")

    def test_deny_as_string_is_not_char_iterated(self):
        # The dangerous one (F3): a string deny must NOT become ['R','e','a','d', ...]
        # and silently report zero coverage on a correct harness.
        config = self._load({"permissions": {"deny": "Read(~/.ssh/**)"}})
        self.assertEqual(config.deny, [])
        self.assertNotIn("R", config.deny)

    def test_allow_as_string_is_not_char_iterated(self):
        self.assertEqual(self._load({"permissions": {"allow": "Read"}}).allow, [])

    def test_hooks_non_dict_does_not_crash(self):
        self.assertEqual(self._load({"hooks": "nope"}).hooks, [])

    def test_automode_non_dict_does_not_crash(self):
        self.assertEqual(self._load({"autoMode": "nope"}).hard_deny, [])

    def test_hard_deny_as_string_splits_lines(self):
        config = self._load({"autoMode": {"hard_deny": "rule one\nrule two"}})
        self.assertEqual(config.hard_deny, ["rule one", "rule two"])

    def test_local_settings_string_merge_does_not_crash(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "settings.json").write_text(
                json.dumps({"permissions": {"deny": ["Read(~/.ssh/**)"]}}), encoding="utf-8"
            )
            (Path(tmp) / "settings.local.json").write_text(
                json.dumps({"permissions": "broken"}), encoding="utf-8"
            )
            config = load_harness(tmp)
            self.assertIn("Read(~/.ssh/**)", config.deny)


if __name__ == "__main__":
    unittest.main()

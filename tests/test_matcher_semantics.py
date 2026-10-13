"""Both hook-query APIs use case-sensitive regex search."""

import unittest

from harness_scorecard.parsing import matcher_covers, matcher_matches_tool


class TestMatcherSemantics(unittest.TestCase):
    def test_matcher_apis_agree(self):
        for matcher, tool, expected in (
            ("^NotBash$", "Bash", False),
            ("NotebookEdit", "Edit", False),
            ("bash", "Bash", False),
            ("Edit|Write", "Edit", True),
            ("Edit|Write", "Write", True),
            ("*", "Bash", True),
            ("", "Edit", True),
            ("[", "[", False),
            ("Bash[", "Bash[", False),
            ("ash", "Bash", True),
        ):
            with self.subTest(matcher=matcher, tool=tool):
                self.assertEqual(matcher_covers(matcher, tool), expected)
                self.assertEqual(matcher_matches_tool(matcher, tool), expected)
        self.assertFalse(matcher_covers("[", None))
        self.assertTrue(matcher_covers("Bash", None))
        self.assertTrue(matcher_covers("*", None))

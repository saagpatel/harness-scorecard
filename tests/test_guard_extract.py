"""Guard-body deny-set extraction (synthetic fixtures only — never real operator guards)."""

import unittest

from harness_scorecard.guard_extract import (
    BlockKind,
    DenyBlock,
    extract_deny_blocks,
    split_and_clauses,
    trace_command_vars,
)

# Every fixture is synthetic, written for one idiom; real guard patterns are operator
# security posture and must never enter this repo.

LITERAL_GUARD = """#!/bin/bash
INPUT=$(cat)
CMD=$(echo "$INPUT" | jq -r '.tool_input.command // empty')
if echo "$CMD" | grep -qE 'git push.*(main|master)'; then
  echo '{"hookSpecificOutput":{"permissionDecision":"deny"}}'
  exit 0
fi
"""

NEGATED_GUARD = """#!/bin/bash
CMD=$(cat | jq -r '.tool_input.command // empty')
if echo "$CMD" | grep -q 'DELETE FROM' && ! echo "$CMD" | grep -qi 'WHERE'; then
  deny "no unbounded deletes"
fi
"""

RESOLVED_PARAM_GUARD = """#!/bin/bash
CMD=$(cat | jq -r '.tool_input.command // empty')
PAT='rm -rf'
if echo "$CMD" | grep -qE "${PAT} +/"; then
  exit 2
fi
"""

UNRESOLVED_PARAM_GUARD = """#!/bin/bash
CMD=$(cat | jq -r '.tool_input.command // empty')
DYNAMIC=$(build_pattern)
if echo "$CMD" | grep -qE "sudo ${DYNAMIC}"; then
  exit 2
fi
"""

LIVE_STATE_GUARD = """#!/bin/bash
CMD=$(cat | jq -r '.tool_input.command // empty')
if [ "$(git branch --show-current)" = "main" ] && echo "$CMD" | grep -q 'push --force'; then
  exit 2
fi
"""

NO_MATCHER_GUARD = """#!/bin/bash
CMD=$(cat | jq -r '.tool_input.command // empty')
if [ ${#CMD} -gt 128 ]; then
  exit 2
fi
"""

UNTRACED_GUARD = """#!/bin/bash
CMD=$(cat | jq -r '.tool_input.command // empty')
OTHER="unrelated"
if echo "$OTHER" | grep -q 'curl'; then
  exit 2
fi
"""

REGEX_AMPERSAND_GUARD = """#!/bin/bash
CMD=$(cat | jq -r '.tool_input.command // empty')
if echo "$CMD" | grep -qE 'foo && bar' && ! echo "$CMD" | grep -q 'safe'; then
  exit 2
fi
"""

ELIF_CHAIN_GUARD = """#!/bin/bash
CMD=$(cat | jq -r '.tool_input.command // empty')
if echo "$CMD" | grep -qi 'drop table'; then
  deny "no drops"
elif echo "$CMD" | grep -qi 'truncate'; then
  deny "no truncates"
fi
"""

TAINT_CHAIN_GUARD = """#!/bin/bash
CMD=$(cat | jq -r '.tool_input.command // empty')
NORM=$(printf '%s' "$CMD" | tr '[:upper:]' '[:lower:]')
if echo "$NORM" | grep -q 'sudo rm'; then
  exit 2
fi
"""

# --- review-round regressions: each fixture reproduced a false-enforced path ----------

PREFIX_COLLISION_GUARD = """#!/bin/bash
CMD=$(cat | jq -r '.tool_input.command // empty')
PAT='oops'
PATTERN='drop table'
if echo "$CMD" | grep -qE "$PATTERN"; then
  exit 2
fi
"""

UNTRACED_SIDE_CONDITION_GUARD = """#!/bin/bash
CMD=$(cat | jq -r '.tool_input.command // empty')
UNRELATED='static text'
if echo "$UNRELATED" | grep -q 'super-secret-marker' && [ -n "$CMD" ]; then
  exit 2
fi
"""

PREFIX_TAINT_GUARD = """#!/bin/bash
CMD=$(cat | jq -r '.tool_input.command // empty')
CMD_DISPLAY="redacted"
if echo "$CMD_DISPLAY" | grep -q 'literal-secret'; then
  exit 2
fi
"""

ECHOED_EXIT_GUARD = """#!/bin/bash
CMD=$(cat | jq -r '.tool_input.command // empty')
if echo "$CMD" | grep -q 'rm -rf /'; then
  echo "tip: if you really need this, exit 2 from a subshell first"
fi
"""

COMMENTED_EXIT_GUARD = """#!/bin/bash
CMD=$(cat | jq -r '.tool_input.command // empty')
if echo "$CMD" | grep -q 'rm -rf /'; then
  # we used to exit 2 here; now we just log
  log_only "$CMD"
fi
"""

ALLOW_DECISION_GUARD = """#!/bin/bash
CMD=$(cat | jq -r '.tool_input.command // empty')
if echo "$CMD" | grep -q 'safe-tool'; then
  echo '{"hookSpecificOutput":{"permissionDecision":"allow"}}'
fi
"""

INVERTED_GREP_GUARD = """#!/bin/bash
CMD=$(cat | jq -r '.tool_input.command // empty')
if echo "$CMD" | grep -qvE 'known-safe-uuid-[0-9a-f]+$'; then
  exit 2
fi
"""


def blocks(text: str) -> list[DenyBlock]:
    return extract_deny_blocks(text, "fixture.sh")


class TestPatternExtraction(unittest.TestCase):
    def test_literal_grep_with_inline_json_deny(self):
        [block] = blocks(LITERAL_GUARD)
        self.assertIs(block.kind, BlockKind.PATTERN)
        self.assertEqual(block.patterns, ["git push.*(main|master)"])
        self.assertTrue(block.is_extracted)

    def test_negated_clause_becomes_unless_exception(self):
        [block] = blocks(NEGATED_GUARD)
        self.assertIs(block.kind, BlockKind.PATTERN)
        self.assertEqual(block.patterns, ["DELETE FROM"])
        self.assertEqual(block.exceptions, ["WHERE"])

    def test_static_variable_resolves_to_pattern(self):
        [block] = blocks(RESOLVED_PARAM_GUARD)
        self.assertIs(block.kind, BlockKind.PATTERN)
        self.assertEqual(block.patterns, ["rm -rf +/"])
        self.assertEqual(block.unresolved, [])

    def test_dynamic_variable_stays_parameterized_with_name_listed(self):
        [block] = blocks(UNRESOLVED_PARAM_GUARD)
        self.assertIs(block.kind, BlockKind.PARAMETERIZED)
        self.assertEqual(block.unresolved, ["DYNAMIC"])
        self.assertTrue(block.is_extracted)

    def test_elif_chain_yields_one_block_per_arm(self):
        found = blocks(ELIF_CHAIN_GUARD)
        self.assertEqual(len(found), 2)
        self.assertEqual([b.patterns for b in found], [["drop table"], ["truncate"]])

    def test_taint_traces_through_derived_variables(self):
        [block] = blocks(TAINT_CHAIN_GUARD)
        self.assertIs(block.kind, BlockKind.PATTERN)
        self.assertEqual(block.patterns, ["sudo rm"])


class TestLogicClassification(unittest.TestCase):
    """Logic blocks are honest flags: never extracted, never creditable."""

    def test_live_state_condition_is_logic(self):
        [block] = blocks(LIVE_STATE_GUARD)
        self.assertIs(block.kind, BlockKind.LOGIC)
        self.assertIn("live state", block.reason)
        self.assertEqual(block.patterns, [])

    def test_arithmetic_gate_without_matcher_is_logic(self):
        [block] = blocks(NO_MATCHER_GUARD)
        self.assertIs(block.kind, BlockKind.LOGIC)
        self.assertIn("no literal matcher", block.reason)

    def test_matcher_on_untraced_variable_is_logic(self):
        [block] = blocks(UNTRACED_GUARD)
        self.assertIs(block.kind, BlockKind.LOGIC)
        self.assertIn("not traced", block.reason)

    def test_logic_block_cannot_carry_patterns(self):
        # The zero-false-enforced invariant is structural, not review-based.
        with self.assertRaises(ValueError):
            DenyBlock("g.sh", 1, BlockKind.LOGIC, patterns=["oops"])
        with self.assertRaises(ValueError):
            DenyBlock("g.sh", 1, BlockKind.LOGIC, exceptions=["oops"])


class TestFalseEnforcedRegressions(unittest.TestCase):
    """Each case reproduced a path where extraction fabricated or mis-credited a deny
    set (2026-07 review round). All must stay conservative forever."""

    def test_variable_prefix_collision_does_not_corrupt_pattern(self):
        [block] = blocks(PREFIX_COLLISION_GUARD)
        self.assertIs(block.kind, BlockKind.PATTERN)
        self.assertEqual(block.patterns, ["drop table"])

    def test_matcher_on_untraced_var_with_traced_side_condition_is_logic(self):
        [block] = blocks(UNTRACED_SIDE_CONDITION_GUARD)
        self.assertIs(block.kind, BlockKind.LOGIC)
        self.assertIn("not traced", block.reason)

    def test_variable_name_prefix_does_not_taint(self):
        # $CMD_DISPLAY is not a reference to $CMD; the grep target is untraced.
        [block] = blocks(PREFIX_TAINT_GUARD)
        self.assertIs(block.kind, BlockKind.LOGIC)
        self.assertIn("not traced", block.reason)

    def test_exit_two_inside_echoed_string_is_not_a_deny_body(self):
        self.assertEqual(blocks(ECHOED_EXIT_GUARD), [])

    def test_exit_two_inside_comment_is_not_a_deny_body(self):
        self.assertEqual(blocks(COMMENTED_EXIT_GUARD), [])

    def test_allow_decision_json_is_not_a_deny_body(self):
        self.assertEqual(blocks(ALLOW_DECISION_GUARD), [])

    def test_inverted_grep_is_logic_not_a_deny_literal(self):
        # grep -v extracts the ALLOWED value; crediting it as a deny set is false backing.
        [block] = blocks(INVERTED_GREP_GUARD)
        self.assertIs(block.kind, BlockKind.LOGIC)
        self.assertIn("inverted", block.reason)


class TestQuoteAwareSplit(unittest.TestCase):
    """The spike's one conservative miss: '&&' inside a regex literal must not split."""

    def test_ampersands_inside_quotes_survive(self):
        clauses = split_and_clauses(
            "echo \"$CMD\" | grep -qE 'foo && bar' && ! echo \"$CMD\" | grep -q 'safe'"
        )
        self.assertEqual(len(clauses), 2)
        self.assertIn("'foo && bar'", clauses[0])

    def test_regex_with_ampersand_extracts_as_pattern(self):
        [block] = blocks(REGEX_AMPERSAND_GUARD)
        self.assertIs(block.kind, BlockKind.PATTERN)
        self.assertEqual(block.patterns, ["foo && bar"])
        self.assertEqual(block.exceptions, ["safe"])

    def test_plain_split_still_works(self):
        self.assertEqual(split_and_clauses("a && b && c"), ["a", "b", "c"])

    def test_double_backslash_before_closing_quote_still_closes_the_string(self):
        # A literal backslash at the end of a string is not an escaped quote; the split
        # after it must still happen (one-char lookback merged these two clauses).
        clauses = split_and_clauses('echo "a\\\\" && ! echo "safe"')
        self.assertEqual(len(clauses), 2)


class TestTaintTrace(unittest.TestCase):
    def test_stdin_root_and_transitive_assignments_are_traced(self):
        traced = trace_command_vars(TAINT_CHAIN_GUARD)
        self.assertIn("CMD", traced)
        self.assertIn("NORM", traced)

    def test_unrelated_variables_are_not_traced(self):
        self.assertNotIn("OTHER", trace_command_vars(UNTRACED_GUARD))


if __name__ == "__main__":
    unittest.main()

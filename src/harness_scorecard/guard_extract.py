"""Static deny-set extraction from shell guard bodies.

Feeds the claims audit (see ``harness_scorecard.claims``): a PreToolUse-style shell guard
is decomposed into its ``if``/``elif`` arms, and every arm that blocks (inline
``permissionDecision`` JSON, a sourced ``deny`` helper call, or ``exit 2``) is classified:

- ``pattern`` — the deny is gated on a fully literal matcher over the tool command.
- ``parameterized`` — the matcher is assembled from in-file variables; statically
  resolvable ones are substituted, the rest listed as unresolved. Still extracted.
- ``logic`` — the deny decision depends on live state (subprocess over git/fs state,
  computed comparisons) or the matcher cannot be traced to the tool command. Never
  extracted: a logic block carries no patterns (``DenyBlock.__post_init__`` enforces
  this structurally), so downstream matching can credit it at most as a manual-review
  candidate — the zero-false-enforced invariant.

Known conservative limits (a missed block is absent from the coverage counts, never
mis-credited): ``case``-statement denies, nested ``if`` bodies, and guards written in
non-shell languages are not parsed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import StrEnum


class BlockKind(StrEnum):
    """How confidently a deny arm's matcher was recovered."""

    PATTERN = "pattern"
    PARAMETERIZED = "parameterized"
    LOGIC = "logic"


@dataclass(slots=True)
class DenyBlock:
    """One blocking arm of a guard script."""

    guard: str
    line: int
    kind: BlockKind
    patterns: list[str] = field(default_factory=list)
    exceptions: list[str] = field(default_factory=list)
    unresolved: list[str] = field(default_factory=list)
    reason: str = ""

    def __post_init__(self) -> None:
        # The zero-false-enforced invariant: a logic-classified block must never carry
        # matcher text, so no downstream path can present it as an extracted deny set.
        if self.kind is BlockKind.LOGIC and (self.patterns or self.exceptions):
            msg = "a logic-classified DenyBlock cannot carry patterns or exceptions"
            raise ValueError(msg)

    @property
    def is_extracted(self) -> bool:
        return self.kind is not BlockKind.LOGIC


# Variable names conventionally bound to the tool command; the taint trace below extends
# this with anything assigned from the stdin JSON's ``tool_input.command`` and onward.
_COMMAND_VARS_SEED = frozenset({"COMMAND", "CMD", "INPUT", "TOOL_INPUT", "FULL_CMD"})

_GREP_PATTERN_RE = re.compile(r"grep\s+(?:-[a-zA-Z]*q[a-zA-Z]*\s+)+(?:-e\s+)?(['\"])(.+?)\1")
# grep with invert-match anywhere in its flags: the literal is an allow-list, not a deny
# target, so extracting it as a deny pattern would be a false backing.
_INVERTED_GREP_RE = re.compile(r"grep\s+(?:-[a-zA-Z]+\s+)*-[a-zA-Z]*v")
# Deny surfaces. A deny/exit statement must sit in an executable position of the arm body
# (start of line or after ;, &, |, {, (, then) with strings and comments stripped first —
# an `exit 2` inside an echoed message is not a deny. The permissionDecision JSON lives
# *inside* a string by design, so it is checked on the raw body, and only with value
# "deny" (an echoed "allow" decision is not a deny either).
_SHELL_STRING_RE = re.compile(r"'[^']*'|\"(?:\\.|[^\"\\])*\"")
_COMMENT_RE = re.compile(r"#[^\n]*")
_DENY_STMT_RE = re.compile(r"(?m)(?:^|[;&|{(]|\bthen\b)\s*(?:deny\b|exit\s+2\b)")
_PERMISSION_DENY_RE = re.compile(r'permissionDecision\\?"?\s*:\s*\\?"?deny')
# Live-state smells: subprocess output over git/fs state feeding the deny decision.
_LIVE_STATE_RE = re.compile(
    r"\$\(\s*git\b|\brev-parse\b|\bbranch --show-current\b|\bconfig --get\b|\bgit -C\b.*\bdiff\b"
)
_VAR_REF_RE = re.compile(r"\$\{?([A-Z_][A-Z0-9_]*)\}?")
_ASSIGN_RE = re.compile(r"^([A-Z_][A-Z0-9_]*)=(.*)$", re.MULTILINE)
_STATIC_ASSIGN_RE = re.compile(r"^([A-Z_][A-Z0-9_]*)=(['\"])(.*)\2\s*$", re.MULTILINE)
_BRANCH_HEAD_RE = re.compile(r"\s*(?:el)?if\b")
_NEGATED_CLAUSE_RE = re.compile(r"!\s*(?:echo|printf|\{)")


def trace_command_vars(text: str) -> set[str]:
    """Names tainted by the tool command: the stdin-JSON root plus transitive assignments."""
    known = set(_COMMAND_VARS_SEED)
    root = re.search(r"^([A-Z_][A-Z0-9_]*)=.*tool_input\.command", text, re.MULTILINE)
    if root:
        known.add(root.group(1))
    changed = True
    while changed:
        changed = False
        for match in _ASSIGN_RE.finditer(text):
            var, rhs = match.group(1), match.group(2)
            if var not in known and any(_refs_var(rhs, name) for name in known):
                known.add(var)
                changed = True
    return known


def _refs_var(text: str, name: str) -> bool:
    # Exact-name references only: `$CMD` must not count as a reference to `CMD` when the
    # text actually says `$CMD_DISPLAY` (that substring slip tainted dead variables).
    return bool(re.search(r"\$(?:\{" + name + r"\}|" + name + r"(?![A-Za-z0-9_]))", text))


def _has_deny_body(body: str) -> bool:
    stripped = _COMMENT_RE.sub(" ", _SHELL_STRING_RE.sub(" ", body))
    return bool(_DENY_STMT_RE.search(stripped) or _PERMISSION_DENY_RE.search(body))


def collect_static_assignments(text: str) -> dict[str, str]:
    """Map ``VAR -> literal`` for simple quoted assignments (no command substitution)."""
    statics: dict[str, str] = {}
    for match in _STATIC_ASSIGN_RE.finditer(text):
        var, _, value = match.groups()
        if "$(" not in value and "`" not in value:
            statics[var] = value
    return statics


def resolve_pattern(raw: str, statics: dict[str, str]) -> tuple[str, list[str]]:
    """Substitute statically-known variables into a matcher; list what stays unresolved.

    Substitution is name-boundary-aware: resolving ``$PAT`` must not eat the prefix of a
    ``$PATTERN`` reference (a plain substring replace fabricated corrupted patterns).
    """
    resolved = raw
    for _ in range(4):  # chase short assignment chains, bounded
        before = resolved
        for var, value in statics.items():
            resolved = re.sub(
                r"\$(?:\{" + var + r"\}|" + var + r"(?![A-Za-z0-9_]))",
                lambda _match, v=value: v,
                resolved,
            )
        if resolved == before:
            break
    return resolved, sorted(set(_VAR_REF_RE.findall(resolved)))


def split_and_clauses(condition: str) -> list[str]:
    """Split a shell condition on ``&&`` — but never inside a quoted string.

    The naive split was the spike's one conservative miss: an ``&&`` inside a regex
    literal cut the matcher in half and demoted the block to logic.
    """
    clauses: list[str] = []
    buf: list[str] = []
    quote = ""
    i = 0
    while i < len(condition):
        char = condition[i]
        if quote == '"' and char == "\\" and i + 1 < len(condition):
            # Consume the escaped character whole, so `\\` before a closing quote is a
            # literal backslash, not an escaped quote (one-char lookback got this wrong).
            buf.append(char)
            buf.append(condition[i + 1])
            i += 2
            continue
        if quote:
            if char == quote:
                quote = ""
            buf.append(char)
        elif char in "'\"":
            quote = char
            buf.append(char)
        elif condition.startswith("&&", i):
            clauses.append("".join(buf))
            buf = []
            i += 1
        else:
            buf.append(char)
        i += 1
    clauses.append("".join(buf))
    return [clause for clause in (c.strip() for c in clauses) if clause]


def split_conditional_branches(text: str) -> list[tuple[int, str, str]]:
    """Yield ``(line_number, condition, body)`` for every ``if``/``elif`` arm.

    Each arm's body runs to the next ``elif``/``else``/``fi`` at its own depth, so every
    arm of an elif chain is analyzed as its own deny block. Nested ``if`` bodies are
    consumed whole (a conservative miss, per the module docstring).
    """
    lines = text.splitlines()
    branches: list[tuple[int, str, str]] = []
    i = 0
    while i < len(lines):
        if not _BRANCH_HEAD_RE.match(lines[i]):
            i += 1
            continue
        start = i
        condition = [lines[i]]
        while "then" not in lines[i] and i + 1 < len(lines):
            i += 1
            condition.append(lines[i])
        depth = 0
        body: list[str] = []
        while i + 1 < len(lines):
            nxt = lines[i + 1]
            if depth == 0 and re.match(r"\s*(?:elif\b|else\b|fi\b)", nxt):
                break
            i += 1
            if re.match(r"\s*if\b", nxt):
                depth += 1
            elif re.match(r"\s*fi\b", nxt):
                depth -= 1
            body.append(nxt)
        branches.append((start + 1, " ".join(part.strip() for part in condition), "\n".join(body)))
        i += 1
    return branches


@dataclass(slots=True)
class _ConditionScan:
    """Matcher literals found in one arm's condition, with the disqualifiers."""

    positives: list[str] = field(default_factory=list)
    negatives: list[str] = field(default_factory=list)
    untraced_matcher: bool = False
    inverted_matcher: bool = False

    def logic_reasons(self, *, live: bool) -> list[str]:
        reasons = []
        if live:
            reasons.append("deny decision depends on live state")
        if self.untraced_matcher:
            reasons.append("matcher target not traced to the tool command")
        if self.inverted_matcher:
            reasons.append("inverted (grep -v) matcher is an allow-list, not a deny set")
        if not reasons:
            reasons.append("no literal matcher found in condition")
        return reasons


def _scan_condition(condition: str, command_vars: set[str]) -> _ConditionScan:
    """Bucket each clause's grep literals; disqualify what can't be safely credited.

    Tracing is per-clause: the clause that carries the matcher must itself read a
    command-tainted variable. A matcher grepping an unrelated variable (even with a
    traced side-condition alongside) may be a dead branch — crediting it is a false
    enforced.
    """
    scan = _ConditionScan()
    for clause in split_and_clauses(condition):
        found = [match.group(2) for match in _GREP_PATTERN_RE.finditer(clause)]
        if not found:
            continue
        if not any(_refs_var(clause, name) for name in command_vars):
            scan.untraced_matcher = True
            continue
        if _INVERTED_GREP_RE.search(clause):
            scan.inverted_matcher = True
            continue
        bucket = scan.negatives if _NEGATED_CLAUSE_RE.search(clause) else scan.positives
        bucket.extend(found)
    return scan


def _extracted_block(
    guard: str, line: int, scan: _ConditionScan, statics: dict[str, str]
) -> DenyBlock:
    patterns: list[str] = []
    exceptions: list[str] = []
    unresolved: set[str] = set()
    for raw in scan.positives:
        resolved, missing = resolve_pattern(raw, statics)
        patterns.append(resolved)
        unresolved.update(missing)
    for raw in scan.negatives:
        resolved, missing = resolve_pattern(raw, statics)
        exceptions.append(resolved)
        unresolved.update(missing)
    kind = BlockKind.PARAMETERIZED if unresolved else BlockKind.PATTERN
    return DenyBlock(
        guard, line, kind, patterns=patterns, exceptions=exceptions, unresolved=sorted(unresolved)
    )


def extract_deny_blocks(text: str, guard: str) -> list[DenyBlock]:
    """Classify every blocking arm of one guard script (see module docstring)."""
    command_vars = trace_command_vars(text)
    statics = collect_static_assignments(text)
    blocks: list[DenyBlock] = []

    for line, condition, body in split_conditional_branches(text):
        if not _has_deny_body(body):
            continue
        scan = _scan_condition(condition, command_vars)
        live = bool(_LIVE_STATE_RE.search(condition) or _LIVE_STATE_RE.search(body))
        if live or scan.untraced_matcher or scan.inverted_matcher or not scan.positives:
            reason = "; ".join(scan.logic_reasons(live=live))
            blocks.append(DenyBlock(guard, line, BlockKind.LOGIC, reason=reason))
        else:
            blocks.append(_extracted_block(guard, line, scan, statics))
    return blocks

"""Dispatcher introspection: detect guard *evidence* inside opaque hook dispatchers.

The rubric's checks look for *named* guard scripts in a hook command. A harness that routes
every tool event through one dispatcher (``pre_tool_use_dispatch.py``) hides that logic, so the
named-guard needles miss and the scorer emits an opaque-dispatcher caveat (see
:mod:`harness_scorecard.caveats`). The operator's recourse today is to hand-read the dispatcher
and declare ``[dispatcher].credits`` in a policy file.

This module does that reading automatically: it scans the dispatcher source (and the sibling
modules beside it, where shared guard logic lives) for a per-check *code construct* -- a named
guard regex, a guard call -- whose presence indicates the guard is implemented. A match is
**evidence, not proof**: source scanning can be fooled, so detection is advisory by default
(:func:`harness_scorecard.scoring.score_harness` turns a find into a *suggestion* to add the
check to ``[dispatcher].credits``) and only credits the finding when the operator opts in with
``--credit-detected``. Patterns target identifiers / calls / named regexes (not prose), and
comment lines and triple-quoted blocks are skipped to suppress docstring mentions -- but a
match is evidence, not proof, which is why detection only *suggests* by default.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from harness_scorecard.caveats import _SCRIPT_RE, _SECURITY_EVENTS, is_dispatcher_command

if TYPE_CHECKING:
    from collections.abc import Iterator, Sequence

    from harness_scorecard.parsing import HookEntry

# Per-check evidence: a code construct whose presence in the dispatcher source indicates the
# guard exists. Each pattern targets a named regex/constant or a call so a comment or a passing
# string mention is unlikely to match; comment and docstring lines are skipped during the scan.
EVIDENCE_PATTERNS: dict[str, tuple[str, ...]] = {
    "CDX-D1-02": (r"\bSENSITIVE_PATH_RE\b", r"home-level credential", r"\.ssh\b.{0,40}\.aws\b"),
    "CDX-D3-02": (r"\binjection_signals\s*\(", r"\bINJECTION_RE\b", r"\bINJECTION_PATTERNS\b"),
    "CDX-D4-02": (
        r"force[_\s-]?push",
        r"git\s+push\b[^\n]*--force",
        r"git\s+(?:reset|rebase|filter-branch|filter-repo)\b",
    ),
    "CDX-D5-03": (
        r"\bCODEX_SELF_WRITE_RE\b",
        r"self[_\s-]?protect",
        r"\.codex/(?:hooks|agents|config)",
    ),
    "CDX-D6-01": (
        r"\bvalidate_closeout_claims\s*\(",
        r"\bcheck_codex_config_surfaces\s*\(",
        r"\bsafe_verification\s*\(",
    ),
    "CDX-D10-01": (r"\bHOOK_AUDIT_LOG\b", r"\baudit\.jsonl\b", r"\bappend_audit\s*\("),
}


@dataclass(frozen=True, slots=True)
class Evidence:
    """A code construct found in a dispatcher source that evidences a check's guard."""

    check_id: str
    location: str  # "<basename>:<lineno>"
    snippet: str


def _resolve_in_root(candidate: Path, root_resolved: Path) -> Path | None:
    """Resolve ``candidate`` and return it only if it is a file confined to ``root_resolved``.

    The confinement check is what stops a ``..`` token in a hook command from escaping the
    harness directory to read an arbitrary file.
    """
    try:
        resolved = candidate.resolve()
    except OSError:
        return None
    if resolved.is_file() and resolved.is_relative_to(root_resolved):
        return resolved
    return None


def _hook_scripts(root: Path, root_resolved: Path, hooks: Sequence[HookEntry]) -> set[Path]:
    """In-root dispatcher script files referenced by security-event hooks.

    Only security-event dispatchers are scanned: a SessionStart dispatcher routes lifecycle
    chores, not tool guards, so it is not a guard-evidence source.
    """
    scripts: set[Path] = set()
    for hook in hooks:
        if hook.event not in _SECURITY_EVENTS or not is_dispatcher_command(hook.command):
            continue
        for token in _SCRIPT_RE.findall(hook.command):
            candidate = Path(token)
            if not candidate.is_absolute():
                candidate = root / token
            resolved = _resolve_in_root(candidate, root_resolved)
            if resolved is not None:
                scripts.add(resolved)
    return scripts


def _dispatcher_sources(root: Path, hooks: Sequence[HookEntry]) -> list[Path]:
    """Dispatcher script files on security-event hooks, plus the ``.py`` siblings beside them.

    A dispatcher's helpers live in its own directory (``common.py``), where shared guard logic
    -- the audit log, the credential-path regex -- sits, so that directory's in-root ``.py``
    files are included. Unreadable paths are skipped.
    """
    root_resolved = root.resolve()
    scripts = _hook_scripts(root, root_resolved, hooks)
    bundle: set[Path] = set(scripts)
    for script in scripts:
        try:
            for sibling in script.parent.glob("*.py"):
                resolved = _resolve_in_root(sibling, root_resolved)
                if resolved is not None:
                    bundle.add(resolved)
        except OSError:
            continue
    return sorted(bundle)


_TRIPLE_RE = re.compile(r'"""|\'\'\'')
_INLINE_TRIPLE_RE = re.compile(r'""".*?"""|\'\'\'.*?\'\'\'')


def _code_lines(lines: list[str]) -> Iterator[tuple[int, str]]:
    """Yield ``(lineno, code)`` with comments and triple-quoted spans/blocks stripped.

    A guard *mentioned* in a docstring is not the guard, so inline ``\"\"\"...\"\"\"`` spans,
    multi-line docstring blocks, and trailing ``#`` comments are removed before a line is offered
    for matching. Normal string literals are kept -- a guard's own regex/message lives there.
    Lines that reduce to whitespace yield nothing.
    """
    in_block = False
    for lineno, raw in enumerate(lines, 1):
        line = raw
        if in_block:
            close = _TRIPLE_RE.search(line)
            if close is None:
                continue
            in_block = False
            line = line[close.end() :]
        line = _INLINE_TRIPLE_RE.sub(" ", line)
        opener = _TRIPLE_RE.search(line)
        if opener is not None:
            in_block = True
            line = line[: opener.start()]
        code = line.split("#", 1)[0]
        if code.strip():
            yield lineno, code


def detect_evidence(root: Path, hooks: Sequence[HookEntry]) -> dict[str, Evidence]:
    """First evidence snippet per check whose guard is found in the dispatcher source bundle.

    Read-only and best-effort: unreadable files are skipped, comment and docstring lines are
    ignored, and at most one :class:`Evidence` is returned per check id (the first match across
    the bundle).
    """
    compiled = {
        check_id: [re.compile(pattern, re.IGNORECASE) for pattern in patterns]
        for check_id, patterns in EVIDENCE_PATTERNS.items()
    }
    found: dict[str, Evidence] = {}
    for path in _dispatcher_sources(root, hooks):
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for lineno, code in _code_lines(lines):
            for check_id, regexes in compiled.items():
                if check_id in found:
                    continue
                if any(regex.search(code) for regex in regexes):
                    snippet = " ".join(code.split())[:120]
                    found[check_id] = Evidence(check_id, f"{path.name}:{lineno}", snippet)
        if len(found) == len(compiled):
            break
    return found

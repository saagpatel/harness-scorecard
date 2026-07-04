"""Claims audit: does the prose actually have enforcement behind it?

Extracts every normative claim from the harness's rules prose (CLAUDE.md +
``rules/*.md``), builds the deny universe (hook-body deny sets via
``harness_scorecard.guard_extract`` + ``permissions.deny`` globs + ``autoMode.hard_deny``
where the active mode makes it effective), and answers per claim: *is this enforced, and
by what?*

Matching design law (each rule earned by a documented false backing in the feasibility
spike):

1. Bare words never substring-match — exact token boundaries only, after regex/glob
   normalization (``--force`` must not meet ``--force-reset``).
2. Paths substring-match with home-prefix canonicalization both directions, so ``~/.ssh``
   meets ``/Users/x/.ssh/**``. Paths are specific enough for substring; words are not.
3. A match requires a path hit, an exact flag hit, or verb+noun co-occurrence — a single
   bare-noun overlap is never backing.
4. A logic-classified guard can yield at most ``candidate_logic``; ``enforced_*`` is
   structurally unreachable from one (its ``DenyBlock`` carries no patterns).

Phase 1 scope: shell guard scripts. Hook commands that don't resolve to a readable
``.sh``/``.bash`` file are reported as unread, never silently under-credited.
"""

from __future__ import annotations

import json
import re
import shlex
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from pathlib import Path

from harness_scorecard.discovery import HarnessConfig
from harness_scorecard.discovery_codex import CodexConfig
from harness_scorecard.guard_extract import extract_deny_blocks

type ClaimsConfig = HarnessConfig | CodexConfig


class ClaimClass(StrEnum):
    """Whether a claim names a blockable action or states a convention."""

    ENFORCEMENT = "enforcement"
    STYLE = "style"


class ClaimStatus(StrEnum):
    """Per-claim verdict under the active permission mode."""

    ENFORCED_HOOK = "enforced_hook"
    ENFORCED_DENY = "enforced_deny"
    ENFORCED_BOTH = "enforced_both"
    CANDIDATE_LOGIC = "candidate_logic"
    PROSE_ONLY = "prose_only"
    STYLE_RULE = "style_rule"


ENFORCED_STATUSES = frozenset(
    {ClaimStatus.ENFORCED_HOOK, ClaimStatus.ENFORCED_DENY, ClaimStatus.ENFORCED_BOTH}
)


@dataclass(slots=True)
class Claim:
    """One normative statement extracted from the rules prose."""

    source: str  # "rules/sandboxing.md:21"
    text: str
    tokens: list[str]
    hard_deny: bool
    claim_class: ClaimClass


@dataclass(slots=True)
class ClaimFinding:
    """A claim plus its resolved enforcement backing."""

    claim: Claim
    status: ClaimStatus
    backing: list[str] = field(default_factory=list)
    logic_candidates: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ClaimsReport:
    """The full ledger plus the honesty counters the output must state."""

    harness_path: str
    mode: str
    hard_deny_effective: bool
    findings: list[ClaimFinding]
    blocks_found: int
    blocks_extracted: int
    blocks_logic: int
    deny_glob_count: int
    scripts_read: list[str]
    scripts_unread: list[str]
    notes: list[str]

    def hard_prose_only(self) -> list[ClaimFinding]:
        """Hard-deny-class claims with no surviving enforcement — the gate population."""
        return [
            finding
            for finding in self.findings
            if finding.claim.hard_deny and finding.status is ClaimStatus.PROSE_ONLY
        ]

    def enforcement_prose_only(self) -> list[ClaimFinding]:
        return [f for f in self.findings if f.status is ClaimStatus.PROSE_ONLY]


# --- claim extraction ----------------------------------------------------------------

# Extraction/matching bounds. _MANY_HITS_THRESHOLD: three or more exact-token hits count
# as backing even without a verb+noun pair — that much lexical overlap is not accidental.
_MAX_CODE_SPAN_LEN = 40
_MAX_CLAIM_LINE_LEN = 300
_MIN_WORD_LEN = 2
_MANY_HITS_THRESHOLD = 3
_MAX_COMMAND_DISPLAY = 60
_MAX_BACKING_CITED = 3

_PROHIBITION_RE = re.compile(
    r"(?i)\b(?:never|blocked|forbidden|hard-deny|must not|off the table|"
    r"do(?:es)? not|don't|requires? (?:an? )?(?:approval )?token)\b"
)
_CODE_SPAN_RE = re.compile(r"`([^`]+)`")
_PATH_TOKEN_RE = re.compile(r"~/[\w./-]+|\$HOME[\w./-]*|/(?:Users|home)/[\w./-]+")
_FLAG_TOKEN_RE = re.compile(r"--?[a-zA-Z][a-zA-Z-]+")
_HARD_DENY_HEADING_RE = re.compile(r"(?i)hard[- ]deny")

VERB_LEXICON = frozenset(
    {
        "push",
        "commit",
        "rm",
        "delete",
        "drop",
        "truncate",
        "read",
        "transmit",
        "mutate",
        "install",
        "force",
        "amend",
        "merge",
        "approve",
        "send",
        "erase",
        "overwrite",
        "publish",
        "deploy",
    }
)
NOUN_LEXICON = frozenset(
    {
        "main",
        "master",
        "token",
        "ssh",
        "aws",
        "gnupg",
        "gcloud",
        "settings",
        "hooks",
        "localhost",
        "database",
        "db",
        "lockfile",
        "credentials",
    }
)
# Headings whose bullets are meta-commentary (keyword lists, anti-pattern catalogs), not
# statements about this harness's own behavior.
_STOP_SECTIONS = frozenset({"anti-patterns", "keywords", "what this does not mean"})


def salient_tokens(text: str) -> list[str]:
    """The matchable tokens of a claim: code spans, paths, flags, and lexicon words."""
    tokens: set[str] = set()
    for match in _CODE_SPAN_RE.finditer(text):
        span = match.group(1).strip()
        if 0 < len(span) <= _MAX_CODE_SPAN_LEN:
            tokens.add(span.lower())
    tokens.update(p.lower() for p in _PATH_TOKEN_RE.findall(text))
    tokens.update(f.lower() for f in _FLAG_TOKEN_RE.findall(text))
    words = set(re.findall(r"[a-zA-Z_.-]{2,}", text.lower()))
    tokens.update(words & VERB_LEXICON)
    tokens.update(words & NOUN_LEXICON)
    return sorted(tokens)


def extract_claims(sources: list[tuple[str, str]]) -> list[Claim]:
    """Scan ``(name, text)`` rule sources for normative claims.

    A claim is an in-scope line that either sits as a bullet under a Hard-Deny heading or
    carries a prohibition marker. The class split is load-bearing: an ``enforcement``
    claim names a blockable action (lexicon verb, path, or hard-deny placement); a
    ``style`` claim is a convention — listed in the ledger, never matched, because style
    rules sharing nouns with guards are exactly what generates false backings.
    """
    claims: list[Claim] = []
    for name, text in sources:
        section = ""
        hard_deny_section = False
        for lineno, line in enumerate(text.splitlines(), 1):
            if line.startswith("#"):
                section = line.lstrip("# ").strip().lower()
                hard_deny_section = bool(_HARD_DENY_HEADING_RE.search(section))
                continue
            stripped = line.strip()
            if not stripped or section in _STOP_SECTIONS:
                continue
            is_bullet = stripped.startswith(("-", "*"))
            if not ((hard_deny_section and is_bullet) or _PROHIBITION_RE.search(stripped)):
                continue
            if len(stripped) > _MAX_CLAIM_LINE_LEN or stripped.startswith(">"):
                continue
            tokens = salient_tokens(stripped)
            if not tokens:
                continue
            words = set(re.findall(r"[a-z.-]{2,}", stripped.lower()))
            enforcement = bool(
                hard_deny_section or (words & VERB_LEXICON) or _PATH_TOKEN_RE.search(stripped)
            )
            claims.append(
                Claim(
                    source=f"{name}:{lineno}",
                    text=stripped.lstrip("-* ").strip(),
                    tokens=tokens,
                    hard_deny=hard_deny_section,
                    claim_class=ClaimClass.ENFORCEMENT if enforcement else ClaimClass.STYLE,
                )
            )
    return claims


# --- matching ------------------------------------------------------------------------

# Any home-directory spelling collapses to one marker so `~/.ssh` meets
# `/Users/x/.ssh/**` regardless of whose home either side was written for. Applied to
# already-lowercased text, so the prefixes are spelled lowercase.
_HOME_FORM_RE = re.compile(r"(?:~|\$home|/users/[^/\s\"')]+|/home/[^/\s\"')]+)(?=/)")


def _canon_paths(text: str) -> str:
    return _HOME_FORM_RE.sub("<home>", text.lower())


def norm_words(text: str) -> set[str]:
    """Normalize a regex/glob into an exact-token word set.

    Alternations and classes are split so ``(main|master)`` yields both words; escapes
    and shell-class noise are stripped. Exact-boundary matching (never substring) is
    what killed the spike's false backings.
    """
    text = text.lower()
    text = re.sub(r"\[\[:space:\]\]|\\s\+?|\[\^[^\]]*\]|\\b", " ", text)
    text = re.sub(r"[\\^$()+?{}|*]", " ", text)
    words = set(re.findall(r"[a-z0-9_.~/-]{2,}", text))
    # A token like `push.` (regex glue after stripping `.*`) must still meet the exact
    # word `push`; keep both forms so boundary matching is not defeated by punctuation.
    for word in list(words):
        trimmed = word.strip(".")
        if len(trimmed) >= _MIN_WORD_LEN:
            words.add(trimmed)
    return words


def match_tokens(tokens: list[str], haystack: str) -> list[str]:
    """Exact-word hits; a match needs a path, an exact flag, or verb+noun co-occurrence."""
    hay_words = norm_words(haystack)
    hay_text = re.sub(r"\s+", " ", haystack.lower())
    hay_canon = _canon_paths(haystack)
    hits: list[str] = []
    for token in tokens:
        if "/" in token or token.startswith("~"):
            if _canon_paths(token) in hay_canon:
                hits.append(token)
        elif " " in token:
            # Multi-word code span: substring, but on token boundaries — `rm -rf` must
            # not meet the inside of `confirm -rfile-flag` by character coincidence.
            if re.search(r"(?<![\w.~/-])" + re.escape(token) + r"(?![\w.~/-])", hay_text):
                hits.append(token)
        elif token in hay_words:
            hits.append(token)
    paths = [t for t in hits if "/" in t or t.startswith("~")]
    flags = [t for t in hits if t.startswith("-")]
    verbs = [t for t in hits if t in VERB_LEXICON]
    others = [t for t in hits if t not in VERB_LEXICON and t not in flags]
    if paths or flags or (verbs and others) or len(hits) >= _MANY_HITS_THRESHOLD:
        return hits
    return []


# --- audit orchestration -------------------------------------------------------------

_SCRIPT_SUFFIXES = (".sh", ".bash")
# Live-config prefixes that the audited directory stands in for.
_CLAUDE_ROOT_ALIAS_PREFIXES = ("~/.claude/", "$HOME/.claude/", "$CLAUDE_CONFIG_DIR/")
_CODEX_ROOT_ALIAS_PREFIXES = ("~/.codex/", "$HOME/.codex/", "$CODEX_HOME/")
_CODEX_GATED_APPROVALS = ("untrusted", "on-request")

_QUALIFIER_NOTE = (
    "Qualifiers are not semantically verified: a match means the action is guarded, not "
    "that every qualifier (e.g. 'non-localhost', 'depth <= 1') is honored."
)


def _root_alias_prefixes(root: Path) -> tuple[str, ...]:
    return _CODEX_ROOT_ALIAS_PREFIXES if root.name == ".codex" else _CLAUDE_ROOT_ALIAS_PREFIXES


def _resolve_hook_script(command: str, root: Path) -> Path | None:
    """Find the shell script a hook command runs, or ``None`` (reported as unread)."""
    try:
        tokens = shlex.split(command)
    except ValueError:
        tokens = command.split()
    for token in tokens:
        cleaned = token.strip("\"'")
        if not cleaned.endswith(_SCRIPT_SUFFIXES):
            continue
        for prefix in _root_alias_prefixes(root):
            if cleaned.startswith(prefix):
                candidate = root / cleaned[len(prefix) :]
                if candidate.is_file():
                    return candidate
        absolute = Path(cleaned).expanduser()
        if absolute.is_absolute() and absolute.is_file():
            return absolute
        relative = root / cleaned
        if relative.is_file():
            return relative
    return None


def _short_command(command: str) -> str:
    command = re.sub(r"\s+", " ", command.strip())
    if len(command) <= _MAX_COMMAND_DISPLAY:
        return command
    return command[: _MAX_COMMAND_DISPLAY - 3] + "..."


@dataclass(slots=True)
class _DenyUniverse:
    """Everything a claim can be matched against, plus the honesty counters."""

    pattern_index: list[tuple[str, str]] = field(default_factory=list)  # (guard, blob)
    logic_sources: dict[str, str] = field(default_factory=dict)
    blocks_found: int = 0
    blocks_extracted: int = 0
    scripts_read: list[str] = field(default_factory=list)
    scripts_unread: list[str] = field(default_factory=list)


def _build_deny_universe(config: ClaimsConfig) -> _DenyUniverse:
    """Extract the deny sets of every readable shell guard the harness registers."""
    universe = _DenyUniverse()
    seen_commands: set[str] = set()
    seen_scripts: set[Path] = set()
    for hook in config.hooks:
        if hook.command in seen_commands:
            continue
        seen_commands.add(hook.command)
        script = _resolve_hook_script(hook.command, config.root)
        if script is None:
            universe.scripts_unread.append(_short_command(hook.command))
            continue
        if script in seen_scripts:
            continue
        seen_scripts.add(script)
        text = _read(script)
        if text is None:
            # Resolved but unreadable (permissions, races): report it unread rather than
            # letting it masquerade as an analyzed guard with zero deny blocks.
            universe.scripts_unread.append(_short_command(hook.command))
            continue
        universe.scripts_read.append(script.name)
        for block in extract_deny_blocks(text, script.name):
            universe.blocks_found += 1
            if block.is_extracted:
                universe.blocks_extracted += 1
                blob = " ".join(block.patterns + block.exceptions)
                universe.pattern_index.append((script.name, blob))
            else:
                universe.logic_sources[script.name] = text
    return universe


def _codex_home_writable(config: CodexConfig) -> bool:
    codex_home = config.root.expanduser()
    for raw in config.writable_roots:
        try:
            writable = Path(raw).expanduser()
        except (ValueError, OSError):
            continue
        if ".codex" in writable.parts:
            return True
        if codex_home == writable or codex_home.is_relative_to(writable):
            return True
    return False


def _claim_sources(config: ClaimsConfig) -> list[tuple[str, str]]:
    root = config.root
    sources: list[tuple[str, str]] = []
    if isinstance(config, CodexConfig):
        if config.has_agents_md:
            sources.append(("AGENTS.md", _read(root / "AGENTS.md") or ""))
        sources.extend(
            (f"agents/{name}", _read(root / "agents" / name) or "")
            for name in config.agent_files
        )
        return sources

    if config.has_claude_md:
        sources.append(("CLAUDE.md", _read(root / "CLAUDE.md") or ""))
    sources.extend(
        (f"rules/{name}", _read(root / "rules" / name) or "") for name in config.rule_files
    )
    return sources


def _codex_config_backing(config: CodexConfig) -> list[str]:
    backing: list[str] = []
    if config.approval_policy in _CODEX_GATED_APPROVALS:
        backing.append(
            f"approval_policy:{config.approval_policy} gates command execution before run: "
            "push commit merge force main master rm delete drop truncate install deploy publish"
        )
    if config.network_blocked:
        backing.append(
            f"sandbox:{config.sandbox_mode} denies outbound network access: "
            "network egress exfil transmit curl wget"
        )
    if not config.sandbox_disabled and not _codex_home_writable(config):
        backing.append(
            f"sandbox:{config.sandbox_mode} keeps ~/.codex out of write scope: "
            "write edit mutate overwrite delete rm ~/.codex AGENTS.md config.toml hooks.json"
        )
    if config.env_secrets_scrubbed:
        backing.append(
            "shell_environment_policy keeps secret-looking env vars out of commands: "
            "token secret credential password key"
        )
    return backing


def _declarative_backing(config: ClaimsConfig) -> list[tuple[str, str]]:
    if isinstance(config, CodexConfig):
        return [("config", rule) for rule in _codex_config_backing(config)]
    hard_deny_rules = config.hard_deny if config.hard_deny_effective else []
    return [("deny", glob) for glob in config.deny] + [
        ("hard_deny", rule) for rule in hard_deny_rules
    ]


def _audit_mode(config: ClaimsConfig) -> str:
    if isinstance(config, CodexConfig):
        return f"sandbox={config.sandbox_mode}, approval={config.approval_policy}"
    return config.default_mode


def _hard_deny_effective(config: ClaimsConfig) -> bool:
    if isinstance(config, CodexConfig):
        return not config.is_bypass
    return config.hard_deny_effective


def _audit_notes(config: ClaimsConfig, universe: _DenyUniverse) -> list[str]:
    notes = [_QUALIFIER_NOTE]
    if isinstance(config, CodexConfig) and config.is_bypass:
        notes.append(
            "Codex is in effective bypass (sandbox_mode=danger-full-access and "
            "approval_policy=never); sandbox and approval-policy config were not counted as "
            "claim backing."
        )
    if isinstance(config, HarnessConfig) and config.is_bypass and config.hard_deny:
        notes.append(
            f"autoMode.hard_deny ({len(config.hard_deny)} rules) is INERT under "
            "bypassPermissions and was not counted as backing."
        )
    if universe.scripts_unread:
        notes.append(
            f"{len(universe.scripts_unread)} hook command(s) did not resolve to a readable "
            "shell script and were not analyzed — claims they enforce will read as prose-only."
        )
    notes.extend(config.caveats)
    return notes


def audit_claims(config: ClaimsConfig) -> ClaimsReport:
    """Run the full claims audit against a loaded harness (read-only)."""
    root = config.root
    claims = extract_claims(_claim_sources(config))
    universe = _build_deny_universe(config)
    declarative = _declarative_backing(config)
    findings = [
        _match_claim(c, universe.pattern_index, declarative, universe.logic_sources)
        for c in claims
    ]
    return ClaimsReport(
        harness_path=str(root),
        mode=_audit_mode(config),
        hard_deny_effective=_hard_deny_effective(config),
        findings=findings,
        blocks_found=universe.blocks_found,
        blocks_extracted=universe.blocks_extracted,
        blocks_logic=universe.blocks_found - universe.blocks_extracted,
        deny_glob_count=len(declarative),
        scripts_read=sorted(universe.scripts_read),
        scripts_unread=sorted(set(universe.scripts_unread)),
        notes=_audit_notes(config, universe),
    )


def _read(path: Path) -> str | None:
    """File text, or ``None`` when unreadable — the caller must not treat an unreadable
    guard as an analyzed-and-empty one."""
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _match_claim(
    claim: Claim,
    pattern_index: list[tuple[str, str]],
    declarative_rules: list[tuple[str, str]],
    logic_sources: dict[str, str],
) -> ClaimFinding:
    if claim.claim_class is ClaimClass.STYLE:
        return ClaimFinding(claim, ClaimStatus.STYLE_RULE)

    hook_hits = sorted({guard for guard, blob in pattern_index if match_tokens(claim.tokens, blob)})
    declarative = [
        f"{kind}:{rule}" for kind, rule in declarative_rules if match_tokens(claim.tokens, rule)
    ]

    if hook_hits and declarative:
        status = ClaimStatus.ENFORCED_BOTH
    elif hook_hits:
        status = ClaimStatus.ENFORCED_HOOK
    elif declarative:
        status = ClaimStatus.ENFORCED_DENY
    else:
        logic_hits = sorted(
            guard for guard, text in logic_sources.items() if match_tokens(claim.tokens, text)
        )
        if logic_hits:
            return ClaimFinding(claim, ClaimStatus.CANDIDATE_LOGIC, logic_candidates=logic_hits)
        return ClaimFinding(claim, ClaimStatus.PROSE_ONLY)

    backing = [f"hook:{guard}" for guard in hook_hits] + declarative
    return ClaimFinding(claim, status, backing=backing)


# --- rendering -----------------------------------------------------------------------

_STATUS_LABELS: dict[ClaimStatus, str] = {
    ClaimStatus.ENFORCED_HOOK: "ENFORCED (hook)",
    ClaimStatus.ENFORCED_DENY: "ENFORCED (deny)",
    ClaimStatus.ENFORCED_BOTH: "ENFORCED (both)",
    ClaimStatus.CANDIDATE_LOGIC: "CANDIDATE (logic)",
    ClaimStatus.PROSE_ONLY: "PROSE-ONLY",
    ClaimStatus.STYLE_RULE: "STYLE",
}


def render_claims_console(report: ClaimsReport) -> str:
    lines = [
        f"claims audit: {report.harness_path} (mode: {report.mode})",
        (
            f"coverage: {report.blocks_found} deny blocks across "
            f"{len(report.scripts_read)} shell guard(s) — {report.blocks_extracted} "
            f"extracted, {report.blocks_logic} logic-flagged (manual review); "
            f"{report.deny_glob_count} declarative backing rule(s)"
        ),
        "",
    ]
    enforcement = [f for f in report.findings if f.claim.claim_class is ClaimClass.ENFORCEMENT]
    style = [f for f in report.findings if f.claim.claim_class is ClaimClass.STYLE]
    for finding in enforcement + style:
        label = _STATUS_LABELS[finding.status]
        marker = " [HARD-DENY]" if finding.claim.hard_deny else ""
        lines.append(f"{label:<18} {finding.claim.source}{marker}  {finding.claim.text[:90]}")
        cited = finding.backing or finding.logic_candidates
        if cited:
            shown = ", ".join(cited[:_MAX_BACKING_CITED])
            overflow = len(cited) - _MAX_BACKING_CITED
            extra = f" (+{overflow} more)" if overflow > 0 else ""
            lines.append(f"{'':<18}   backing: {shown}{extra}")
    enforced = sum(1 for f in enforcement if f.status in ENFORCED_STATUSES)
    candidates = sum(1 for f in enforcement if f.status is ClaimStatus.CANDIDATE_LOGIC)
    prose_only = len(report.enforcement_prose_only())
    lines += [
        "",
        (
            f"summary: {len(enforcement)} enforcement claims — {enforced} enforced, "
            f"{candidates} candidate (logic), {prose_only} prose-only; "
            f"{len(style)} style rules listed (never matched)"
        ),
    ]
    lines.extend(f"note: {note}" for note in report.notes)
    return "\n".join(lines)


def render_claims_json(report: ClaimsReport) -> str:
    payload = {
        "harness_path": report.harness_path,
        "mode": report.mode,
        "hard_deny_effective": report.hard_deny_effective,
        "coverage": {
            "deny_blocks_found": report.blocks_found,
            "deny_blocks_extracted": report.blocks_extracted,
            "deny_blocks_logic": report.blocks_logic,
            "permissions_deny_globs": report.deny_glob_count,
            "scripts_read": report.scripts_read,
            "scripts_unread": report.scripts_unread,
        },
        "findings": [
            {
                **asdict(finding.claim),
                "status": finding.status.value,
                "backing": finding.backing,
                "logic_candidates": finding.logic_candidates,
            }
            for finding in report.findings
        ],
        "notes": report.notes,
    }
    return json.dumps(payload, indent=2)

# Claims Audit — Design

**Status:** design accepted, implementation not started.
**Lineage:** the Harness Enforcement Auditor lane (scoped 2026-06-27, spikes passed
2026-07-03) rehomed into this repo. Feasibility evidence: both spike verdicts in the
operator vault (`wiki/audits/hea-spike-verdict-2026-07-03.md`) — guard-body extraction
hit 83% on a six-guard production corpus and the claims ledger mechanically reproduced
a hand-run enforcement audit, both with zero false "enforced" claims.

## What it adds

Scorecard today grades a harness against a **fixed rubric**: expectations we define,
traced to documented red-team failure modes. The claims audit grades a harness against
**its own stated guarantees**: parse the prose rules (CLAUDE.md, `rules/*.md`), extract
every enforcement claim ("never push to main", "reads of ~/.ssh are denied"), and
answer, per claim, under the **active permission mode**: *is this actually enforced,
and by what?*

The one-line wedge survives from the original concept: existing agent-config linters
tell you your CLAUDE.md is well-written; this tells you which of its guarantees
evaporate under the mode you actually run.

## Product shape: subcommand + one rubric check (hybrid)

### 1. `harness-scorecard claims <path>` — the product surface

Full ledger output, one row per extracted claim:

```
ENFORCED (deny)   sandboxing.md:21  Read or transmit ~/.ssh, ~/.aws, ...
                    backing: 7 permissions.deny globs
ENFORCED (hook)   sandboxing.md:22  Push to main or master
                    backing: git-safety.sh (3 deny patterns)
PROSE-ONLY        sandboxing.md:23  Destructive DB ops on non-localhost hosts
                    nearest: db-guard.sh backs the destructive-SQL half;
                    the host qualifier is not checked by anything
CANDIDATE (logic) rules/foo.md:14   ...
                    manual review: matched a guard whose deny decision
                    depends on live state
STYLE             testing.md:38     Do NOT use waitForTimeout ...
                    (convention, not an enforcement claim — never matched)
```

- Statuses: `enforced_hook` / `enforced_deny` / `enforced_both` / `candidate_logic` /
  `prose_only` / `style_rule`.
- `--json` for machine output; human output cites source `file:line` and backing.
- Exit code: non-zero when any **hard-deny-class** claim is `prose_only`
  (`--strict` widens that to all enforcement claims). Mirrors `scan`'s gate philosophy.
- Mode-aware like everything else: under bypass, an `autoMode.hard_deny` entry is never
  backing; `permissions.deny` and PreToolUse hooks are.

### 2. One new rubric check, no new dimension

`HS-D5-06 — Stated hard guarantees have enforcement backing` (D5, harness
self-protection & integrity):

- **PASS** — every hard-deny-class claim in the rules files has hook or deny backing.
- **PARTIAL** — some backed, some prose-only.
- **FAIL** — a stated hard guarantee has no surviving enforcement under the active mode.
- **N/A (not penalized)** — the harness states no hard guarantees. A harness must never
  score worse for documenting its rules; only for documenting rules it doesn't enforce.

This threads claims into the default `scan` grade without polluting the rubric's
fixed-expectation model: the check's failure mode is real and documented (the 2026-06-27
dry-run's live-proven finding: a prose rule forbidding a read that nothing blocked).
Adding a check bumps `RUBRIC_VERSION` (see §8 of rubric.md).

**Rejected: an 11th dimension.** Claims are target-derived, so a whole dimension would
score differently per harness and break "the rubric is the product" (fixed, comparable,
every check traces to a failure mode). One check inside D5 captures the graded signal;
the subcommand carries the full ledger.

## Engine design

Two modules, both rewritten typed-and-tested from the spike code (port the lessons,
not the code):

### `guard_extract.py` — hook-body deny-set extraction

Input: hook script text. Output: deny blocks classified three ways —

- `pattern` — deny gated on a fully literal matcher over the command string.
- `parameterized` — literal matcher assembled from in-file/env variables; resolved
  where statically possible, unresolved names listed. Credited as extraction.
- `logic` — the deny decision depends on live state (subprocess over git/fs, computed
  comparisons). **Never credited; surfaced for manual review.** Degrades to honesty.

Spike-proven mechanics to port: taint-tracing command variables from the stdin JSON
root; `deny "..."` helper-call recognition alongside inline hook JSON and `exit 2`;
static `VAR='literal'` resolution with bounded chain-chasing; negated clauses become
`unless` exceptions on the deny entry. Known spike gap to fix in the port: the
condition splitter must be quote-aware (an `&&` inside a regex literal broke one
classification — conservatively, but still).

### `claims.py` — claim extraction + matching

Extraction: prohibition-marker scan over CLAUDE.md + rule files, plus all bullets under
a Hard-Deny heading. Every claim is classed **enforcement** (names a blockable action:
verb from a small lexicon, path, or flag) or **style** (convention; listed in the
ledger, never matched). The class split is load-bearing: without it, style rules
sharing nouns with guards generate false backings.

Matching (the spike's three-iteration lesson, now design law):

1. **Never substring-match bare words.** v1 false backings all came from substrings:
   `database` in a testing convention "backed by" the DB guard; `--force` matching
   `--force-reset`. Words match on exact token boundaries after regex/glob
   normalization (alternations split, classes stripped).
2. **Paths substring-match, tilde-expanded both directions** — `~/.ssh` must meet
   `/Users/x/.ssh/**`. Paths are specific enough that substring is safe; words are not.
3. **Match requires a path hit, an exact flag hit, or verb+noun co-occurrence.**
   Single bare-noun overlap is never backing.
4. **Logic guards can produce at most `candidate_logic`.** No code path may emit
   `enforced_*` from a logic-classified block — this is the zero-false-enforced
   invariant, enforced structurally, not by review.

Backing sources, mode-aware: extracted hook deny sets; `permissions.deny` globs;
`autoMode.hard_deny` only when the active mode is `auto`.

### Reuse

`HarnessConfig` already carries everything needed: `root`, `rule_files`,
`hooks` (command paths to read bodies from), `deny`, `hard_deny`, `default_mode`,
and the `is_bypass` / effective-floor helpers. No discovery changes beyond reading
file contents at evaluate time.

## Honesty & caveats

- The report must state extraction coverage: N deny blocks found, M extracted,
  K logic-flagged for manual review. A dispatcher-style harness (one opaque script)
  gets the existing dispatcher caveat, not silent under-crediting.
- Qualifier limitation stated in output: a claim's qualifiers ("non-localhost",
  "depth ≤ 1") are not semantically verified — a match means the *action* is guarded,
  not that every qualifier is honored. The spike's DB-rule nuance is the canonical
  example and becomes a documented example in the ledger output.

## Test plan

Synthetic fixtures only — **never real operator guards** (extracted deny sets are
security posture; same reason spike artifacts stayed out of this repo).

- Guard extraction: fixture guards covering each idiom (inline jq deny, `deny` helper,
  parameterized regex assembly, elif chains, negated exceptions, live-state logic
  blocks, `&&` inside regex literals). Oracle per fixture: expected block count,
  classes, patterns.
- Matching adversarials (the spike's false-backing constructions as permanent
  negatives): style rule with a guard noun → must NOT back; `--force` claim vs
  `--force-reset` guard → must NOT back; tilde path vs absolute glob → MUST back;
  logic-only guard + matching claim → `candidate_logic`, never enforced.
- Mode-awareness: same claim set under `auto` vs `bypassPermissions` — hard_deny
  backing flips.
- HS-D5-06: no-claims harness → N/A not penalized; one prose-only hard guarantee → FAIL.

## Phasing

- **Phase 1 (this design):** Claude Code harnesses, `claims` subcommand + HS-D5-06,
  rubric bump, README + rubric.md sections.
- **Phase 2:** Codex (AGENTS.md prose + config.toml/hooks.json backing) via the
  existing `discovery_codex` adapter; CDX check mirror.
- **Out of scope, explicitly:** semantic qualifier verification; shell logic-block
  interpretation (stays manual-review by design); any hosted/remote surface.

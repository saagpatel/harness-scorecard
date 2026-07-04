# Harness Scorecard

A read-only linter and **A–F maturity grader for coding-agent harnesses**. Point it at a
Claude Code or Codex setup — Claude Code's hooks, `permissions`, `rules/*.md`, agents, and
`CLAUDE.md`, or Codex's `config.toml` (sandbox, approval policy, trust levels), `hooks.json`,
and `AGENTS.md` — and it returns a graded scorecard: the overall maturity grade, the specific
gaps, and the guards that are missing, each with rationale. The harness type is auto-detected.

"Harness engineering" became a named discipline in 2026 and everyone is assembling harnesses
with no way to tell if theirs is any good. The rubric is the product: every check traces to a
**documented red-team failure mode**, not generic advice.

## What it looks like

```text
$ harness-scorecard scan examples/sample-harness

Harness Scorecard  v1.1.0
Target: examples/sample-harness   (claude-code)

  GRADE:  F        overall 0.28 / 1.00
  Scored 10 of 10 rubric dimensions (0 specced, pending).

  Capability gates tripped (grade capped):
    - HS-D5-01 caps at C  (Harness config write/read protected)

  D1  Secret protection & credential isolation    0.44  [weight 5]
      [PASS] HS-D1-01  Sensitive credential paths denied for read  [GATE->D]
             All core credential paths are denied for read.
             - covered: ~/.ssh, ~/.aws, ~/.gnupg, 1Password/op, gcloud, .env files
      [FAIL] HS-D1-02  Sensitive-read Bash backstop
             No Bash-level backstop for sensitive reads; deny lists cover only the Read tool.
             fix: Add a PreToolUse Bash hook that re-blocks reads of sensitive files.
      … (+4 more checks)

  D4  Destructive-action & git safety    0.63  [weight 5]
      [PASS] HS-D4-01  Push to protected branch effectively blocked  [GATE->C]
             Push to a protected branch is blocked by the effective floor.
             - hook:git-safety
             - permissions.deny
      [PASS] HS-D4-02  Catastrophic deletion blocked
             Catastrophic deletion is blocked by the effective floor.
             - hook:block-dangerous-cmds
             - hook:dangerous
      [FAIL] HS-D4-03  Destructive DB ops on non-local hosts blocked
             No effective guard against destructive DB operations on non-local hosts.
             - defaultMode=bypassPermissions: autoMode.hard_deny is INERT
             fix: Add a PreToolUse Bash db-guard hook that blocks destructive ops on non-local hosts.
      … (+2 more checks)

  … (+8 more dimensions)
```

That one line — `defaultMode=bypassPermissions: autoMode.hard_deny is INERT` — is the whole
thesis rendered live: a rich `hard_deny` block earns **nothing** because the mode makes it
inert. The sample above ([`examples/sample-harness`](examples/sample-harness/settings.json)) is
deliberately incomplete to show the findings; run it yourself, or point the tool at your own
`~/.claude` — a mature harness scores an A.

## What makes the grade real

Most config "linters" credit a harness for declaring a rule. This one models the *effective*
enforcement floor. The headline example:

> `autoMode.hard_deny` is **inert** when `permissions.defaultMode == "bypassPermissions"`.

A naive scorer reads a rich `hard_deny` block and awards an A. Harness Scorecard reads the
mode, discounts the inert block, and grades against what actually fires — `permissions.deny`
globs plus the PreToolUse hooks. See [`docs/rubric.md`](docs/rubric.md) for the full model,
including **capability gates** that cap the grade when a critical hole is present (you can't
score an A with readable credentials, no matter how many cheap checks pass).

It's honest about its own limits, too. A harness that funnels every guard through one opaque
dispatcher script hides its logic from static analysis, so the named-guard checks under-credit
it. Rather than silently mark it down, the report emits a **caveat** — "a low score here may be
a static-analysis limit, not a missing guard" — so the grade is never misread as "insecure."

## Proven, not asserted

The rubric claims every gated check traces to a real red-team failure mode. That claim is
**tested**, not just stated. [`examples/redteam/`](examples/redteam/) holds a vulnerable/guarded
fixture pair for each of the six capability gates: a plausible, otherwise-strong harness that is
missing exactly one guard, beside its fixed twin. [`tests/test_redteam_corpus.py`](tests/test_redteam_corpus.py)
mechanically asserts that the scorer **FAILs** the gated check on the vulnerable config (and the
gate caps the grade) and **PASSes** it on the guarded one — so the moat can't quietly rot.

For five of the six, the vulnerable harness scores in the **A band on raw signal** and is
dragged to the cap by that single gate — the cleanest demonstration that the gate, not general
weakness, is what bit:

```bash
harness-scorecard scan examples/redteam/claude-d4-inert-harddeny/vulnerable   # F/D/C — gate capped
harness-scorecard scan examples/redteam/claude-d4-inert-harddeny/guarded      # A — one guard added
```

Every config is static and inert; nothing executes. Each [`ATTACK.md`](examples/redteam/claude-d4-inert-harddeny/ATTACK.md)
narrates the threat, the gate that catches it, and the one-line fix. This is the moat: not
"trust our checklist," but "here is the attack, and here is the proof we catch it."

## Install

```bash
python -m pip install harness-scorecard

# Or run the published package without adding it to the current environment.
uvx harness-scorecard scan ~/.claude
```

For GitHub Actions, use the moving major tag for the latest stable 1.x action, or
pin an exact release tag when you want a fully fixed revision:

```yaml
- uses: saagpatel/harness-scorecard@v1
# - uses: saagpatel/harness-scorecard@v1.13.0
```

## Usage

```bash
# Grade a harness directory (e.g. your ~/.claude)
harness-scorecard scan ~/.claude

# JSON for tooling, plus a self-contained HTML scorecard
harness-scorecard scan ~/.claude --format json --html scorecard.html

# SARIF 2.1.0 for CI / GitHub code scanning, failing the run below grade C
harness-scorecard scan ~/.claude --sarif harness.sarif --min-grade C
```

`--min-grade {A,B,C,D,F}` sets the bar (default `B`). Exit codes: `0` meets the bar ·
`1` below the bar · `2` no harness found.

### Explain a finding

A scan tells you `HS-D4-01 FAIL`. `explain` tells you *why that matters* and how to fix it —
the documented red-team failure mode behind any check, straight from the CLI:

```text
$ harness-scorecard explain HS-D4-01
HS-D4-01  ·  Push to protected branch effectively blocked
D4 — Destructive-action & git safety  ·  weight 5  ·  critical  ·  static
GATE: a failing result caps the grade at C.

Why it matters
  A config that declares 'never push to main' only in autoMode.hard_deny does nothing
  under bypassPermissions (hard_deny is inert), so the agent or an injection pushes
  straight to a protected branch.

How to fix it
  Block push to main/master via a PreToolUse Bash hook or a deny entry (not hard_deny
  alone under bypass).

Proof it's caught
  writeup:  examples/redteam/claude-d4-inert-harddeny/ATTACK.md
  FAIL it:  harness-scorecard scan examples/redteam/claude-d4-inert-harddeny/vulnerable
  PASS it:  harness-scorecard scan examples/redteam/claude-d4-inert-harddeny/guarded
```

For the six capability gates, `explain` points at the red-team corpus pair that proves the
check. Works for any check id (`HS-*` or `CDX-*`, case-insensitive); `--format json` emits the
same content for tooling.

Or skip the second command entirely — `scan --explain` folds the one-line failure mode inline
next to every finding that isn't passing, so the *why* rides along with the grade:

```text
$ harness-scorecard scan ~/.claude --explain
...
      [FAIL] HS-D4-01  Push to protected branch effectively blocked  [GATE->C]
             Push to main/master is not blocked by any effective guard.
             why: A config that declares 'never push to main' only in autoMode.hard_deny does
                  nothing under bypassPermissions, so the agent or an injection pushes to main.
             fix: Block push to main/master via a PreToolUse Bash hook or a deny entry.
```

### Grade your whole machine

`fleet` grades several harnesses at once and reports the distribution and the worst offender —
no fake rolled-up letter (averaging A–F is meaningless). It's the "every agent harness on this
box" view:

```text
$ harness-scorecard fleet ~/.claude ~/.codex

Harness Scorecard  fleet  (2 harnesses)

  Grades:  Ax1   Bx0   Cx0   Dx1   Fx0
  Weakest dimension fleet-wide: D9 Memory / provenance hygiene (avg 0.62)
  Worst offender: ~/.codex (D, 0.64)

  GRADE  SCORE  TYPE         WEAKEST    HARNESS
  A      1.00   claude-code  -          ~/.claude
  D      0.64   codex        D9 0.25    ~/.codex
```

Pass any paths or globs (`fleet ~/.claude ~/Projects/*/.claude`); each harness is graded with
its own auto-discovered policy. `--min-grade` (default `B`) exits non-zero if **any** harness is
below the bar — drop it in CI to keep a whole team's harnesses above a floor.

### Audit your own stated guarantees

The rubric grades against *our* expectations. `claims` grades against *yours*: it parses
the rules prose (Claude Code: CLAUDE.md + `rules/*.md`; Codex: AGENTS.md + inventoried
instruction files), extracts every enforcement claim, and answers per claim — under the
active permission mode — *is this actually enforced, and by what?*

```text
$ harness-scorecard claims ~/.claude

ENFORCED (deny)    rules/sandboxing.md:21 [HARD-DENY]  Read or transmit ~/.ssh, ~/.aws, ...
                     backing: deny:Read(//Users/you/.ssh/**), ... (+4 more)
ENFORCED (hook)    rules/sandboxing.md:22 [HARD-DENY]  Push to main or master
                     backing: hook:git-safety.sh
PROSE-ONLY         rules/sandboxing.md:23 [HARD-DENY]  Destructive DB ops on non-localhost hosts
CANDIDATE (logic)  rules/git.md:14                     Never amend after a hook failure
                     backing: git-state-guard.sh
STYLE              rules/testing.md:38                 Do NOT use waitForTimeout ...
```

Deny sets are extracted statically from hook bodies; a guard whose deny decision depends
on live state is surfaced as a manual-review candidate, never credited — the audit can
under-count, but it cannot claim a guarantee is enforced when it isn't. Exit is non-zero
when a hard-deny-class claim is prose-only (`--strict` widens that to every enforcement
claim); `--format json` / `--json FILE` emit the machine ledger. The graded counterpart
is check `HS-D5-04`, which is N/A — never a penalty — for harnesses that state no hard
guarantees. Codex harnesses get the mirrored check `CDX-D5-04`.

### Grade badge

Emit a flat SVG badge (colored A green → F red) for a harness repo's README, then regenerate it
in CI so it can't drift from reality:

```bash
harness-scorecard scan ~/.claude --badge harness-grade.svg
```

```markdown
![harness grade](harness-grade.svg)
```

### Track drift over time

`diff` compares two scorecards and reports what changed — which checks flipped, which
dimension scores moved, and whether a capability gate newly trips. Each argument is either a
live harness directory or a saved JSON report (`scan --json`), so the same command covers a CI
regression gate, a before/after audit, or drift between two snapshots:

```bash
# Record a baseline, then later fail if the harness grade regresses below it
harness-scorecard scan ~/.claude --json baseline.json
harness-scorecard diff baseline.json ~/.claude          # exit 1 if the grade dropped

# Compare two saved snapshots, machine-readable
harness-scorecard diff old.json new.json --format json
```

Exit codes: `0` no regression (same or better grade) · `1` grade regressed · `2` invalid input.
Gate and dimension moves are reported for context; the **letter grade** is what fails the gate.

### Accept known gaps with a policy file

Drop a `.harness-scorecard.toml` in the harness directory (or pass `--policy`) to record decisions
the grader should respect — always surfaced in the report, never silently hidden:

```toml
[[waiver]]
check = "HS-D1-03"
reason = "Write-time secret scanning is handled by pre-commit, outside the harness."

[dispatcher]
credits = ["HS-D4-03"]   # checks an opaque dispatcher enforces but static analysis can't see
```

A **waiver** excludes a finding from the grade (and suppresses its gate cap) but lists it as
`[WAIV]` with the reason; a stale waiver is flagged, not dropped. The **dispatcher manifest**
upgrades a declared check from FAIL to PARTIAL — half credit, "declared, not statically verified."
See [`examples/harness-scorecard.toml`](examples/harness-scorecard.toml).

### Auto-detect guards behind a dispatcher

Writing that manifest by hand means reading the dispatcher yourself. `scan` can do the reading: it
introspects the dispatcher source for each check's guard signature and, by default, **suggests**
what to credit:

```text
  Policy notes:
    ! CDX-D3-02: dispatcher guard evidence at user_prompt_submit_dispatch.py:124 -- verify and add to [dispatcher].credits, or re-run with --credit-detected
```

Pass `--credit-detected` to apply those finds as PARTIAL credits, labeled `(dispatcher-detected)`
to keep them distinct from a hand-verified `(dispatcher-credited)` manifest entry:

```bash
$ harness-scorecard scan ~/.codex --credit-detected
```

A source match is *evidence, not proof*, so detection stays conservative: suggest-only by default,
comment and docstring mentions are ignored, scanned paths are confined to the harness directory,
and a capability gate is never auto-credited — lifting a grade floor still requires a verified
manifest entry. Each check carries its own guard signature (a `dispatcher_evidence` field), so
introspection covers both Claude (`HS-*`) and Codex (`CDX-*`) checks and a new check is picked up
the moment it declares one.

## GitHub Action

Grade your harness in CI and upload the findings to code scanning:

```yaml
- uses: saagpatel/harness-scorecard@v1
  with:
    path: .claude
    min-grade: B
```

The action writes SARIF and uploads it (requires `security-events: write`) **even when the grade
fails the build**, so findings always reach code scanning. Commit a `baseline.json` and pass
`baseline:` to also fail the job on any grade regression — a PR that weakens the harness can't
merge:

```yaml
- uses: saagpatel/harness-scorecard@v1
  with:
    path: .claude
    baseline: .github/harness-baseline.json   # fail if the grade drops below this
```

A complete workflow — permissions, weekly scheduling, SARIF upload — is in
[`examples/github-workflow.yml`](examples/github-workflow.yml).

### Inline failure modes in the run summary

Put the grade and every failing finding — each with its red-team failure mode and the fix —
straight on the workflow run page, so a red check explains itself without anyone opening the
logs:

```yaml
- run: harness-scorecard scan .claude --summary "$GITHUB_STEP_SUMMARY" --min-grade B
```

`--summary` appends GitHub-flavored Markdown, so it's safe alongside other steps that write to
the run summary. The console report still goes to the step log; the Markdown goes to the summary.

## Guarantees

- **Read-only.** It never writes to the harness it audits.
- **Privacy-preserving.** All output redacts secrets, tokens, emails, and absolute home
  paths. Nothing leaves the machine.
- **Dependency-free runtime.** The scorer ships stdlib-only — a tool that grades
  supply-chain hygiene should carry the smallest surface itself.

## Scope (v1)

Implements **all ten rubric dimensions** end-to-end for **both Claude Code and Codex**: secret
protection, egress/exfiltration control, tool-surface & inbound-injection defense,
destructive-action & git safety, harness self-protection & integrity, verification gates,
subagent isolation & governance, recovery/rollback safety, memory/provenance hygiene, and
observability/audit trail (the critical gated trio is D1/D4/D5). Each harness has its own
adapter and check suite over the shared scoring engine; the bypass-aware effective floor maps
to Codex's `sandbox_mode = "danger-full-access"` + `approval_policy = "never"` just as it does
to Claude Code's `bypassPermissions`. The rubric is versioned and emitted in every report.

## Development

```bash
uv sync --frozen                                      # install dev tooling from the lockfile
uv run --no-sync python -m unittest discover -s tests # tests (stdlib runner, zero extra deps)
uv run --no-sync ruff check src/ tests/               # lint
uv run --no-sync ty check src/                        # type check
```

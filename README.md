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

Harness Scorecard  v1.0.0
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

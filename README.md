# Harness Scorecard

A read-only linter and **A–F maturity grader for coding-agent harnesses**. Point it at a
Claude Code or Codex setup — Claude Code's hooks, `permissions`, `rules/*.md`, agents, and
`CLAUDE.md`, or Codex's `config.toml` (sandbox, approval policy, trust levels), `hooks.json`,
and `AGENTS.md` — and it returns a graded scorecard: the overall maturity grade, the specific
gaps, and the guards that are missing, each with rationale. The harness type is auto-detected.

"Harness engineering" became a named discipline in 2026 and everyone is assembling harnesses
with no way to tell if theirs is any good. The rubric is the product: every check traces to a
**documented red-team failure mode**, not generic advice.

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

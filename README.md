# Harness Scorecard

A read-only linter and **A–F maturity grader for coding-agent harnesses**. Point it at a
Claude Code (or, soon, Codex) setup — its hooks, `permissions` lists, `rules/*.md`, agents,
skills, and `CLAUDE.md` — and it returns a graded scorecard: the overall maturity grade, the
specific gaps, and the guards that are missing, each with rationale.

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

## Usage

```bash
# Grade a harness directory (e.g. your ~/.claude)
uv run harness-scorecard scan ~/.claude

# JSON for tooling, plus a self-contained HTML scorecard
uv run harness-scorecard scan ~/.claude --format json --html scorecard.html
```

Exit codes: `0` healthy (A/B) · `1` needs attention (C/D/F) · `2` invalid input.

## Guarantees

- **Read-only.** It never writes to the harness it audits.
- **Privacy-preserving.** All output redacts secrets, tokens, emails, and absolute home
  paths. Nothing leaves the machine.
- **Dependency-free runtime.** The scorer ships stdlib-only — a tool that grades
  supply-chain hygiene should carry the smallest surface itself.

## Scope (v1)

Implements **all ten rubric dimensions** end-to-end for Claude Code harnesses: secret
protection, egress/exfiltration control, tool-surface & inbound-injection defense,
destructive-action & git safety, harness self-protection & integrity, verification gates,
subagent isolation & governance, recovery/rollback safety, memory/provenance hygiene, and
observability/audit trail (the critical gated trio is D1/D4/D5). Codex support is next. The
rubric is versioned and emitted in every report.

## Development

```bash
uv sync --all-groups          # install dev tooling (ruff, ty, pytest)
uv run python -m unittest     # stdlib test runner — zero extra deps
uv run pytest                 # same suite under pytest
uv run ruff check && uv run ty check src/
```

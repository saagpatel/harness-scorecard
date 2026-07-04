<!-- portfolio-context:start -->
# Portfolio Context

## What This Project Is

harness-scorecard: A read-only linter and **A–F maturity grader for coding-agent harnesses**. Point it at a.

## Current State

Portfolio truth currently marks this project as `active` with `boilerplate` context. Phase 104 recovered minimum-viable context so future sessions can resume without rediscovery.

## Stack

- Primary stack: Python

## How To Run

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

## Known Risks

- This repo only has minimum-viable recovery context today; deeper handoff details may still live in the README and supporting docs.

## Review guidelines

Focus Codex review on read-only enforcement, claim/backing correctness, hook
phase and matcher semantics, path-boundary matching, SARIF and JSON output
contracts, release workflow permissions, trusted-publisher environment gates,
and whether a score or grade can overstate harness safety. Treat any change
that broadens filesystem or secret access, weakens blocking-hook checks, or
lets publish/test jobs inherit unnecessary credentials as merge-relevant.

Treat exact output and release claims as contracts. Console text, JSON, SARIF,
HTML, exit codes, score/grade semantics, action examples, and PyPI/GitHub
release instructions must stay aligned with code and workflows. A docs or
workflow change that alters the trusted-publisher claim, `id-token` boundary,
tag trigger, or consumer-facing output shape is merge-relevant.

For docs-only PRs, comment only when docs claim a grade, safety property,
permission boundary, release state, or output format that is not supported by
the reviewed code or workflows.

## Next Recommended Move

Use this context plus the README and supporting docs to resume the next active task, then promote the repo beyond minimum-viable by capturing a dedicated handoff, roadmap, or discovery artifact.

<!-- portfolio-context:end -->

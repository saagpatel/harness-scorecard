# Purpose

Harness Scorecard is a read-only linter and A–F maturity grader for Claude Code
and Codex harnesses. The runtime is Python stdlib-only, with a Python 3.12 floor.

## Layout

- `src/harness_scorecard/`: discovery, checks, scoring, CLI, and report renderers.
- `tests/`: unittest suite and inert harness fixtures.
- `examples/`: sample harnesses and red-team fixture pairs.
- `docs/`: rubric, release checklist, and supporting contracts.
- `.github/workflows/`: CI and publishing; follow its local `AGENTS.md` too.

## Setup

Use uv 0.13.0; `.python-version` pins managed Python 3.14.7 for development.
From the repository root, run `make setup` to install locked dependencies.
Never refresh the lockfile just to verify a change.

## Checks

Run `make check` for lock freshness, formatting, lint, source-only types, and
the unittest suite with branch coverage (90.33% minimum). `make test` runs only
the coverage tests. CI covers Python 3.12–3.15, all required. Keep tests on unittest and type-check only `src/`.

For a safe CLI smoke, run:

```bash
uv run --no-sync harness-scorecard scan tests/fixtures/strong_harness --min-grade A
```

Fixtures do not execute hooks or connect to providers. Use repository fixtures
for verification, not personal harness directories or machine-wide fleet scans.
For HTML/report changes, follow the conditional browser checks in
[README Development](README.md#development).

## Boundaries

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

For `publish.yml`, keep `id-token: write` scoped to the publish job and guarded
by the `pypi` environment. Keep the semver release-tag trigger and release docs
aligned with the PyPI trusted-publisher fields. Manual dispatch still requires
review of the environment claim and intended ref. See
[workflow instructions](.github/workflows/AGENTS.md).

For docs-only PRs, comment only when docs claim a grade, safety property,
permission boundary, release state, or output format that is not supported by
the reviewed code or workflows.

## Delivery

Keep changes small and scoped; preserve unrelated work. Report actual commands
and results, and distinguish local verification from CI, publishing, and human
acceptance. `make build` creates local distributions; publishing is separate and
must follow [the release checklist](docs/RELEASE.md). Keep generated reports,
coverage data, and distributions out of commits.

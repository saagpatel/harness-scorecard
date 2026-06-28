# Changelog

All notable changes to Harness Scorecard are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **`diff` mode** — `harness-scorecard diff <baseline> <current>` compares two scorecards and
  reports what changed: which checks flipped, which dimension scores moved, and whether a
  capability gate newly trips. Each argument is either a live harness directory or a saved JSON
  report (`scan --json`), so one command covers a CI regression gate, a before/after audit, and
  drift between snapshots. Exit codes: `0` no regression · `1` grade regressed · `2` invalid
  input. Console and JSON output, both fully redacted.
- **GitHub Action `baseline` input** — point it at a committed JSON scorecard and the action
  fails the job on any grade regression, so a PR that weakens the harness can't merge.
- **`report.from_dict()`** — reconstructs a `Scorecard` from a saved JSON report (the inverse of
  `to_dict()`), with a clear `ValueError` on malformed input.

## [1.0.1] - 2026-06-27

Patch release: hardening and consistency fixes from a full-codebase audit. No change to
grading behavior for well-formed harnesses.

### Fixed

- **Graceful degradation** — a malformed `settings.json` with a null or non-list hook event
  (e.g. `"hooks": {"PreToolUse": null}`) no longer raises `TypeError` during the settings/local
  merge; it degrades to an empty inventory as the contract promises.
- **Privacy** — the "no harness found" error path now redacts the home path before writing to
  stderr, so a real path can't leak into CI logs.
- **Scoring** — a dimension whose checks are all N/A is excluded from the overall score instead
  of counted as a zero (latent edge case; no effect on current harnesses).
- **Output consistency** — `check.title` is now redacted in the console and JSON renderers (it
  was already redacted in HTML and SARIF), and the `[GATE]` label uses the same predicate in
  every renderer.

### Changed

- Trove classifier bumped to `Development Status :: 5 - Production/Stable` to match the GA.
- `docs/rubric.md` §5 reordered to D1–D10 and minor check-title wording aligned with the code.

## [1.0.0] - 2026-06-27

First public release. A read-only A–F maturity grader for coding-agent harness
configurations, covering both Claude Code and Codex against a single red-team rubric.

### Added

- **Rubric engine** — 10 weighted dimensions scored PASS / PARTIAL / FAIL / N/A into a
  weighted, gated, A–F-banded grade. Capability gates cap the grade when a critical guard is
  missing (no amount of cheap checks earns an A past an open front door).
- **Bypass-aware effective floor** — the moat. Credits only guards that actually fire:
  Claude Code's `autoMode.hard_deny` is discounted under `bypassPermissions`; the same insight
  maps to Codex's `sandbox_mode = "danger-full-access"` + `approval_policy = "never"`.
- **Claude Code adapter** — all 10 dimensions (31 `HS-*` checks) over `settings.json`,
  `hooks`, `rules/*.md`, `agents/`, `skills/`, and `CLAUDE.md`.
- **Codex adapter** — all 10 dimensions (24 `CDX-*` checks) over `config.toml` (sandbox,
  approval policy, trust levels, env policy, agents), `hooks.json`, and `AGENTS.md`. Parses
  TOML with the standard-library `tomllib`.
- **Auto-detection** — `scan` identifies Claude Code vs Codex by the config files present;
  `--type {auto,claude-code,codex}` forces it.
- **Output formats** — human console report, JSON, a self-contained HTML scorecard, and
  **SARIF 2.1.0** for GitHub code scanning (`--format`, `--json`, `--html`, `--sarif`).
- **CI gate** — `--min-grade {A,B,C,D,F}` (default `B`) controls the exit code so the tool
  doubles as a tunable build gate.
- **GitHub Action** — a composite action that grades a harness, uploads SARIF (even on a
  failing grade), and enforces a minimum grade; SHA-pinned and shell-injection-safe.
- **Privacy by construction** — inputs are read-only; every emitted string (console, JSON,
  HTML, SARIF) redacts home paths, secrets, tokens, and emails. Nothing leaves the machine.
- **Dependency-free runtime** — standard library only (Python ≥ 3.12); a tool that grades
  supply-chain hygiene carries no third-party runtime surface of its own.
- **Distribution** — `uv_build` packaging with a `harness-scorecard` console script, MIT
  license, `py.typed` marker, and a `--version` that reports both the package and rubric
  versions.

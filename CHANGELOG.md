# Changelog

All notable changes to Harness Scorecard are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

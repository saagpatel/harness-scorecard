# Changelog

All notable changes to Harness Scorecard are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.5.0] - 2026-06-28

### Added

- **`explain <CHECK_ID>` command** — bridges a scan finding to its rationale. Given any check id
  (`HS-D4-01`, `CDX-D1-01`, …, case-insensitive) it prints the check's metadata, the documented
  red-team **failure mode** it guards against, the **remediation**, and — for the six capability
  gates — a pointer to the vulnerable/guarded **proof** pair in `examples/redteam/`. `--format
  json` emits the same content for tooling; an unknown id exits 2 with the list of valid ids.
- **Failure-mode registry (`failure_modes.py`)** — a threat narrative for *every* check, keyed by
  its stable id and shipped in-package (so `explain` works from an installed wheel, where
  `docs/` and `examples/` are not present). A meta-test asserts the registry covers exactly the
  registered checks, so a new check can't ship without a narrative and a retired id can't leave a
  dangling entry.

Read-only and pure: `explain` reads the in-code check catalog and narrative registry, never the
audited harness. The rubric is unchanged at **1.0.0**.

## [1.4.0] - 2026-06-28

### Added

- **Red-team validation corpus (`examples/redteam/`)** — the rubric's central claim ("every
  gated check traces to a documented red-team failure mode") is now *proven*, not just asserted.
  Each of the six capability gates ships a vulnerable/guarded pair of static config fixtures: a
  plausible, otherwise-strong harness missing exactly one guard, beside its fixed twin. Covers
  Claude Code (`HS-D1-01`→D, `HS-D4-01`→C, `HS-D5-01`→C) and Codex (`CDX-D1-01`→D, `CDX-D4-01`→C,
  `CDX-D5-01`→C). Every entry carries an `ATTACK.md` (threat narrative + the gate that catches it
  + the one-line fix); defensive only — the fixtures are inert config and nothing executes.
- **`tests/test_redteam_corpus.py`** — a data-driven proof that mechanically FAILs each gated
  check on its `vulnerable/` config (gate present in `gate_caps`, grade capped) and PASSes it on
  `guarded/`. For five of six, the vulnerable harness scores in the A band on raw signal and is
  dragged to the cap by that single gate; `codex-d4` is documented as the cascade exception.
- **`docs/rubric.md`** back-links each gate to its corpus entry (claim ↔ proof), and the README
  gains a **"Proven, not asserted"** section.

The rubric is unchanged at **1.0.0** — this release proves existing checks, it does not add or
reweight any, so grades stay directly comparable to prior releases.

## [1.3.0] - 2026-06-28

### Added

- **`fleet` command** — grade several harnesses at once and report the grade distribution, the
  weakest dimension *across the whole fleet*, and the worst offender. Pass paths or globs
  (`fleet ~/.claude ~/Projects/*/.claude`); each is graded with its own auto-discovered policy.
  No rolled-up letter grade (averaging A–F is meaningless) — the distribution and the floor are
  shown instead. Console + JSON; `--min-grade` exits non-zero if any harness is below the bar; a
  path that isn't a harness is skipped with a note, never aborting the run.
- **`scan --badge FILE`** — emit a flat SVG grade badge (colored A green → F red) for a harness
  repo's README. Dependency-free; carries only the label and the letter, nothing to redact.

## [1.2.0] - 2026-06-28

### Added

- **Operator policy file (`.harness-scorecard.toml`)** — auto-discovered in the harness directory
  or passed with `--policy`, with two mechanisms that are always surfaced in the report:
  - **Waivers** (`[[waiver]]`) accept a known finding with a reason. The waived check is excluded
    from the grade and its capability-gate cap is suppressed, but it's shown as `[WAIV]` with the
    reason. Stale waivers (a check that passes or doesn't exist) are reported as policy notes,
    never silently dropped. In SARIF a waived finding is emitted with a `suppressions` entry so it
    stays visible but doesn't alert.
  - **Dispatcher manifest** (`[dispatcher].credits`) credits checks that an opaque dispatcher
    enforces but the static checks can't see. A declared check that would FAIL is upgraded to
    PARTIAL (half credit) and marked "dispatcher-credited" — declared, not statically verified.
- **`examples/harness-scorecard.toml`** — a documented policy-file template.
- **Codex check `CDX-D4-04` — trusted-project breadth** — counts `[projects.*].trust_level =
  "trusted"` entries (each suppresses approval prompts in its directory): a bounded set passes,
  >25 is PARTIAL, >100 FAIL; N/A when `approval_policy = "never"` already removes the gate
  globally. Catches an approval floor quietly eroded across hundreds of trusted directories.

## [1.1.0] - 2026-06-28

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
- **Dispatcher caveats in the report** — when a harness routes tool events through an opaque hook
  dispatcher (e.g. `pre_tool_use_dispatch.py`), the named-guard checks can't see inside it and
  under-credit. The report now surfaces a caveat in every format (console, JSON, HTML, SARIF) so a
  low score reads as "not statically visible," not "insecure." The grade is unchanged — only the
  framing is added. Detection is conservative (explicit `dispatch`/`router`/`run-hooks` idioms on
  tool-gating events), so a normally-named guard is never mislabeled.
- **`examples/sample-harness/`** — a committed, deliberately-imperfect example harness, scanned in
  the README's lead "What it looks like" excerpt and reproducible with `scan examples/sample-harness`.

### Fixed

- **Redaction false positive** — ordinary words beginning with a key prefix (`skill-provenance`,
  `pkcs11`) were mangled to `[redacted-secret]` in reports. Real prefixed keys carry a `-`/`_`
  separator after the prefix; the matcher now requires it (AWS `AKIA` ids stay matched separately).

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

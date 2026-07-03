# Changelog

All notable changes to Harness Scorecard are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **HS-D10-03 peer-agent branch receipt discipline.** The scorer now uses read-only git and
  bridge-db access to flag `codex/*` or `cc/*` branches that have commits ahead of `main` but no
  matching `activity_log.branch` receipt for the repo. The check is suggest-only, non-gating, and
  shared with the Codex adapter because it grades repo proof receipts rather than harness syntax.
  Rubric bumped to 1.1.0.

## [1.11.0] - 2026-06-28

### Added

- **Dispatcher introspection now covers every maskable check, across all dimensions.** Seeded
  `dispatcher_evidence` on the last seven checks whose guard can hide behind an opaque dispatcher:
  write-time secret scan (HS-D1-03), network-egress Bash guard (HS-D2-01), destructive-DB guard
  (HS-D4-03), dependency-install gate (HS-D4-04), subagent scope-linter (HS-D7-03),
  defer-destructive posture (HS-D8-02), and the skill-install provenance gate (HS-D9-01). With
  this, the only unseeded checks are the ones introspection *cannot* improve on — settings
  deny-rules, env vars, matcher-coverage checks, and hooks on events outside the scanned set
  (`SessionStart` / `PreCompact` / `SubagentStop` / failure events) are visible directly. HS-D7-03
  and HS-D8-02 are AND-checks with only one dispatcher-scannable half, so detection lifts them
  FAIL → PARTIAL, never to PASS.
- Each signature stays anchored to a code construct, and the per-pattern oracle test was extended
  to pin the new anti-false-credit boundaries — an auth `confirm_token`, a `pip install` subprocess
  exec, a `curl user@host` URL, and a `tool_name == "semgrep"` route all match nothing. Rubric
  unchanged at 1.0.0.

## [1.10.0] - 2026-06-28

### Added

- **Dispatcher introspection now covers the rest of the maskable Claude (HS-*) checks.** Seeded
  `dispatcher_evidence` on six more checks whose guard can hide behind an opaque dispatcher:
  inbound-injection sentinels (HS-D3-02), harness config write/read protection (HS-D5-01),
  hook-integrity verify/self-heal (HS-D5-02), config snapshot/validate (HS-D5-03), tool-call audit
  logging (HS-D10-01), and the sensitive-read Bash backstop (HS-D1-02). A Claude harness that routes
  these guards through one dispatcher now gets the same suggest-by-default / `--credit-detected`
  treatment the destructive-git checks already had. HS-D5-01 is a capability gate, so it is only
  ever *suggested*, never auto-credited. Rubric unchanged at 1.0.0.
- Every seeded signature is anchored to a code construct (a named regex/identifier, a call, a path
  literal, or a guard-name idiom) rather than prose, and a per-pattern test pins the
  anti-false-credit boundary — a generic verb (`sanitize_path`), a bare file extension
  (`training_data.jsonl`), or a config path shared with a different guard does not credit a check it
  doesn't implement.

## [1.9.0] - 2026-06-28

### Changed

- **Dispatcher-introspection evidence now lives on the checks.** The per-check guard signatures
  that `--credit-detected` matches moved out of a hardcoded table in `introspect.py` and onto each
  check as a `dispatcher_evidence` field. The signature lives with the check it belongs to, so it
  can't drift out of sync, and a new check is covered the moment it declares one — the introspector
  is now harness-agnostic rather than Codex-keyed. No behavior change for existing Codex scans.

### Added

- **Dispatcher introspection now covers Claude (HS-*) checks, not just Codex.** Seeded
  `dispatcher_evidence` on the Claude destructive-git checks (protected-branch push, catastrophic
  `rm -rf`, force-push), so a Claude harness that routes its git/destructive guards through an
  opaque dispatcher gets the same suggest-by-default / `--credit-detected` treatment Codex does.
  The protected-branch check is a capability gate, so it is only ever *suggested*, never
  auto-credited. Rubric unchanged at 1.0.0.

### Added

- **`scan --credit-detected`** and dispatcher introspection — the scorer now reads an opaque
  dispatcher's source itself instead of relying solely on a hand-written manifest. For each check
  whose guard lives behind a dispatcher, it looks for that guard's code signature (a named regex,
  a guard call) in the dispatcher script and its in-directory siblings. By default a find is a
  **suggestion** (a policy note: "evidence at `file:line` — verify and add to `[dispatcher].credits`,
  or re-run with `--credit-detected`"), so the grade never moves silently. Passing
  `--credit-detected` applies the finds as PARTIAL credits, rendered `(dispatcher-detected)` to
  stay distinct from a hand-verified `(dispatcher-credited)` manifest entry (new `credit_source`
  field in the JSON report).

  Detection is deliberately conservative — a source match is evidence, not proof: comment and
  triple-quoted docstring mentions are ignored, scanned paths are confined to the harness
  directory (a `..` token can't escape it), only security-event dispatchers are read, and a
  capability gate is **never** auto-credited (lifting a grade floor still requires a verified
  manifest entry). Rubric unchanged at 1.0.0.

## [1.7.0] - 2026-06-28

### Added

- **`scan --summary FILE`** — writes a GitHub-flavored Markdown report (grade headline, a
  capability-gates-tripped table, and every failing finding with its red-team failure mode and
  fix) suitable for a CI step summary. Point it at `$GITHUB_STEP_SUMMARY` and a red check
  explains itself on the PR's run page — no log-diving:

  ```yaml
  - run: harness-scorecard scan .claude --summary "$GITHUB_STEP_SUMMARY" --min-grade B
  ```

  A side-output like `--html`/`--sarif`/`--badge`, but it **appends** (the step summary
  accumulates across job steps) and draws its "why" from the same in-package narrative registry
  as `explain` / `scan --explain`. Table cells and blockquotes are escaped so a finding can't
  break the Markdown. The rubric is unchanged at **1.0.0**.

## [1.6.0] - 2026-06-28

### Added

- **`scan --explain`** — folds the one-line red-team failure mode inline next to every finding
  that isn't passing (FAIL/PARTIAL), so the *why* rides along with the grade and no second
  command is needed. Draws from the same in-package narrative registry as the `explain` command,
  printed as a `why:` line above each `fix:`. Console output only; the flag is a no-op for
  `--format json` (the structured report is unchanged). The rubric is unchanged at **1.0.0**.

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

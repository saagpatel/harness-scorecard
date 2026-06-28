# Roadmap

Harness Scorecard 1.0 grades Claude Code and Codex harness configs against a 10-dimension
red-team rubric. This is the candidate backlog beyond 1.0 — ordered by leverage, not commitment.

## Near-term (1.1)

- **`--diff` / grade-delta** — grade two configs (or the same config over time) and report what
  changed: which checks flipped, which dimension scores moved, whether a gate newly trips. The
  obvious CI use: fail a PR that *lowers* the harness grade.
- **Baseline / waiver file** — a `.harness-scorecard.toml` that records accepted findings
  (with a reason) so a known, deliberate gap stops re-surfacing as noise. Waivers are listed in
  the report, never silently hidden.
- **Dispatcher escape hatch** — the honest limit today is that an opaque hook dispatcher
  (`pre_tool_use_dispatch.py`) hides its security logic from static analysis, so it under-grades.
  Let a harness declare, in a small manifest, what its dispatcher enforces, so the grader can
  credit it without executing anything. Keeps the tool static while closing the under-credit gap.
- **Codex trust-level discipline (D4)** — a dedicated check on `[projects.*].trust_level`: a
  harness that marks hundreds of directories `trusted` has quietly eroded its approval floor.
  (The signal that prompted this: a real `~/.codex` with 343 trusted projects.)

## Mid-term (1.x)

- **More adapters** — Cursor, Aider, Continue, Gemini CLI. The engine, rubric, scoring, and all
  four renderers are already harness-agnostic; each new harness is an adapter + a check suite,
  exactly as Codex was.
- **Rubric profiles** — `--profile strict|baseline` to tune weights/gates for different risk
  postures (a solo side-project vs. an agent with production credentials).
- **Deeper Codex coverage** — `web_search` cache semantics, per-MCP-server egress surface,
  `writable_roots` breadth scoring, and `[shell_environment_policy]` allow/deny granularity.
- **Shareable grade badge** — an SVG/endpoint badge (`grade: A`) for a harness repo's README,
  generated from the JSON report.

## Longer-term / exploratory

- **Opt-in runtime mode** — the rubric already tags RUNTIME-detectability signals and refuses to
  fold them into a static grade. An explicit, sandboxed `--runtime` pass could confirm a few of
  them (does the deny actually block?) and surface them as a separate, clearly-labeled section.
- **Fleet view** — grade every harness on a machine (or across a team) and report the
  distribution, the weakest dimension org-wide, and drift over time.
- **Rubric as a versioned spec** — publish `docs/rubric.md` as a citable, versioned standard so
  a grade is reproducible against a named rubric release independent of the tool version.

## Non-goals (deliberately out of scope)

- Grading the *repository* an agent works on, or the *quality of agent output* — that is a
  different subject with a different rubric.
- Executing the harness or the agent to grade it. The tool stays static-by-default; anything
  requiring execution is opt-in, sandboxed, and never silently folded into the grade.
- Auto-fixing a harness. The tool reports and explains; it never mutates the harness it audits.

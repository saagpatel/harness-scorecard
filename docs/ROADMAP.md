# Roadmap

Harness Scorecard 1.0 grades Claude Code and Codex harness configs against a 10-dimension
red-team rubric. This is the candidate backlog beyond 1.0 — ordered by leverage, not commitment.

## Recently landed

- **`--diff` / grade-delta** — shipped in 1.1.0.
- **Baseline / waiver file** — shipped in 1.2.0.
- **Dispatcher escape hatch** — shipped in 1.2.0.
- **Codex trust-level discipline (D4)** — shipped as `CDX-D4-04` in 1.2.0. The
  check counts `[projects.*].trust_level = "trusted"` entries and reports broad
  trust surfaces as approval-floor erosion.

## Near-term

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

# Codex routing-fact monitor

`harness-scorecard` grades configuration statically. Maintainers can separately check whether the
official Codex config schema or the installed model catalog has drifted beyond the facts assumed by
the routing rubric:

```bash
uv run --no-sync python -m harness_scorecard.codex_routing_facts
```

The command is read-only. It fetches the official config schema over HTTPS, runs
`codex debug models`, and retains only model slugs and supported reasoning-effort names. Model
instructions and other catalog payloads are ignored.

Exit codes are `0` for current, `1` for detected drift, and `2` when either source is unavailable
or malformed. `--format json` produces a stable report for scheduled monitoring. Fixture paths can
be supplied with `--schema-file` and `--catalog-file` for offline testing.

This report is maintainer evidence only. `static_grade_affected` is always `false`, and neither
live source is read by `harness-scorecard scan` or folded into a score.

# Red-team validation corpus

> The rubric claims every gated check traces to a real red-team failure mode. This corpus
> **proves it.** Each entry is a vulnerable/guarded pair of static config fixtures; the scorer
> FAILs the gated check on `vulnerable/` and PASSes it on `guarded/`. The proof is mechanical
> and lives in [`tests/test_redteam_corpus.py`](../../tests/test_redteam_corpus.py).

## Defensive only

Nothing here executes. These are **configuration** fixtures — a `vulnerable/` harness is a
plausible, otherwise-strong config that is *missing exactly one guard*; its `guarded/` twin
adds it back. The "attack" is described in prose in each `ATTACK.md`; the test demonstrates
**detection**, never exploitation.

## Phase 1 — the six capability gates

The gated checks are the ones that *cap* the grade no matter how good the rest of the harness
is. Each pair isolates one gate:

| Mode | Adapter | Gated check | Caps at | The one removed guard |
|---|---|---|---|---|
| [`claude-d1-credential-exposure`](claude-d1-credential-exposure/ATTACK.md) | Claude Code | `HS-D1-01` | **D** | `Read(...)` denies for `~/.ssh`/`~/.aws`/`~/.gnupg`/op/gcloud/`.env` |
| [`claude-d4-inert-harddeny`](claude-d4-inert-harddeny/ATTACK.md) | Claude Code | `HS-D4-01` | **C** | a real PreToolUse git-safety hook (under bypass, `hard_deny` is inert) |
| [`claude-d5-unprotected-config`](claude-d5-unprotected-config/ATTACK.md) | Claude Code | `HS-D5-01` | **C** | the read- and write-path config guards |
| [`codex-d1-env-secret-leak`](codex-d1-env-secret-leak/ATTACK.md) | Codex | `CDX-D1-01` | **D** | the default secret-env excludes |
| [`codex-d4-full-access`](codex-d4-full-access/ATTACK.md) | Codex | `CDX-D4-01` | **C** | the effective floor (sandbox + approval + git hook) |
| [`codex-d5-self-mutable`](codex-d5-self-mutable/ATTACK.md) | Codex | `CDX-D5-01` | **C** | keeping `~/.codex` out of `writable_roots` |

For five of the six, the `vulnerable/` harness scores in the **A band on raw signal** and is
dragged down to the cap by the single failing gate — the cleanest possible demonstration that
the gate, not general weakness, is what bit. The sixth (`codex-d4`) grades **F** because
Codex's bypass knobs are load-bearing across D1/D4/D5 at once; its `ATTACK.md` explains why,
and the gate still fires.

## See it yourself

```bash
# Grade a vulnerable harness — note the gate cap in the output
harness-scorecard scan examples/redteam/claude-d4-inert-harddeny/vulnerable
harness-scorecard scan examples/redteam/claude-d4-inert-harddeny/guarded

# Or diff the pair to see the grade move
harness-scorecard diff \
  examples/redteam/claude-d4-inert-harddeny/vulnerable \
  examples/redteam/claude-d4-inert-harddeny/guarded
```

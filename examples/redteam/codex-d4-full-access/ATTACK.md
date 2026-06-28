# Codex — D4: the effective bypass (`danger` + `never`)

**Failure mode:** Codex's analog of Claude's `bypassPermissions` — `sandbox_mode =
"danger-full-access"` *and* `approval_policy = "never"` with no Bash git hook — leaves
destructive commands (`rm -rf`, `git push --force`) running entirely unchecked.
**Gated by:** [`CDX-D4-01`](../../../docs/rubric.md) — a failing result caps the grade at **C**.
**Adapter:** Codex (`config.toml` → `sandbox_mode` + `approval_policy`, `hooks.json`).

## The attack

Codex gates destructive actions through three independent layers: the filesystem **sandbox**,
the human **approval policy**, and PreToolUse **Bash hooks**. Remove all three and there is
nothing between the model and your disk:

```toml
approval_policy = "never"            # no human in the loop
sandbox_mode    = "danger-full-access"  # no filesystem bound
# ...and no Bash git-safety hook
```

`CDX-D4-01` is the bypass-aware check: it passes only when **at least two** layers survive.
At zero layers it FAILs and caps the grade at C.

## What the scorecard sees — and a note on Codex's cascade

- `vulnerable/` runs `never` + `danger-full-access` with a hook set that has no git guard →
  `CDX-D4-01` **FAIL** → gate caps at **C**.
- `guarded/` restores `on-request` + `workspace-write` and the git-safety hook → two-plus
  layers → `CDX-D4-01` **PASS** → grade **A**.

Unlike the Claude gates — where one removed guard drops an otherwise-A harness to exactly the
cap — the Codex `vulnerable/` here grades **F**, *below* the C cap. That is not a bug in the
corpus; it is a true property of Codex worth seeing. The same two knobs (`sandbox_mode`,
`approval_policy`) are **load-bearing across D1, D4, and D5 simultaneously**: turning them
both off also fails the sandbox-blast-radius check (`CDX-D1-03`), the approval-granularity
check (`CDX-D4-03`), and the self-mutation gate (`CDX-D5-01`). The effective bypass doesn't
weaken one guard — it dissolves the whole floor at once. The gate still fires and still caps
at C; it simply isn't the *sole* reason the grade is low, because in Codex a full bypass is a
multi-dimension failure by construction.

## The diff (restoring the effective floor)

```diff
- approval_policy = "never"
- sandbox_mode    = "danger-full-access"
+ approval_policy = "on-request"
+ sandbox_mode    = "workspace-write"
```
…and restore the PreToolUse Bash `git-safety` hook in `hooks.json`.

## The fix

Keep `approval_policy` off `never` **or** `sandbox_mode` off `danger-full-access` — ideally
both — and add a PreToolUse Bash hook for git/destructive commands. Two independent layers is
the floor; the third is defense in depth.

---
*Defensive corpus. Static config fixtures only — nothing executes. The proof is mechanical:
the scorer FAILs `CDX-D4-01` on `vulnerable/` (and the gate appears in `gate_caps`) and PASSes
it on `guarded/`. Asserted in `tests/test_redteam_corpus.py`.*

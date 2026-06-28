# Claude Code — D4: the inert `hard_deny` (the flagship)

**Failure mode:** a harness that *looks* protected against pushing to `main` isn't, because
its protection is declared only in `autoMode.hard_deny` while it runs `bypassPermissions` —
under which `hard_deny` is **inert**.
**Gated by:** [`HS-D4-01`](../../../docs/rubric.md) — a failing result caps the grade at **C**.
**Adapter:** Claude Code (`settings.json` → `permissions.defaultMode` + `hooks`).

## The attack

This is the failure mode the whole scorecard exists for. An operator runs `bypassPermissions`
for velocity and writes a confident five-rule `autoMode.hard_deny` block:

```json
"autoMode": { "hard_deny": ["Push to main or master", "..."] }
```

It reads like a guarantee. It is not. `autoMode.hard_deny` only enforces when
`defaultMode != bypassPermissions`. Under bypass, the **effective floor** is
`permissions.deny` globs plus the PreToolUse hooks — *only*. The hard_deny block fires
nothing. The agent (or an injection) runs `git push origin main` and it goes through.

A naive linter reads the rich hard_deny block and awards an A. That grade is a lie, and it
is the exact lie this tool refuses to tell.

## What the scorecard sees

Both `vulnerable/` and `guarded/` run `bypassPermissions` and carry the *same*
`hard_deny` block listing "Push to main or master". The difference is one hook:

- `vulnerable/` has **no** PreToolUse `Bash` `git-safety` hook → the effective floor is empty
  → `HS-D4-01` **FAIL** → grade capped at **C** (raw signal 0.94).
- `guarded/` adds the hook → the floor blocks the push → `HS-D4-01` **PASS** → grade **A**.

The hard_deny block is identical in both. The scorer never credits it under bypass — proving
it computes against the effective floor, not the declared one.

## The one-guard diff

```diff
  "PreToolUse": [
    { "matcher": "Bash", "hooks": [
        { "type": "command", "command": "${DIR}/hooks/block-dangerous-cmds.sh" },
+       { "type": "command", "command": "${DIR}/hooks/git-safety.sh" },
        { "type": "command", "command": "${DIR}/hooks/db-guard.sh" }
    ]}
  ]
```

## The fix

Encode protected-branch blocking in the **effective floor**: a PreToolUse `Bash` hook (or a
`permissions.deny` entry), not `hard_deny` alone. If you must run `bypassPermissions`, every
rule you care about has to live in `permissions.deny` or a hook — treat `hard_deny` as
documentation, because under bypass that is all it is.

---
*Defensive corpus. Static config fixtures only — nothing executes. The proof is mechanical:
the scorer FAILs `HS-D4-01` on `vulnerable/` and PASSes it on `guarded/`, with an identical
`hard_deny` block in both. Asserted in `tests/test_redteam_corpus.py`.*

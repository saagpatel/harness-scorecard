# Codex — D1: secrets leaked into every subprocess

**Failure mode:** every shell command Codex runs inherits your API keys, tokens, and
passwords, because the default secret excludes were turned off.
**Gated by:** [`CDX-D1-01`](../../../docs/rubric.md) — a failing result caps the grade at **D**.
**Adapter:** Codex (`config.toml` → `[shell_environment_policy]`).

## The attack

Codex's filesystem sandbox bounds *writes*, but every command it spawns runs in an
environment. By default Codex scrubs secret-looking variables (names matching
`KEY`/`SECRET`/`TOKEN`/`PASSWORD`/`CREDENTIAL`) out of that environment. Set
`ignore_default_excludes = true` — often done to pass through one needed variable — and the
scrubbing is gone: `AWS_SECRET_ACCESS_KEY`, `GITHUB_TOKEN`, `OPENAI_API_KEY`, and everything
else now flows into every `npm install`, every `curl`, every build script the agent runs.
A single malicious postinstall script or injected command reads them straight out of `env`.

This is an env-hygiene problem the sandbox can't fix — the sandbox bounds where bytes can be
*written*, not what secrets a command can *see*.

## What the scorecard sees

- `vulnerable/` sets `ignore_default_excludes = true` → secrets are exposed to every
  subprocess → `CDX-D1-01` **FAIL** → grade capped at **D** (raw signal 0.86).
- `guarded/` leaves it `false` (the default) → secrets scrubbed → `CDX-D1-01` **PASS** →
  grade **A**.

## The one-guard diff

```diff
  [shell_environment_policy]
  inherit = "core"
- ignore_default_excludes = true
+ ignore_default_excludes = false
  exclude = ["AWS_*", "*_TOKEN"]
```

## The fix

Leave `ignore_default_excludes` unset (it defaults to `false`), and never place a secret-named
variable in `[shell_environment_policy.set]`. If you need exactly one variable passed through,
add *it* to an allowlist — don't disable the whole exclude set. Back it with a credential-read
guard hook (`CDX-D1-02`), since the sandbox still permits *reading* `~/.ssh` and `~/.aws`.

---
*Defensive corpus. Static config fixtures only — nothing executes. The proof is mechanical:
the scorer FAILs `CDX-D1-01` on `vulnerable/` and PASSes it on `guarded/`. Asserted in
`tests/test_redteam_corpus.py`.*

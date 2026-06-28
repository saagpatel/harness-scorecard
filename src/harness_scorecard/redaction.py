"""Privacy-preserving redaction for all emitted output.

The scorer reads real harness configs but must never leak secrets, tokens, emails, or
user-identifying absolute paths into its reports. Redaction is applied at the rendering
boundary so nothing sensitive reaches console / JSON / HTML.
"""

from __future__ import annotations

import os
import re

_HOME = os.path.expanduser("~")  # noqa: PTH111 - intentional: compare against $HOME literally

_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
# Long opaque strings that look like secrets/tokens/keys: >= 24 base64-ish chars AND
# containing at least one digit. The digit requirement avoids redacting long but
# digit-free identifiers (e.g. a harness directory name), which are not secrets.
_TOKEN = re.compile(r"\b(?=[A-Za-z0-9_\-]*\d)[A-Za-z0-9_\-]{24,}\b")
# Common key prefixes worth redacting even when short / digit-free. The alphabetic prefixes
# (sk/pk/gh*/xox*) are always followed by a ``-``/``_`` separator in real keys (``sk-ant-…``,
# ``sk_live_…``, ``ghp_…``, ``xoxb-…``); requiring that separator avoids redacting ordinary words
# that merely start with those letters ("skill-provenance", "pkcs11"). AWS access-key ids
# (``AKIA`` + 16 uppercase alnum) carry no separator, so they are a distinct alternative.
_PREFIXED_SECRET = re.compile(
    r"\b(?:(?:sk|pk|ghp|gho|ghs|ghr|xox[baprs])[-_][A-Za-z0-9][-_A-Za-z0-9]{6,}"
    r"|AKIA[0-9A-Z]{16})\b"
)


def redact_path(path: str) -> str:
    """Collapse the user's home directory to ``~`` so absolute paths don't identify them.

    Requires a path separator after the home prefix so a sibling user whose name shares a
    prefix (``/Users/doppelganger`` vs home ``/Users/d``) is left untouched, not mangled.
    """
    if _HOME and (path == _HOME or path.startswith(_HOME + os.sep)):
        return "~" + path[len(_HOME) :]
    return path


def _redact_home(text: str) -> str:
    """Collapse the home dir to ``~`` wherever it appears in free text, not just as a prefix.

    The negative lookahead ``(?![\\w.-])`` requires the next character after the home prefix to
    be a path separator or boundary, so a sibling user (``/Users/doppelganger`` vs home
    ``/Users/d``) is left untouched. ``_HOME`` is read at call time so tests can monkeypatch it.
    """
    if not _HOME:
        return text
    return re.sub(re.escape(_HOME) + r"(?![\w.-])", "~", text)


def redact_text(text: str) -> str:
    """Redact emails, prefixed secrets, opaque tokens, and home paths from free text."""
    text = _redact_home(text)
    text = _EMAIL.sub("[redacted-email]", text)
    text = _PREFIXED_SECRET.sub("[redacted-secret]", text)
    return _TOKEN.sub("[redacted-token]", text)

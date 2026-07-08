"""Repo-level receipt discipline check.

This check is intentionally read-only: it inspects git refs and opens bridge-db in SQLite
``mode=ro`` to verify that peer-agent task branches have a matching activity receipt.
"""

from __future__ import annotations

import os
import re
import shutil
import sqlite3
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol
from urllib.parse import quote

from harness_scorecard.checks.base import Check, CheckOutcome, failed, not_applicable, passed
from harness_scorecard.models import Detectability, Severity

_PEER_BRANCH = ("codex/", "cc/")
_DEFAULT_BRIDGE_DB = Path.home() / ".local" / "share" / "bridge-db" / "bridge.db"
_BRIDGE_DB_ENV = "HARNESS_SCORECARD_BRIDGE_DB"
_REMOTE_RE = re.compile(r"(?:(?:git@|https://)([^/:]+)[:/])([^/]+)/([^/.]+)(?:\.git)?$")
_GIT = shutil.which("git") or "git"


class ReceiptConfig(Protocol):
    root: Path


@dataclass(frozen=True, slots=True)
class PeerBranch:
    name: str
    ref: str
    ahead: int


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(  # noqa: S603 - fixed git executable; args are not shell-expanded.
        (_GIT, "-C", str(repo), *args),
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    return result.stdout.strip()


def _git_root(path: Path) -> Path | None:
    try:
        return Path(_git(path, "rev-parse", "--show-toplevel"))
    except (OSError, subprocess.SubprocessError):
        return None


def _baseline_ref(repo: Path) -> str | None:
    for ref in ("origin/main", "main"):
        try:
            _git(repo, "rev-parse", "--verify", f"{ref}^{{commit}}")
        except (OSError, subprocess.SubprocessError):
            continue
        return ref
    return None


def _normalize_branch(ref: str) -> str | None:
    if ref.endswith("/HEAD"):
        return None
    branch = ref.removeprefix("origin/")
    if branch.startswith(_PEER_BRANCH):
        return branch
    return None


def _peer_branches_ahead(repo: Path, baseline: str) -> list[PeerBranch]:
    try:
        refs = _git(
            repo,
            "for-each-ref",
            "--format=%(refname:short)",
            "refs/heads",
            "refs/remotes",
        ).splitlines()
    except (OSError, subprocess.SubprocessError):
        return []

    by_branch: dict[str, str] = {}
    for ref in refs:
        branch = _normalize_branch(ref)
        if branch is not None:
            by_branch.setdefault(branch, ref)

    ahead: list[PeerBranch] = []
    for branch, ref in sorted(by_branch.items()):
        try:
            count = int(_git(repo, "rev-list", "--count", f"{baseline}..{ref}") or "0")
        except (OSError, subprocess.SubprocessError, ValueError):
            continue
        if count > 0:
            ahead.append(PeerBranch(branch, ref, count))
    return ahead


def _project_aliases(repo: Path) -> tuple[str, ...]:
    aliases = {repo.name.lower()}
    try:
        remote = _git(repo, "config", "--get", "remote.origin.url")
    except (OSError, subprocess.SubprocessError):
        remote = ""
    match = _REMOTE_RE.search(remote)
    if match:
        owner = match.group(2).lower()
        name = match.group(3).removesuffix(".git").lower()
        aliases.add(name)
        aliases.add(f"{owner}/{name}")
    return tuple(sorted(aliases))


def _bridge_db_path() -> Path:
    configured = os.environ.get(_BRIDGE_DB_ENV) or os.environ.get("BRIDGE_DB_PATH")
    return Path(configured).expanduser() if configured else _DEFAULT_BRIDGE_DB


def _connect_read_only(path: Path) -> sqlite3.Connection:
    uri = f"file:{quote(str(path))}?mode=ro"
    return sqlite3.connect(uri, uri=True)


def _receipt_exists(db_path: Path, branch: str, aliases: tuple[str, ...]) -> bool:
    sql = """
        SELECT 1
        FROM activity_log
        WHERE branch = ?
          AND (
            lower(project_name) = ?
            OR lower(coalesce(canonical_key, '')) = ?
          )
        LIMIT 1
    """
    with _connect_read_only(db_path) as db:
        for alias in aliases:
            if db.execute(sql, (branch, alias, alias)).fetchone() is not None:
                return True
    return False


def check_receipt_discipline(config: ReceiptConfig) -> CheckOutcome:  # noqa: PLR0911
    repo = _git_root(config.root)
    if repo is None:
        return not_applicable("No containing git worktree; receipt discipline is repo-scoped.")
    if config.root.resolve() != repo.resolve():
        return not_applicable(
            "Receipt discipline is repo-scoped and only applies when scanning a git worktree root."
        )

    baseline = _baseline_ref(repo)
    if baseline is None:
        return not_applicable("No main baseline ref found for receipt comparison.")

    branches = _peer_branches_ahead(repo, baseline)
    if not branches:
        return not_applicable("No codex/* or cc/* branches are ahead of main.")

    db_path = _bridge_db_path()
    if not db_path.exists():
        return not_applicable(f"Bridge activity database not found at {db_path}.")

    aliases = _project_aliases(repo)
    try:
        missing = [
            branch for branch in branches if not _receipt_exists(db_path, branch.name, aliases)
        ]
    except sqlite3.Error as exc:
        return not_applicable(f"Bridge activity database could not be read: {exc}.")

    if missing:
        evidence = [f"{branch.name} ({branch.ahead} commits ahead)" for branch in missing]
        return failed(
            "Peer-agent branches have commits ahead of main without matching bridge receipts.",
            evidence=evidence,
        )

    evidence = [f"{branch.name} ({branch.ahead} commits ahead)" for branch in branches]
    return passed("Every peer-agent branch ahead of main has a matching bridge receipt.", evidence)


RECEIPT_DISCIPLINE_CHECK: Check[ReceiptConfig] = Check(
    id="HS-D10-03",
    dimension="D10",
    title="Peer-agent branch receipt discipline",
    weight=1,
    evaluate=check_receipt_discipline,
    severity=Severity.LOW,
    detectability=Detectability.RUNTIME,
    remediation=(
        "Log bridge-db activity for each codex/* or cc/* branch that carries commits ahead of "
        "main, with the branch field set exactly to that branch name."
    ),
)

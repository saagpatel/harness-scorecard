"""D10 - Observability / audit trail checks."""

import os
import shutil
import sqlite3
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from harness_scorecard.discovery import HookEntry, load_harness
from harness_scorecard.models import Status
from tests.test_checks import get_check, make_config

FIXTURES = Path(__file__).parent / "fixtures"
GIT = shutil.which("git") or "git"


class TestD10OnFixtures(unittest.TestCase):
    def test_strong_passes_every_d10_check(self):
        config = load_harness(FIXTURES / "strong_harness")
        for cid in ("HS-D10-01", "HS-D10-02"):
            self.assertEqual(get_check(cid).run(config).status, Status.PASS, cid)

    def test_weak_fails_every_d10_check(self):
        config = load_harness(FIXTURES / "weak_harness")
        for cid in ("HS-D10-01", "HS-D10-02"):
            self.assertEqual(get_check(cid).run(config).status, Status.FAIL, cid)


class TestD1001AuditLogging(unittest.TestCase):
    def test_bash_only_is_partial(self):
        config = make_config(hooks=[HookEntry("PostToolUse", "Bash", "/h/bash-audit-log.sh")])
        self.assertEqual(get_check("HS-D10-01").run(config).status, Status.PARTIAL)

    def test_both_lanes_pass(self):
        config = make_config(
            hooks=[
                HookEntry("PostToolUse", "Bash", "/h/bash-audit-log.sh"),
                HookEntry("PostToolUse", "mcp__.*", "/h/mcp-audit-log.sh"),
            ]
        )
        self.assertEqual(get_check("HS-D10-01").run(config).status, Status.PASS)

    def test_mcp_audit_hook_on_bash_lane_does_not_credit_mcp(self):
        # A hook named mcp-audit-log but registered on the Bash lane logs Bash, not MCP.
        config = make_config(hooks=[HookEntry("PostToolUse", "Bash", "/h/mcp-audit-log.sh")])
        self.assertEqual(get_check("HS-D10-01").run(config).status, Status.PARTIAL)


class TestD1002FailureLogging(unittest.TestCase):
    def test_denial_only_is_partial(self):
        config = make_config(
            hooks=[HookEntry("PermissionDenied", "", "/h/permission-denied-log.sh")]
        )
        self.assertEqual(get_check("HS-D10-02").run(config).status, Status.PARTIAL)

    def test_both_categories_pass(self):
        config = make_config(
            hooks=[
                HookEntry("PermissionDenied", "", "/h/permission-denied-log.sh"),
                HookEntry("PostToolUseFailure", "", "/h/tool-failure-log.sh"),
            ]
        )
        self.assertEqual(get_check("HS-D10-02").run(config).status, Status.PASS)

    def test_non_logging_hook_under_event_is_not_credited(self):
        # A hook under the event that does not log/audit is not failure logging.
        config = make_config(
            hooks=[
                HookEntry("PermissionDenied", "", "/h/notify.sh"),
                HookEntry("PostToolUseFailure", "", "/h/notify.sh"),
            ]
        )
        self.assertEqual(get_check("HS-D10-02").run(config).status, Status.FAIL)


class TestD1003ReceiptDiscipline(unittest.TestCase):
    def _git(self, repo: Path, *args: str) -> str:
        result = subprocess.run(  # noqa: S603 - fixed git executable in isolated test repo.
            (GIT, "-C", str(repo), *args),
            check=True,
            capture_output=True,
            text=True,
        )
        return result.stdout.strip()

    def _commit(self, repo: Path, filename: str, body: str) -> None:
        (repo / filename).write_text(body, encoding="utf-8")
        self._git(repo, "add", filename)
        self._git(
            repo,
            "-c",
            "user.name=Harness Scorecard Tests",
            "-c",
            "user.email=tests@example.invalid",
            "commit",
            "-m",
            f"test: {filename}",
        )

    def _repo(self, tmp: Path) -> Path:
        repo = tmp / "demo-repo"
        repo.mkdir()
        subprocess.run(  # noqa: S603 - fixed git executable in isolated test repo.
            (GIT, "-C", str(repo), "init", "-b", "main"), check=True
        )
        self._commit(repo, "README.md", "base\n")
        return repo

    def _bridge_db(self, tmp: Path, rows: list[tuple[str, str]]) -> Path:
        db_path = tmp / "bridge.db"
        with sqlite3.connect(db_path) as db:
            db.execute(
                """
                CREATE TABLE activity_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    project_name TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    branch TEXT,
                    tags TEXT NOT NULL DEFAULT '[]',
                    canonical_key TEXT
                )
                """
            )
            for project, branch in rows:
                db.execute(
                    """
                    INSERT INTO activity_log
                      (source, timestamp, project_name, summary, branch, tags, canonical_key)
                    VALUES ('codex', '2026-07-03T00:00:00Z', ?, 'receipt', ?, '[]', NULL)
                    """,
                    (project, branch),
                )
        return db_path

    def _run_check(self, repo: Path, db_path: Path):
        config = make_config(root=repo)
        with patch.dict(os.environ, {"HARNESS_SCORECARD_BRIDGE_DB": str(db_path)}):
            return get_check("HS-D10-03").run(config)

    def test_branch_with_commits_and_receipt_passes(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            repo = self._repo(tmp)
            self._git(repo, "switch", "-c", "codex/with-receipt")
            self._commit(repo, "feature.txt", "work\n")
            db_path = self._bridge_db(tmp, [("demo-repo", "codex/with-receipt")])

            result = self._run_check(repo, db_path)

        self.assertEqual(result.status, Status.PASS)

    def test_branch_with_commits_and_no_receipt_fails(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            repo = self._repo(tmp)
            self._git(repo, "switch", "-c", "codex/no-receipt")
            self._commit(repo, "feature.txt", "work\n")
            db_path = self._bridge_db(tmp, [])

            result = self._run_check(repo, db_path)

        self.assertEqual(result.status, Status.FAIL)
        self.assertIn("codex/no-receipt", result.evidence[0])
        self.assertIsNone(result.triggered_gate_cap)

    def test_clean_peer_branch_is_not_applicable(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            repo = self._repo(tmp)
            self._git(repo, "switch", "-c", "codex/no-commits")
            db_path = self._bridge_db(tmp, [])

            result = self._run_check(repo, db_path)

        self.assertEqual(result.status, Status.NOT_APPLICABLE)


if __name__ == "__main__":
    unittest.main()

"""The publishing token is unavailable to build and test commands."""

import re
import unittest
from pathlib import Path


class TestPublishBoundary(unittest.TestCase):
    def test_only_upload_job_has_oidc(self):
        text = (Path(__file__).resolve().parents[1] / ".github/workflows/publish.yml").read_text()
        self.assertEqual(text.count("id-token: write"), 1)
        jobs = text.split("jobs:\n")[1]
        self.assertIn("  build:\n", jobs)
        build, publish = jobs.split("  publish:\n")
        self.assertIn("contents: read", build)
        self.assertNotIn("id-token:", build)
        self.assertNotIn("environment:", build)
        self.assertIn("make setup", build)
        self.assertIn("make check", build)
        self.assertIn("if-no-files-found: error", build)
        self.assertIn("retention-days: 1", build)
        self.assertIn("needs: build", publish)
        self.assertIn("environment: pypi", publish)
        self.assertIn("id-token: write", publish)
        self.assertNotIn("contents:", publish)
        self.assertNotIn("run:", publish)
        self.assertNotIn("checkout", publish)
        self.assertRegex(build, r"actions/upload-artifact@[0-9a-f]{40} # v")
        self.assertRegex(publish, r"actions/download-artifact@[0-9a-f]{40} # v")
        self.assertEqual(len(re.findall(r"uses:", publish)), 2)

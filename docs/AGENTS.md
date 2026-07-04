# AGENTS.md - Harness Scorecard Docs

## Review guidelines

Treat docs as user-facing contracts for a security and release tool. Review
claims about grades, read-only behavior, permission boundaries, exact output
formats, SARIF/JSON fields, exit codes, and release state against the current
code and workflows.

Release docs must stay synchronized with `.github/workflows/publish.yml`.
Trusted-publisher fields, `environment: pypi`, exact semver tag behavior,
manual dispatch behavior, and `v1` tag movement are merge-relevant.

Rubric and roadmap docs should not overstate static analysis coverage. If a
check is heuristic, mode-dependent, or cannot prove runtime behavior, keep the
limitation visible in the doc.

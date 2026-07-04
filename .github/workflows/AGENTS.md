# AGENTS.md - Harness Scorecard Workflows

## Review guidelines

Treat workflows as mutation-boundary code. Review changes to triggers,
permissions, environments, concurrency, pinned actions, publish jobs, and
artifact publication paths as merge-relevant when they can broaden credentials,
publish unexpectedly, skip tests, or weaken release gates.

For `publish.yml`, keep `id-token: write` scoped to the publish job and guarded
by the `pypi` environment. The tag trigger should stay limited to exact semver
release tags unless the release docs and PyPI trusted-publisher claim are
updated together.

Manual `workflow_dispatch` does not make a publish path safe by itself. Review
must check the environment claim, PyPI trusted-publisher fields, and whether the
workflow can run on an unintended ref.

# Release Checklist

This repo publishes two surfaces:

- the Python package on PyPI: <https://pypi.org/project/harness-scorecard/>
- the composite GitHub Action: `saagpatel/harness-scorecard@v1`

## Normal Release

1. Update `pyproject.toml`, refresh `uv.lock`, and add the changelog entry.
2. Merge the release prep through a PR to `main`.
3. Confirm PyPI trusted publishing is configured for the exact GitHub identity:

   ```text
   Owner: saagpatel
   Repository name: harness-scorecard
   Workflow name: publish.yml
   Environment name: blank / empty
   ```

   Project settings page:
   <https://pypi.org/manage/project/harness-scorecard/settings/publishing/>

4. Create the exact release tag, for example `v1.13.0`.
5. Wait for the `Publish` GitHub Actions workflow to pass.
6. Verify the PyPI release page and JSON API show the new version and both artifacts.
7. Move the `v1` major tag to the same commit as the exact release tag. The
   publish workflow is intentionally filtered to exact semver tags
   (`v[0-9]+.[0-9]+.[0-9]+`), so moving `v1` should not attempt a second PyPI
   upload.
8. Create the GitHub release after PyPI is live.

## Trusted Publishing Failure

If the publish step fails with `invalid-publisher`, the GitHub OIDC token was valid
but PyPI could not find a trusted publisher matching its claims. Check the fields
above before changing workflow code.

The failure output prints useful claims:

- `repository`
- `repository_owner`
- `workflow_ref`
- `job_workflow_ref`
- `environment`
- `ref`

For this repo, `publish.yml` should not set a GitHub Actions environment unless
PyPI is also configured with that same environment name.

## Post-Release Readback

Use these checks before calling a release complete:

```bash
gh run list --repo saagpatel/harness-scorecard --workflow Publish --limit 3
gh release view vX.Y.Z --repo saagpatel/harness-scorecard
python -m pip index versions harness-scorecard
```

The exact version tag and the moving `v1` tag should both resolve to the release
commit. The `v1` tag is what the README and example workflow recommend for normal
GitHub Action consumers.

# Deploy to npm

`pii-safe-logger` publishes through `.github/workflows/publish.yml` using npm Trusted Publishing and GitHub OIDC. The workflow does not need an npm token.

## One-time npm setup

In the npm package settings for `pii-safe-logger`, add a GitHub Actions trusted publisher with:

- Owner: `uppy19d0`
- Repository: `pii-safe-logger`
- Workflow filename: `publish.yml`
- Environment: `npm`
- Allowed action: direct `npm publish`

The workflow filename is just `publish.yml`. Keep the GitHub `npm` environment configured. After a successful trusted release, revoke the old npm automation token and delete the `NPM_TOKEN` repository secret.

The repository variable `NPM_TRUSTED_PUBLISHING_ENABLED` keeps release and publish jobs disabled until npm setup is complete. Set it to `true` in GitHub Actions variables only after the trusted publisher is configured. Then manually run `Create GitHub Release` on `main` to publish the version prepared while the gate was closed. Leave the variable unset or `false` until npm is ready.

## Release

1. Update the package version and run `npm ci --ignore-scripts`, `npm audit --audit-level=high`, and `npm test`.
2. Merge through CI. The `Create GitHub Release` workflow creates the release, and its successful completion triggers `Deploy to npm`. You can also run the deploy workflow manually from `main`.
3. The deploy workflow skips a version that already exists. For a new version, it checks dependencies, tests, previews the package, and publishes with provenance.
4. Verify the new version and provenance attestation on npm.

Never move a published tag or reuse an npm version. Increment the version to fix a failed release.

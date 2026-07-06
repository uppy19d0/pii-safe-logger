# Deploy to npm

This repository publishes `pii-safe-logger` to npm through GitHub Actions.

## One-Time Setup

1. Revoke any npm token that was shared outside npm or GitHub Secrets.
2. Create a new npm token from npmjs.com.
3. In GitHub, open `Settings` > `Secrets and variables` > `Actions`.
4. Add a repository secret named `NPM_TOKEN`.
5. Paste the new npm token as the secret value.

## Automatic Deploy

Every push to `main` starts the deploy workflow. The workflow checks
`package.json` against npm before publishing.

- If the version already exists on npm, publishing is skipped.
- If the version does not exist on npm, the workflow runs tests and publishes it.

The package currently published on npm is `0.2.2`. If `package.json` contains
`1.0.0`, the workflow will publish `1.0.0` because it is a new version.

## Manual Deploy

1. Open the repository on GitHub.
2. Go to `Actions`.
3. Open `Deploy to npm`.
4. Click `Run workflow`.
5. Select branch `main`.
6. Click `Run workflow`.

The workflow will:

1. check out the code
2. set up Node.js
3. show the package name and version
4. check whether the version already exists on npm
5. install dependencies with `npm ci` when the version is new
6. run tests when the version is new
7. verify the npm token when the version is new
8. preview the package files
9. publish to npm with provenance
10. verify the published package version

## Release Deploy

Creating a GitHub release also runs the same deploy workflow:

1. Update `version` in `package.json`.
2. Commit and push the change.
3. Create a Git tag, for example `v1.0.1`.
4. Push the tag.
5. Create a GitHub Release from that tag.

## Important

Never commit npm tokens to this repository. The workflow reads the token only
from the GitHub secret named `NPM_TOKEN`.

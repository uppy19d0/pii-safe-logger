# Deploy to npm

This repository publishes `pii-safe-logger` to npm through GitHub Actions.

## One-Time Setup

1. Revoke any npm token that was shared outside npm or GitHub Secrets.
2. Create a new npm token from npmjs.com.
3. In GitHub, open `Settings` > `Secrets and variables` > `Actions`.
4. Add a repository secret named `NPM_TOKEN`.
5. Paste the new npm token as the secret value.

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
4. install dependencies with `npm ci`
5. run tests
6. verify the npm token
7. stop if the version already exists on npm
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

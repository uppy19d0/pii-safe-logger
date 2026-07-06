# pii-safe-logger

Small npm logger that redacts common PII before writing logs.

## Install

```bash
npm install pii-safe-logger
```

## Use

```js
import { createPiiSafeLogger } from "pii-safe-logger";

const logger = createPiiSafeLogger({ level: "info" });

logger.info("User signed in", {
  email: "ana@example.com",
  password: "super-secret",
  token: "abcd-1234"
});
```

### TypeScript

The package ships with TypeScript declarations, so this works without extra setup:

```ts
import { createPiiSafeLogger, maskPii } from "pii-safe-logger";

const logger = createPiiSafeLogger({ level: "debug" });
const safeValue = maskPii({ email: "ana@example.com" });

logger.info("payload", safeValue);
```

The library masks:

- common sensitive object keys like `password`, `token`, and `apiKey`
- email addresses
- SSNs
- phone numbers
- likely credit card numbers

## API

- `createPiiSafeLogger(options)` creates a logger with `debug`, `info`, `warn`, `error`, and `log`
- `maskPii(value, options)` returns a deep-masked copy of the value

## Deploy

See [DEPLOY.md](./DEPLOY.md) for the GitHub Actions pipeline and npm publishing
steps.

## Supply Chain Release Checklist

To publish with the strongest npm supply-chain signals:

1. Keep the source in the public GitHub repository:
   `https://github.com/uppy19d0/pii-safe-logger`.
2. In npm, configure Trusted Publisher for the package using:
   - Repository owner: `uppy19d0`
   - Repository name: `pii-safe-logger`
   - Workflow filename: `publish.yml`
3. Publish by creating a GitHub release. The publish workflow uses OIDC and npm
   provenance instead of a long-lived npm token.
4. Verify the published package after release:

```bash
npm view pii-safe-logger@latest
npm audit signatures
```

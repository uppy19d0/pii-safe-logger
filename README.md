# pii-safe-logger

[![CI](https://github.com/uppy19d0/pii-safe-logger/actions/workflows/ci.yml/badge.svg)](https://github.com/uppy19d0/pii-safe-logger/actions/workflows/ci.yml)
[![Deploy to npm](https://github.com/uppy19d0/pii-safe-logger/actions/workflows/publish.yml/badge.svg)](https://github.com/uppy19d0/pii-safe-logger/actions/workflows/publish.yml)

PII-safe logging utilities for JavaScript and TypeScript. The package redacts
common sensitive values before log messages reach `console`, a custom sink, or
your observability pipeline.

Use it when your service handles emails, phone numbers, SSNs, card numbers,
passwords, API keys, tokens, authorization headers, or other customer data that
should not appear in logs.

Created by [Luis Aneuris Tavarez De Jesus](https://www.ltavarez.me/).

## What PII-safe Means

`PII` means `Personally Identifiable Information`: data that can identify a
person directly or indirectly. Examples include email addresses, phone numbers,
government identifiers, account identifiers, and payment details.

`PII-safe` means this logger is designed to reduce accidental exposure by
masking common sensitive fields and patterns before a log line is emitted.

No generic logger can guarantee perfect PII detection for every business domain.
Treat this package as a safe default layer, then configure `sensitiveKeys` for
your own field names.

## Features

- Zero runtime dependencies.
- ESM package for modern Node.js projects.
- TypeScript declarations included.
- Redacts nested objects, arrays, strings, `Error` instances, dates, regular
  expressions, functions, symbols, and circular references.
- Masks common string patterns: emails, SSNs, phone numbers, and likely credit
  card numbers.
- Redacts common sensitive object keys such as `password`, `token`, `secret`,
  `authorization`, `apiKey`, and `ssn`.
- Supports custom redaction text.
- Supports custom sensitive key sets.
- Supports custom log sinks.
- Supports log levels: `debug`, `info`, `warn`, and `error`.

## Installation

```bash
npm install pii-safe-logger
```

## Quick Start

```js
import { createPiiSafeLogger } from "pii-safe-logger";

const logger = createPiiSafeLogger({ level: "info" });

logger.info("User signed in", {
  email: "ana@example.com",
  password: "super-secret",
  token: "abcd-1234"
});
```

The emitted log line contains redacted values instead of the original sensitive
data.

## Redact Without Logging

Use `maskPii` when you need a safe copy of a value but do not want to emit a log.

```js
import { maskPii } from "pii-safe-logger";

const safePayload = maskPii({
  email: "ana@example.com",
  profile: {
    phone: "+1 (555) 123-4567"
  },
  password: "super-secret"
});

console.log(safePayload);
```

Output:

```json
{
  "email": "[REDACTED]",
  "profile": {
    "phone": "[REDACTED]"
  },
  "password": "[REDACTED]"
}
```

## String Pattern Redaction

Free-form strings are scanned for common PII patterns.

```js
import { maskPii } from "pii-safe-logger";

const message = "Contact ana@example.com or +1 (555) 123-4567";

console.log(maskPii(message));
// Contact [REDACTED] or [REDACTED]
```

## Object Redaction

Objects and arrays are copied recursively. The original value is not mutated.

```js
import { maskPii } from "pii-safe-logger";

const input = {
  user: {
    email: "ana@example.com",
    credentials: {
      apiKey: "key-123",
      password: "secret"
    }
  },
  notes: ["Card 4111 1111 1111 1111"]
};

const output = maskPii(input);
```

## Circular References

Circular references are replaced with `"[Circular]"` so logs can still be
serialized safely.

```js
import { maskPii } from "pii-safe-logger";

const payload = { token: "abc" };
payload.self = payload;

console.log(maskPii(payload));
// { token: "[REDACTED]", self: "[Circular]" }
```

## Errors

`Error` instances are converted into safe objects with `name`, `message`, and
`stack` fields. The message and stack are also redacted.

```js
import { maskPii } from "pii-safe-logger";

const error = new Error("Failed for ana@example.com");

console.log(maskPii(error));
```

## Log Levels

`level` controls the minimum log level.

```js
import { createPiiSafeLogger } from "pii-safe-logger";

const logger = createPiiSafeLogger({ level: "warn" });

logger.info("This will not be emitted");
logger.warn("This will be emitted", { email: "ana@example.com" });
```

Level order:

```text
debug < info < warn < error
```

## Custom Sink

By default, logs are written to `console`. You can provide a custom sink with
`debug`, `info`, `warn`, `error`, or `log` methods.

```js
import { createPiiSafeLogger } from "pii-safe-logger";

const lines = [];

const logger = createPiiSafeLogger({
  sink: {
    debug(line) {
      lines.push(line);
    },
    info(line) {
      lines.push(line);
    },
    warn(line) {
      lines.push(line);
    },
    error(line) {
      lines.push(line);
    },
    log(line) {
      lines.push(line);
    }
  }
});

logger.info("Payment created", {
  email: "ana@example.com",
  card: "4111 1111 1111 1111"
});
```

## Custom Redaction Text

The default replacement is `"[REDACTED]"`. You can change it with `redaction`.

```js
import { maskPii } from "pii-safe-logger";

const safe = maskPii("Email: ana@example.com", {
  redaction: "[PRIVATE]"
});

console.log(safe);
// Email: [PRIVATE]
```

## Custom Sensitive Keys

Use `sensitiveKeys` to decide which object keys should be fully redacted.
Provide normalized keys: lowercase, without dashes, underscores, or spaces.

```js
import { maskPii } from "pii-safe-logger";

const safe = maskPii(
  {
    documentId: "001-1234567-8",
    accountNumber: "123456789"
  },
  {
    sensitiveKeys: new Set(["documentid", "accountnumber"])
  }
);

console.log(safe);
// { documentId: "[REDACTED]", accountNumber: "[REDACTED]" }
```

## Preserve Free-form Strings

If you only want to redact sensitive object keys and leave string values
unchanged, set `maskStringValues` to `false`.

```js
import { maskPii } from "pii-safe-logger";

const safe = maskPii("Contact ana@example.com", {
  maskStringValues: false
});

console.log(safe);
// Contact ana@example.com
```

## TypeScript

The package ships with TypeScript declarations.

```ts
import { createPiiSafeLogger, maskPii } from "pii-safe-logger";

const logger = createPiiSafeLogger({ level: "debug" });

const safeValue = maskPii({
  email: "ana@example.com",
  password: "secret"
});

logger.info("safe payload", safeValue);
```

## API

### `createPiiSafeLogger(options?)`

Creates a logger with these methods:

- `debug(message?, ...meta)`
- `info(message?, ...meta)`
- `warn(message?, ...meta)`
- `error(message?, ...meta)`
- `log(message?, ...meta)`

### `maskPii(value, options?)`

Returns a deep-masked copy of `value`.

### Options

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `level` | `"debug" \| "info" \| "warn" \| "error"` | `"info"` | Minimum log level for `createPiiSafeLogger`. |
| `sink` | `Pick<Console, LogLevel \| "log">` | `console` | Destination for formatted log lines. |
| `redaction` | `string` | `"[REDACTED]"` | Replacement text for sensitive values. |
| `sensitiveKeys` | `Iterable<string>` | built-in set | Object keys that should be fully redacted. |
| `maskStringValues` | `boolean` | `true` | Whether to scan free-form strings for PII patterns. |

## What Gets Redacted

Built-in redaction covers:

- emails: `ana@example.com`
- SSNs: `123-45-6789` or `123456789`
- phone-like values: `+1 (555) 123-4567`
- likely credit card values: `4111 1111 1111 1111`
- common sensitive keys: `password`, `passwd`, `secret`, `token`, `apiKey`,
  `apikey`, `authorization`, `bearer`, and `ssn`

## Development

```bash
npm install
npm test
```

## Deploy

See [DEPLOY.md](./DEPLOY.md) for the GitHub Actions pipeline and npm publishing
steps.

## Supply Chain Security

This package is published from GitHub Actions with npm provenance enabled.

The repository includes:

- CI checks on push and pull request
- automatic npm deploy on `main`
- duplicate-version protection before `npm publish`
- pinned GitHub Actions
- Dependabot updates
- `SECURITY.md`
- MIT license

## Security Note

This package is a defensive logging helper, not a data-loss-prevention system.
Always avoid intentionally passing secrets into logs. Add custom
`sensitiveKeys` for domain-specific identifiers such as document numbers,
account numbers, customer IDs, vendor IDs, and internal tokens.

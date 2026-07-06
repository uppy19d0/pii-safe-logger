# pii-safe-logger

[![CI](https://github.com/uppy19d0/pii-safe-logger/actions/workflows/ci.yml/badge.svg)](https://github.com/uppy19d0/pii-safe-logger/actions/workflows/ci.yml)

PII-safe structured logging for JavaScript and TypeScript. It redacts sensitive
data before logs reach `console`, a custom sink, or your observability pipeline.

Use it when your services handle emails, phone numbers, card numbers, bearer
tokens, JWTs, passwords, OTPs, API keys, national IDs, account numbers, or other
customer data that should never appear in logs.

Created by [Luis Aneuris Tavarez De Jesus](https://www.ltavarez.me/).

## What Does PII-safe Mean?

`PII` means `Personally Identifiable Information`: data that can identify a
person directly or indirectly, such as email, phone number, document number,
card number, address, tokens, or account identifiers.

`PII-safe` means the logger is designed to keep that sensitive information out
of logs by redacting or masking it before it reaches your terminal, cloud logs,
APM, SIEM, or observability tools.

No generic logger can know every sensitive field in your business domain. This
package gives you a strong default layer and lets you add your own field names
and redaction rules.

## Features

- Zero runtime dependencies.
- Works with JavaScript and TypeScript.
- Supports ESM `import` and CommonJS `require`.
- Includes TypeScript declarations.
- Redacts nested objects, arrays, `Error` instances, dates, strings, regular
  expressions, functions, symbols, and circular references.
- Built-in string rules for emails, phone numbers, SSNs, credit cards with
  Luhn validation, JWTs, bearer tokens, and secret assignments.
- Redacts sensitive fields by key name, including `password`, `token`,
  `authorization`, `email`, `phone`, `cardNumber`, `apiKey`, `otp`, `pin`,
  `secret`, and more.
- Supports custom rules, custom field names, field-specific partial masking,
  custom redaction text, custom sinks, custom formatters, log levels, child
  loggers, and transaction IDs for traceability.

## Installation

```bash
npm install pii-safe-logger
```

## Quick Start

### JavaScript ESM

```js
import { createPiiSafeLogger } from "pii-safe-logger";

const logger = createPiiSafeLogger({
  service: "payments-service",
  level: "info"
}).withTransaction();

logger.info("Payment created for luis@example.com", {
  cardNumber: "4111111111111111",
  amount: 250,
  authorization: "Bearer abc.def.ghi"
});
```

### JavaScript CommonJS

```js
const { createPiiSafeLogger } = require("pii-safe-logger");

const logger = createPiiSafeLogger({
  service: "payments-service",
  level: "info"
}).withTransaction();

logger.info("Payment created for luis@example.com", {
  cardNumber: "4111111111111111",
  amount: 250,
  authorization: "Bearer abc.def.ghi"
});
```

Output:

```json
{
  "level": "info",
  "message": "Payment created for [REDACTED]",
  "timestamp": "2026-07-05T20:00:00.000Z",
  "context": {
    "cardNumber": "[REDACTED]",
    "amount": 250,
    "authorization": "[REDACTED]"
  },
  "service": "payments-service",
  "transactionId": "txn_lz8z2l3r_1f4a8c3b9d20a7e1"
}
```

## Redact Without Logging

Use `redact` or `maskPii` when you need a safe copy of a value but do not want
to emit a log.

```js
import { redact, redactString } from "pii-safe-logger";

redactString("Email: luis@example.com");
// "Email: [REDACTED]"

redact({
  email: "luis@example.com",
  profile: {
    phone: "+1 809 555 1234"
  }
});
// { email: "[REDACTED]", profile: { phone: "[REDACTED]" } }
```

`maskPii` is kept as a friendly alias for `redact`.

```js
import { maskPii } from "pii-safe-logger";

const safePayload = maskPii({
  password: "super-secret",
  notes: "Contact luis@example.com"
});
```

## Custom Field Names

Use `redactFields` when your payloads contain sensitive domain-specific field
names. String field names are normalized before matching, so `account_number`,
`account-number`, and `account number` can be represented as `accountnumber`.

```js
import { createPiiSafeLogger } from "pii-safe-logger";

const logger = createPiiSafeLogger({
  redactFields: ["accountNumber", /document/i]
});

logger.info("Account loaded", {
  accountNumber: "123456789",
  documentId: "00112345678"
});
```

You can also use the backwards-compatible `sensitiveKeys` option:

```js
import { redact } from "pii-safe-logger";

const safe = redact(
  {
    vendorToken: "vendor-secret"
  },
  {
    sensitiveKeys: new Set(["vendortoken"])
  }
);
```

## Partial Masking

Use partial masking when you need traceability or support visibility without
exposing the full value.

```js
import { redactString } from "pii-safe-logger";

const safe = redactString("Customer luis@example.com", {
  preserveFirst: 2,
  preserveLast: 4
});

// "Customer lu[REDACTED].com"
```

For object fields, use `maskFields`. These rules run before `redactFields`, so
you can decide that a specific field should show only a safe fragment.

```js
import { redact } from "pii-safe-logger";

const safePayload = redact(
  {
    cardNumber: "4111111111111111",
    email: "luis@example.com"
  },
  {
    maskFields: [
      { field: "cardNumber", preserveFirst: 6, preserveLast: 4, replacement: "******" },
      { field: "email", preserveFirst: 2, preserveLast: 4 }
    ]
  }
);

// {
//   cardNumber: "411111******1111",
//   email: "lu[REDACTED].com"
// }
```

You can mask one value directly:

```js
import { maskValue } from "pii-safe-logger";

maskValue("4111111111111111", {
  preserveFirst: 6,
  preserveLast: 4,
  replacement: "******"
});
// "411111******1111"
```

## Custom Rules

Custom rules let you redact business-specific identifiers that a generic logger
cannot know, such as internal customer IDs, account aliases, transaction
references, or vendor-specific payload values.

```js
import {
  DEFAULT_REDACTION_RULES,
  createMask,
  redactString
} from "pii-safe-logger";

const safeMessage = redactString("Customer loaded: cus_123456789", {
  rules: [
    ...DEFAULT_REDACTION_RULES,
    {
      name: "internal-customer-id",
      reason: "custom",
      pattern: /\bcus_[a-z0-9]+\b/gi,
      replacement: createMask({
        preserveFirst: 4,
        preserveLast: 4,
        replacement: "****"
      })
    }
  ]
});

// "Customer loaded: cus_****6789"
```

When you provide `rules`, they replace the default pattern rules. Import and
spread `DEFAULT_REDACTION_RULES` if you want to extend the built-in behavior.

You can also replace the full match with a fixed value:

```js
import { DEFAULT_REDACTION_RULES, createPiiSafeLogger } from "pii-safe-logger";

const logger = createPiiSafeLogger({
  rules: [
    ...DEFAULT_REDACTION_RULES,
    {
      name: "internal-account-id",
      reason: "custom",
      pattern: /\bacct_\d+\b/g,
      replacement: "[ACCOUNT_ID]"
    }
  ]
});
```

## Transaction IDs

Use transaction IDs to correlate logs across steps without logging sensitive
customer data.

```js
import { DEFAULT_REDACT_FIELDS, createPiiSafeLogger } from "pii-safe-logger";

const logger = createPiiSafeLogger({
  service: "payments-service",
  redactFields: [...DEFAULT_REDACT_FIELDS, "customerId"]
});

const txLogger = logger.withTransaction();

txLogger.info("Payment validation started", {
  customerId: "cus_123456789",
  amount: 250
});

txLogger.info("Payment validation finished");
```

Both logs receive the same safe `transactionId`.

You can also provide your own transaction ID:

```js
const txLogger = logger.withTransaction("txn-payment-001");
```

Or generate one manually:

```js
import { createTransactionId } from "pii-safe-logger";

const transactionId = createTransactionId("payment");
// payment_lz8z2l3r_1f4a8c3b9d20a7e1
```

## Child Loggers

Child loggers attach shared context to every emitted entry.

```js
const requestLogger = logger.withTransaction().child({
  requestId: "req_123",
  userId: "usr_456"
});

requestLogger.info("Request started");
```

The context is also passed through the redaction pipeline before it is emitted.

## Custom Sink

By default, the logger writes formatted log entries to `console`. You can send
logs to another destination by providing a `sink`.

```js
import { createPiiSafeLogger } from "pii-safe-logger";

const logger = createPiiSafeLogger({
  sink: {
    info: (entry) => {
      process.stdout.write(`${entry}\n`);
    },
    error: (entry) => {
      process.stderr.write(`${entry}\n`);
    },
    log: (entry) => {
      process.stdout.write(`${entry}\n`);
    }
  }
});
```

## Custom Formatter

The default formatter is `JSON.stringify`. Use `formatter` to control the final
shape of each log entry.

```js
import { createPiiSafeLogger } from "pii-safe-logger";

const logger = createPiiSafeLogger({
  formatter: (entry) => ({
    ...entry,
    environment: process.env.NODE_ENV || "development"
  })
});
```

If the formatter returns a string, the logger emits it directly. Otherwise, the
result is serialized with `JSON.stringify`.

## Log Levels

`level` controls the minimum log level.

```js
const logger = createPiiSafeLogger({ level: "warn" });

logger.info("This will not be emitted");
logger.warn("This will be emitted");
```

Level order:

```text
debug < info < warn < error
```

## Handling Circular References

Circular references are replaced with `"[Circular]"` so log formatting does not
throw.

```js
import { redact } from "pii-safe-logger";

const input = { token: "abc" };
input.self = input;

redact(input);
// { token: "[REDACTED]", self: "[Circular]" }
```

## TypeScript

The package ships with TypeScript declarations.

```ts
import { createPiiSafeLogger, redact } from "pii-safe-logger";

const logger = createPiiSafeLogger({
  service: "payments-service",
  level: "debug"
});

const safePayload = redact({
  email: "luis@example.com",
  password: "secret"
});

logger.info("payload", safePayload);
```

## API

### `createPiiSafeLogger(options?)`

Creates a logger with:

- `debug(message?, ...meta)`
- `info(message?, ...meta)`
- `warn(message?, ...meta)`
- `error(message?, ...meta)`
- `log(message?, ...meta)`
- `child(context?)`
- `withTransaction(transactionId?)`

### `redact(value, options?)`

Returns a safe copy of any value.

### `maskPii(value, options?)`

Alias for `redact`.

### `redactString(value, options?)`

Applies redaction rules to a string.

### `maskValue(value, options?)`

Masks a single value while preserving optional first or last characters.

### `createMask(options?)`

Creates a reusable replacement function for custom rules.

### `createTransactionId(prefix?)`

Creates a non-sensitive ID suitable for log correlation.

### `DEFAULT_REDACTION_RULES`

Built-in string redaction rules. Import this when you want to extend the default
rules instead of replacing them.

### `DEFAULT_REDACT_FIELDS`

Built-in normalized object field names. Import this when you want to extend the
default field redaction list instead of replacing it.

## Options

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `level` | `"debug" \| "info" \| "warn" \| "error"` | `"info"` | Minimum log level. |
| `service` | `string` | `undefined` | Service name included in log entries. |
| `sink` | `LoggerSink` | `console` | Destination for formatted logs. |
| `formatter` | `(entry) => unknown` | `JSON.stringify` | Formats a sanitized log entry. |
| `replacement` | `string` | `"[REDACTED]"` | Replacement text. |
| `redaction` | `string` | `"[REDACTED]"` | Backwards-compatible alias for `replacement`. |
| `redactFields` | `(string \| RegExp)[]` | built-in field list | Field names to redact completely. |
| `sensitiveKeys` | `Iterable<string>` | built-in field list | Backwards-compatible key set for field redaction. |
| `maskFields` | `FieldMask[]` | `[]` | Field names to mask partially. |
| `rules` | `RedactionRule[]` | built-in rules | Pattern rules for strings. |
| `transactionId` | `string \| () => string` | `undefined` | Transaction ID included in log entries. |
| `transactionIdGenerator` | `() => string` | `createTransactionId` through `withTransaction()` | Custom generator for `withTransaction()`. |
| `preserveFirst` | `number` | `0` | Characters to preserve at the start of a matched string. |
| `preserveLast` | `number` | `0` | Characters to preserve at the end of a matched string. |
| `maxDepth` | `number` | `12` | Maximum object traversal depth. |
| `maxArrayLength` | `number` | `100` | Maximum array items to include. |
| `maskStringValues` | `boolean` | `true` | Whether to scan free-form strings for sensitive patterns. |

## Built-in Redaction Coverage

The default configuration redacts:

- email addresses
- SSNs
- phone-like values
- likely credit card values that pass Luhn validation
- JWTs
- bearer tokens
- assignments such as `password=secret`, `token: abc`, and `apiKey=value`
- common sensitive object keys such as `password`, `token`, `authorization`,
  `email`, `phone`, `cardNumber`, `apiKey`, `otp`, `pin`, and `secret`

## Development

```bash
npm install
npm test
```

## Versioning

This package follows Semantic Versioning. Patch releases are reserved for
backwards-compatible fixes and documentation updates. Minor releases may add new
APIs, options, or redaction coverage. Major releases are used for breaking
changes.

See [SEMVER.md](./SEMVER.md) for the public API contract and release rules.

## Security Note

No logger can guarantee perfect PII detection for every business domain. Treat
this package as a strong default layer, then add custom field names and custom
rules for your own identifiers, document numbers, account numbers, customer IDs,
vendor payloads, and internal tokens.

Avoid intentionally passing secrets to logs. This package reduces accidental
exposure; it does not replace access controls, log retention policies, or
security review.

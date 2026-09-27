# Security Model

`pii-safe-logger` is a defensive logging library. Its goal is to reduce the chance that application logs expose personal data, regulated data, credentials, tokens, connection strings, or payment data.

## Threats Covered

- Accidental logging of PII, PHI, PANs, CVV/CVC values, tokens, API keys, private keys, and database URLs.
- Nested object leaks through structured log context.
- Secret leaks inside free-form log messages.
- Error object leaks through `message`, `stack`, and enumerable custom fields.
- Circular references and oversized nested payloads that could break logging pipelines.
- Mixed regulated payloads that combine GDPR, HIPAA, and PCI-like fields.

## Threats Not Covered

- This library is not a legal compliance certification.
- It does not replace data classification, access control, encryption, retention controls, SIEM policy, DLP, or incident response.
- It cannot know every business-specific identifier unless you add custom fields or rules.
- It cannot remove values already emitted by another logger before this library receives them.
- It cannot guarantee safety if a custom formatter reintroduces raw values from outside the redacted log entry.

## Default Controls

- Default redaction field names for passwords, tokens, email, phone, payment cards, OTPs, PINs, and secrets.
- Default string rules for email, phone, SSN-like IDs, credit cards with Luhn validation, JWTs, bearer tokens, secret assignments, AWS access keys, GitHub tokens, Slack tokens, private key blocks, and database URLs.
- Compliance presets for GDPR, HIPAA, and PCI-style logging controls.
- Maximum depth and array length controls.
- Circular reference handling.
- ESM, CommonJS, and TypeScript declarations.
- Zero runtime dependencies.

## Validation

The test suite includes a security corpus with realistic leak examples:

- Cloud and source-control secrets.
- Regulated personal and health data.
- Payment card and magnetic stripe track data.
- Private key blocks.
- Logger-output leak checks.
- String-only leak checks.

Run:

```bash
npm test
npm run benchmark
npm pack --dry-run
```

## Recommended Production Use

- Use `createComplianceOptions("gdpr", "hipaa", "pci")` for regulated services, then add domain-specific `redactFields` and `rules`.
- Redact as close as possible to the application boundary, before logs reach APM, cloud logs, SIEM, queues, files, or stdout collectors.
- Keep raw request/response body logging disabled in production unless explicitly filtered.
- Treat log sinks as sensitive systems: restrict access, encrypt at rest, monitor access, and set retention.
- Add application-specific regression tests for identifiers unique to your company.

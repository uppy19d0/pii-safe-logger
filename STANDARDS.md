# Standards Alignment

`pii-safe-logger` is designed to support secure logging practices. It is not a certification product, but it provides controls that help teams implement common security and privacy expectations.

## OWASP Logging Guidance

Relevant expectations:

- Do not log sensitive personal data, secrets, passwords, access tokens, session identifiers, or regulated data.
- Prefer consistent structured logs.
- Avoid creating secondary sensitive-data exposure through logging.
- Validate logs against realistic abuse and leak scenarios.

Library support:

- Structured logger with redacted `message`, `context`, and transaction metadata.
- Redaction rules for credentials, tokens, private keys, connection strings, and regulated identifiers.
- Security corpus tests for realistic leak payloads.
- Custom fields and custom rules for application-specific identifiers.

## PCI-style Logging Controls

Relevant expectations:

- Avoid exposing full PANs in logs.
- Do not log sensitive authentication data such as CVV/CVC or magnetic stripe track data.
- Use masking/tokenization patterns carefully and avoid storing sensitive payment data in log systems.

Library support:

- Luhn-aware payment-card detection.
- PCI preset covering PAN-like fields, CVV/CVC fields, cardholder fields, payment tokens, and magnetic stripe track data.
- Tests that assert PAN, CVV, and track data are not emitted.

## HIPAA-style PHI Controls

Relevant expectations:

- Avoid exposing patient identifiers and health information in logs.
- Treat logs that can contain PHI as sensitive systems with access and retention controls.

Library support:

- HIPAA preset covering patient names, patient IDs, MRNs, claims, diagnoses, insurance, policy numbers, and dates of birth.
- Tests that assert patient names, MRNs, diagnoses, and patient IDs are redacted.

## GDPR-style Personal Data Controls

Relevant expectations:

- Avoid unnecessary processing and storage of personal data.
- Treat identifiers such as IP addresses, device IDs, cookies, names, addresses, and national IDs as personal data when applicable.

Library support:

- GDPR preset covering names, address fields, IP addresses, cookies, device IDs, session IDs, national IDs, document IDs, and common contact data.
- Partial masking controls for support-safe identifiers.

## Enterprise Review Checklist

- Confirm `npm test` and `npm pack --dry-run` pass in CI.
- Review `SECURITY_MODEL.md` for covered and uncovered threats.
- Add company-specific `redactFields` and `rules`.
- Add a company-specific leak corpus to CI.
- Verify logger integrations before logs reach stdout collectors, APM agents, or cloud logging.
- Document log retention, access control, and incident response outside the library.

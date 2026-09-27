# Contributing

Thanks for improving `pii-safe-logger`.

## Development

```bash
npm ci
npm test
npm pack --dry-run
```

## Quality Expectations

- Add tests for new redaction rules, mask behavior, or logger output.
- Keep default rules conservative and avoid leaking sensitive values in snapshots or examples.
- Preserve ESM, CommonJS, and TypeScript declaration support.
- Document user-facing behavior in the README when changing public APIs.

## Security

Do not open public issues for vulnerabilities or bypasses that expose private data. Follow the reporting guidance in `SECURITY.md`.

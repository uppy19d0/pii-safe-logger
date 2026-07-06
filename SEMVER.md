# Semantic Versioning Policy

`pii-safe-logger` follows Semantic Versioning after `1.0.0`.

## Public API

The public API is everything a package consumer can import, call, configure, or
rely on at runtime:

- package entrypoints and `exports`
- TypeScript declarations in `src/index.d.ts`
- exported functions and constants
- logger methods and log entry shape
- documented options
- default redaction behavior
- supported module formats
- supported Node.js engine range

## Patch Releases

Patch versions are for backwards-compatible changes only:

- documentation improvements
- CI or release maintenance
- bug fixes that preserve the public API
- redaction accuracy fixes that do not remove existing documented behavior
- internal refactors with no consumer-visible API change

Examples:

- `1.1.0` to `1.1.1`
- improving README examples
- fixing a false positive in a redaction rule

## Minor Releases

Minor versions are for backwards-compatible additions:

- new exported helpers
- new logger options
- new redaction rules
- new TypeScript types
- new module entrypoints
- new behavior that does not break existing consumers

Examples:

- `1.1.1` to `1.2.0`
- adding a new built-in redaction rule
- adding a new optional logger method

## Major Releases

Major versions are required for breaking changes:

- removing or renaming an export
- changing an existing function signature incompatibly
- changing default log shape incompatibly
- changing default redaction behavior in a way that can expose previously
  redacted sensitive data
- dropping a supported Node.js major version
- removing CommonJS or ESM support

Examples:

- `1.1.1` to `2.0.0`
- removing `maskPii`
- changing `createPiiSafeLogger().info()` to emit objects instead of strings

## CI Guard

The CI workflow runs `scripts/check-semver.js`.

The guard checks the current commit against the previous commit or pull request
base:

- package-content changes must include a version increase
- public API changes are not allowed in patch releases
- public API changes require at least a minor version bump
- breaking changes must be reviewed manually and released as a major version

This guard is intentionally conservative. It cannot prove every behavioral
change is safe, but it blocks the most common accidental SemVer mistakes.

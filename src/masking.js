const DEFAULT_REDACTION = "[REDACTED]";

const DEFAULT_SENSITIVE_KEYS = new Set([
  "password",
  "passwd",
  "secret",
  "token",
  "accessToken",
  "refreshToken",
  "apiKey",
  "apikey",
  "authorization",
  "bearer",
  "ssn",
  "socialSecurityNumber",
  "creditCard",
  "cardNumber"
]);

const EMAIL_PATTERN = /\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b/gi;
const SSN_PATTERN = /\b\d{3}-?\d{2}-?\d{4}\b/g;
const CREDIT_CARD_PATTERN = /\b(?:\d[ -]*?){13,19}\b/g;
const PHONE_PATTERN = /\+?(?:\d[\d\s().-]{7,}\d)/g;

function normalizeKey(key) {
  return String(key).replace(/[-_\s]/g, "").toLowerCase();
}

function redactPrimitive(value, redaction) {
  if (typeof value !== "string") {
    return value;
  }

  return value
    .replace(EMAIL_PATTERN, redaction)
    .replace(SSN_PATTERN, redaction)
    .replace(CREDIT_CARD_PATTERN, redaction)
    .replace(PHONE_PATTERN, redaction);
}

function redactString(value, redaction, maskStringValues) {
  if (!value) {
    return value;
  }

  if (maskStringValues === false) {
    return value;
  }

  return redactPrimitive(value, redaction);
}

function redactValue(value, options, seen, path) {
  const { redaction = DEFAULT_REDACTION, sensitiveKeys = DEFAULT_SENSITIVE_KEYS } = options;

  if (value === null || value === undefined) {
    return value;
  }

  if (typeof value === "string") {
    return redactString(value, redaction, options.maskStringValues);
  }

  if (typeof value === "number" || typeof value === "boolean" || typeof value === "bigint") {
    return value;
  }

  if (typeof value === "function") {
    return "[Function]";
  }

  if (typeof value === "symbol") {
    return value.toString();
  }

  if (seen.has(value)) {
    return "[Circular]";
  }

  seen.add(value);

  if (value instanceof Date) {
    return value.toISOString();
  }

  if (value instanceof RegExp) {
    return value.toString();
  }

  if (value instanceof Error) {
    const safeError = {
      name: value.name,
      message: redactString(value.message, redaction, options.maskStringValues),
      stack: redactString(value.stack || "", redaction, options.maskStringValues)
    };

    for (const [key, errorValue] of Object.entries(value)) {
      safeError[key] = redactValue(errorValue, options, seen, path.concat(key));
    }

    seen.delete(value);
    return safeError;
  }

  if (Array.isArray(value)) {
    const result = value.map((item, index) => redactValue(item, options, seen, path.concat(String(index))));
    seen.delete(value);
    return result;
  }

  const output = {};

  for (const [key, nestedValue] of Object.entries(value)) {
    const normalizedKey = normalizeKey(key);
    if (sensitiveKeys.has(normalizedKey)) {
      output[key] = redaction;
      continue;
    }

    output[key] = redactValue(nestedValue, options, seen, path.concat(key));
  }

  seen.delete(value);
  return output;
}

export function maskPii(value, options = {}) {
  return redactValue(value, options, new WeakSet(), []);
}

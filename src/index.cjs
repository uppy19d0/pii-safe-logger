"use strict";

const DEFAULT_REPLACEMENT = "[REDACTED]";
const DEFAULT_MAX_DEPTH = 12;
const DEFAULT_MAX_ARRAY_LENGTH = 100;
const LEVELS = ["debug", "info", "warn", "error"];

const DEFAULT_REDACT_FIELD_NAMES = [
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
  "cardNumber",
  "card",
  "email",
  "phone",
  "otp",
  "pin"
];

const EMAIL_PATTERN = /\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b/gi;
const SSN_PATTERN = /\b\d{3}-?\d{2}-?\d{4}\b/g;
const CREDIT_CARD_PATTERN = /\b(?:\d[ -]*?){13,19}\b/g;
const PHONE_PATTERN = /(?<![\w])\+?(?:\d[\d\s().-]{7,}\d)(?![\w])/g;
const JWT_PATTERN = /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g;
const BEARER_PATTERN = /\bBearer\s+[A-Za-z0-9._~+/=-]+\b/gi;
const AWS_ACCESS_KEY_PATTERN = /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g;
const GITHUB_TOKEN_PATTERN = /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}\b/g;
const SLACK_TOKEN_PATTERN = /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g;
const PRIVATE_KEY_PATTERN = /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g;
const DATABASE_URL_PATTERN = /\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis):\/\/[^\s"']+/gi;
const SECRET_ASSIGNMENT_PATTERN =
  /\b(password|passwd|token|api[_-]?key|secret|otp|pin)\s*[:=]\s*(["']?)[^"',\s;}]+/gi;

function normalizeKey(key) {
  return String(key).replace(/[-_\s]/g, "").toLowerCase();
}

const DEFAULT_REDACT_FIELDS = DEFAULT_REDACT_FIELD_NAMES.map(normalizeKey);

function getReplacement(options = {}) {
  return options.replacement ?? options.redaction ?? DEFAULT_REPLACEMENT;
}

function isPlainObject(value) {
  if (Object.prototype.toString.call(value) !== "[object Object]") {
    return false;
  }

  const prototype = Object.getPrototypeOf(value);
  return prototype === null || prototype === Object.prototype;
}

function clonePattern(pattern) {
  const flags = pattern.flags.includes("g") ? pattern.flags : `${pattern.flags}g`;
  return new RegExp(pattern.source, flags);
}

function digitsOnly(value) {
  return String(value).replace(/\D/g, "");
}

function passesLuhn(value) {
  let sum = 0;
  let shouldDouble = false;

  for (let index = value.length - 1; index >= 0; index -= 1) {
    let digit = Number(value[index]);

    if (shouldDouble) {
      digit *= 2;
      if (digit > 9) {
        digit -= 9;
      }
    }

    sum += digit;
    shouldDouble = !shouldDouble;
  }

  return sum % 10 === 0;
}

function isLikelyCreditCard(value) {
  const digits = digitsOnly(value);
  return digits.length >= 13 && digits.length <= 19 && passesLuhn(digits);
}

function maskValue(value, options = {}) {
  if (value === null || value === undefined) {
    return value;
  }

  const stringValue = String(value);
  const replacement = getReplacement(options);
  const preserveFirst = Math.max(0, options.preserveFirst || 0);
  const preserveLast = Math.max(0, options.preserveLast || 0);

  if (preserveFirst === 0 && preserveLast === 0) {
    return replacement;
  }

  if (stringValue.length <= preserveFirst + preserveLast) {
    return replacement;
  }

  const start = stringValue.slice(0, preserveFirst);
  const end = preserveLast > 0 ? stringValue.slice(-preserveLast) : "";
  return `${start}${replacement}${end}`;
}

function createMask(options = {}) {
  return (value) => maskValue(value, options);
}

const DEFAULT_REDACTION_RULES = [
  {
    name: "email",
    reason: "email",
    pattern: EMAIL_PATTERN
  },
  {
    name: "ssn",
    reason: "national-id",
    pattern: SSN_PATTERN
  },
  {
    name: "jwt",
    reason: "token",
    pattern: JWT_PATTERN
  },
  {
    name: "bearer-token",
    reason: "token",
    pattern: BEARER_PATTERN
  },
  {
    name: "aws-access-key",
    reason: "cloud-secret",
    pattern: AWS_ACCESS_KEY_PATTERN
  },
  {
    name: "github-token",
    reason: "source-control-token",
    pattern: GITHUB_TOKEN_PATTERN
  },
  {
    name: "slack-token",
    reason: "chat-token",
    pattern: SLACK_TOKEN_PATTERN
  },
  {
    name: "private-key",
    reason: "private-key",
    pattern: PRIVATE_KEY_PATTERN
  },
  {
    name: "database-url",
    reason: "connection-string",
    pattern: DATABASE_URL_PATTERN
  },
  {
    name: "secret-assignment",
    reason: "secret",
    pattern: SECRET_ASSIGNMENT_PATTERN,
    replacement(match, _field, quote, options) {
      const prefix = match.match(/^(.*?[:=]\s*)(["']?)/u);
      const delimiter = quote || "";
      return `${prefix ? prefix[1] : ""}${delimiter}${getReplacement(options)}${delimiter}`;
    }
  },
  {
    name: "credit-card",
    reason: "payment-card",
    pattern: CREDIT_CARD_PATTERN,
    replacement(match, options) {
      return isLikelyCreditCard(match) ? maskValue(match, options) : match;
    }
  },
  {
    name: "phone",
    reason: "phone",
    pattern: PHONE_PATTERN
  }
];

function fieldMatches(field, key) {
  if (field instanceof RegExp) {
    field.lastIndex = 0;
    return field.test(key);
  }

  return normalizeKey(field) === normalizeKey(key);
}

function getRedactFields(options = {}) {
  if (options.redactFields) {
    return [...options.redactFields];
  }

  if (options.sensitiveKeys) {
    return [...options.sensitiveKeys];
  }

  return DEFAULT_REDACT_FIELDS;
}

function shouldRedactField(key, options) {
  return getRedactFields(options).some((field) => fieldMatches(field, key));
}

function findMaskField(key, options = {}) {
  const maskFields = options.maskFields || [];
  return maskFields.find((rule) => fieldMatches(rule.field, key));
}

function applyRule(value, rule, options) {
  const pattern = clonePattern(rule.pattern);
  const replacement = rule.replacement;

  return value.replace(pattern, (...args) => {
    const match = args[0];
    const groups = args.slice(1, -2);

    if (typeof replacement === "function") {
      return replacement(match, ...groups, options, rule);
    }

    if (typeof replacement === "string") {
      return replacement;
    }

    return maskValue(match, options);
  });
}

function redactString(value, options = {}) {
  if (typeof value !== "string") {
    return value;
  }

  if (options.maskStringValues === false) {
    return value;
  }

  const rules = options.rules || DEFAULT_REDACTION_RULES;
  return rules.reduce((current, rule) => applyRule(current, rule, options), value);
}

function redactError(value, options, seen, depth) {
  const safeError = {
    name: value.name,
    message: redactString(value.message, options),
    stack: redactString(value.stack || "", options)
  };

  for (const [key, errorValue] of Object.entries(value)) {
    safeError[key] = redactValue(errorValue, options, seen, depth + 1);
  }

  return safeError;
}

function redactArray(value, options, seen, depth) {
  const maxArrayLength = options.maxArrayLength ?? DEFAULT_MAX_ARRAY_LENGTH;
  return value
    .slice(0, maxArrayLength)
    .map((item) => redactValue(item, options, seen, depth + 1));
}

function redactObject(value, options, seen, depth) {
  const output = {};

  for (const [key, nestedValue] of Object.entries(value)) {
    const maskField = findMaskField(key, options);

    if (maskField) {
      output[key] = maskValue(nestedValue, {
        replacement: maskField.replacement ?? getReplacement(options),
        preserveFirst: maskField.preserveFirst,
        preserveLast: maskField.preserveLast
      });
      continue;
    }

    if (shouldRedactField(key, options)) {
      output[key] = getReplacement(options);
      continue;
    }

    output[key] = redactValue(nestedValue, options, seen, depth + 1);
  }

  return output;
}

function redactValue(value, options, seen, depth) {
  const maxDepth = options.maxDepth ?? DEFAULT_MAX_DEPTH;

  if (depth > maxDepth) {
    return "[MaxDepth]";
  }

  if (value === null || value === undefined) {
    return value;
  }

  if (typeof value === "string") {
    return redactString(value, options);
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

  try {
    if (value instanceof Date) {
      return value.toISOString();
    }

    if (value instanceof RegExp) {
      return value.toString();
    }

    if (value instanceof Error) {
      return redactError(value, options, seen, depth);
    }

    if (Array.isArray(value)) {
      return redactArray(value, options, seen, depth);
    }

    if (isPlainObject(value)) {
      return redactObject(value, options, seen, depth);
    }

    return redactObject(Object(value), options, seen, depth);
  } finally {
    seen.delete(value);
  }
}

function redact(value, options = {}) {
  return redactValue(value, options, new WeakSet(), 0);
}

function shouldLog(currentLevel, targetLevel) {
  return LEVELS.indexOf(targetLevel) >= LEVELS.indexOf(currentLevel);
}

function createDefaultTransactionId(prefix = "txn") {
  const timestamp = Date.now().toString(36);
  const random = Math.random().toString(16).slice(2, 18).padEnd(16, "0");
  return `${prefix}_${timestamp}_${random}`;
}

function resolveTransactionId(transactionId) {
  if (typeof transactionId === "function") {
    return transactionId();
  }

  return transactionId;
}

function formatEntry(entry, formatter) {
  const formatted = formatter(entry);

  if (typeof formatted === "string") {
    return formatted;
  }

  return JSON.stringify(formatted);
}

function normalizeLoggerOptions(options) {
  const replacement = options.replacement ?? options.redaction ?? DEFAULT_REPLACEMENT;

  return {
    ...options,
    replacement,
    redaction: replacement
  };
}

function buildEntry(level, message, meta, state) {
  const maskOptions = state.maskOptions;
  const transactionId = resolveTransactionId(state.transactionId);
  const context = {
    ...state.context
  };

  if (meta.length === 1 && isPlainObject(meta[0])) {
    Object.assign(context, meta[0]);
  } else if (meta.length > 0) {
    context.meta = meta;
  }

  const entry = {
    level,
    message: typeof message === "string" ? redactString(message, maskOptions) : redact(message, maskOptions),
    timestamp: new Date().toISOString()
  };

  if (Object.keys(context).length > 0) {
    entry.context = redact(context, maskOptions);
  }

  if (state.service) {
    entry.service = state.service;
  }

  if (transactionId) {
    entry.transactionId = redactString(String(transactionId), maskOptions);
  }

  return entry;
}

function createLogger(state) {
  const write = (targetLevel, message, ...meta) => {
    if (!shouldLog(state.level, targetLevel)) {
      return;
    }

    const entry = buildEntry(targetLevel, message, meta, state);
    const line = formatEntry(entry, state.formatter);
    const method =
      typeof state.sink[targetLevel] === "function"
        ? state.sink[targetLevel]
        : typeof state.sink.log === "function"
          ? state.sink.log
          : () => {};

    method.call(state.sink, line);
  };

  return {
    debug(message, ...meta) {
      write("debug", message, ...meta);
    },
    info(message, ...meta) {
      write("info", message, ...meta);
    },
    warn(message, ...meta) {
      write("warn", message, ...meta);
    },
    error(message, ...meta) {
      write("error", message, ...meta);
    },
    log(message, ...meta) {
      write("info", message, ...meta);
    },
    child(context = {}) {
      return createLogger({
        ...state,
        context: {
          ...state.context,
          ...context
        }
      });
    },
    withTransaction(transactionId) {
      const generator = state.transactionIdGenerator || createDefaultTransactionId;
      return createLogger({
        ...state,
        transactionId: transactionId || generator()
      });
    }
  };
}

function createTransactionId(prefix = "txn") {
  return createDefaultTransactionId(prefix);
}

function createPiiSafeLogger(options = {}) {
  const normalizedOptions = normalizeLoggerOptions(options);
  const {
    level = "info",
    sink = console,
    service,
    formatter = JSON.stringify,
    transactionId,
    transactionIdGenerator,
    ...maskOptions
  } = normalizedOptions;

  return createLogger({
    level,
    sink,
    service,
    formatter,
    transactionId,
    transactionIdGenerator,
    context: {},
    maskOptions
  });
}

const NATIONAL_ID_PATTERN = /\b(?:\d{3}-?\d{7}-?\d{1}|\d{9,12})\b/g;
const IP_ADDRESS_PATTERN = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g;
const MEDICAL_RECORD_PATTERN = /\b(?:mrn|medical[_\s-]?record|patient[_\s-]?id)\s*[:=]\s*["']?[A-Za-z0-9._-]{4,}\b/gi;
const PCI_TRACK_PATTERN = /%(?:B|\d)[^^\s]{6,}\^[^^\s]*\^[^^\s]*\?/g;
const WINSTON_LEVELS = ["error", "warn", "info", "debug"];
const PINO_LEVELS = ["fatal", "error", "warn", "info", "debug", "trace"];

function uniqueFields(...fieldGroups) {
  const fields = [];
  const seen = new Set();

  for (const group of fieldGroups) {
    for (const field of group) {
      const key = String(field).toLowerCase();
      if (!seen.has(key)) {
        seen.add(key);
        fields.push(field);
      }
    }
  }

  return fields;
}

function buildPreset({ name, redactFields, rules, maskFields = [], maxDepth = 10, maxArrayLength = 50 }) {
  return Object.freeze({
    name,
    redactFields: uniqueFields(DEFAULT_REDACT_FIELDS, redactFields),
    rules: [...DEFAULT_REDACTION_RULES, ...rules],
    maskFields,
    maxDepth,
    maxArrayLength
  });
}

const COMPLIANCE_PRESETS = Object.freeze({
  gdpr: buildPreset({
    name: "gdpr",
    redactFields: [
      "firstName",
      "lastName",
      "fullName",
      "name",
      "address",
      "street",
      "city",
      "postalCode",
      "zip",
      "ip",
      "ipAddress",
      "deviceId",
      "sessionId",
      "cookie",
      "nationalId",
      "documentId"
    ],
    rules: [
      { name: "ip-address", reason: "personal-data", pattern: IP_ADDRESS_PATTERN },
      { name: "national-id", reason: "personal-data", pattern: NATIONAL_ID_PATTERN }
    ],
    maskFields: [
      { field: "userId", preserveFirst: 3, preserveLast: 3 },
      { field: "customerId", preserveFirst: 3, preserveLast: 3 }
    ]
  }),
  hipaa: buildPreset({
    name: "hipaa",
    redactFields: [
      "patient",
      "patientName",
      "patientId",
      "memberId",
      "mrn",
      "medicalRecordNumber",
      "diagnosis",
      "condition",
      "claim",
      "claimId",
      "insurance",
      "policyNumber",
      "dateOfBirth",
      "dob"
    ],
    rules: [
      { name: "medical-record", reason: "phi", pattern: MEDICAL_RECORD_PATTERN },
      { name: "ip-address", reason: "phi", pattern: IP_ADDRESS_PATTERN }
    ]
  }),
  pci: buildPreset({
    name: "pci",
    redactFields: [
      "pan",
      "card",
      "cardNumber",
      "creditCard",
      "cvv",
      "cvc",
      "expiration",
      "expiry",
      "trackData",
      "magstripe",
      "cardholderName",
      "paymentToken"
    ],
    rules: [{ name: "pci-track-data", reason: "payment-card", pattern: PCI_TRACK_PATTERN }],
    maskFields: [
      { field: "last4", preserveLast: 4 },
      { field: "cardLast4", preserveLast: 4 }
    ],
    maxDepth: 8
  })
});

function getCompliancePreset(name) {
  const preset = COMPLIANCE_PRESETS[String(name).toLowerCase()];

  if (!preset) {
    throw new Error(`Unknown compliance preset: ${name}`);
  }

  return preset;
}

function createComplianceOptions(...presetNames) {
  const presets = presetNames.length > 0 ? presetNames.map(getCompliancePreset) : [COMPLIANCE_PRESETS.gdpr];

  return {
    redactFields: uniqueFields(...presets.map((preset) => preset.redactFields)),
    rules: presets.flatMap((preset) => preset.rules),
    maskFields: presets.flatMap((preset) => preset.maskFields || []),
    maxDepth: Math.min(...presets.map((preset) => preset.maxDepth || 12)),
    maxArrayLength: Math.min(...presets.map((preset) => preset.maxArrayLength || 100))
  };
}

function createSinkFromLogger(target, levels) {
  return levels.reduce((sink, level) => {
    sink[level === "fatal" || level === "trace" ? "debug" : level] = (line) => {
      const method = typeof target[level] === "function" ? target[level] : target.info || target.log;
      if (typeof method === "function") {
        method.call(target, line);
      }
    };
    return sink;
  }, {});
}

function createWinstonPiiSafeLogger(winstonLogger, options = {}) {
  return createPiiSafeLogger({
    ...options,
    sink: createSinkFromLogger(winstonLogger, WINSTON_LEVELS)
  });
}

function createPinoPiiSafeLogger(pinoLogger, options = {}) {
  return createPiiSafeLogger({
    ...options,
    sink: createSinkFromLogger(pinoLogger, PINO_LEVELS)
  });
}

function createWinstonRedactionFormat(options = {}) {
  return (info) => redact(info, options);
}

function createPinoRedactionHooks(options = {}) {
  return {
    logMethod(args, method) {
      const maskedArgs = args.map((value) => (typeof value === "string" ? redactString(value, options) : redact(value, options)));
      return method.apply(this, maskedArgs);
    }
  };
}

function createSafeLogPayload(value, options = {}) {
  return redact(value, options);
}

module.exports = {
  COMPLIANCE_PRESETS,
  DEFAULT_REDACT_FIELDS,
  DEFAULT_REDACTION_RULES,
  createComplianceOptions,
  createMask,
  createPinoPiiSafeLogger,
  createPinoRedactionHooks,
  createPiiSafeLogger,
  createSafeLogPayload,
  createTransactionId,
  createWinstonPiiSafeLogger,
  createWinstonRedactionFormat,
  getCompliancePreset,
  maskPii: redact,
  maskValue,
  redact,
  redactString
};

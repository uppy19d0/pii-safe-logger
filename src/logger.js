import { redact, redactString } from "./masking.js";

const LEVELS = ["debug", "info", "warn", "error"];

function shouldLog(currentLevel, targetLevel) {
  return LEVELS.indexOf(targetLevel) >= LEVELS.indexOf(currentLevel);
}

function isPlainObject(value) {
  if (Object.prototype.toString.call(value) !== "[object Object]") {
    return false;
  }

  const prototype = Object.getPrototypeOf(value);
  return prototype === null || prototype === Object.prototype;
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
  const replacement = options.replacement ?? options.redaction ?? "[REDACTED]";

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

  const logger = {
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

  return logger;
}

export function createTransactionId(prefix = "txn") {
  return createDefaultTransactionId(prefix);
}

export function createPiiSafeLogger(options = {}) {
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

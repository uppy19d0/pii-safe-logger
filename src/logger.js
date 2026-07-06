import { maskPii } from "./masking.js";

const LEVELS = ["debug", "info", "warn", "error"];

function shouldLog(currentLevel, targetLevel) {
  return LEVELS.indexOf(targetLevel) >= LEVELS.indexOf(currentLevel);
}

function formatPart(part, maskOptions) {
  const masked = maskPii(part, maskOptions);

  if (typeof masked === "string") {
    return masked;
  }

  if (masked === null) {
    return "null";
  }

  if (masked === undefined) {
    return "undefined";
  }

  return JSON.stringify(masked);
}

function formatLine(message, meta, maskOptions) {
  const pieces = [];

  if (message !== undefined && message !== null) {
    pieces.push(formatPart(message, maskOptions));
  }

  for (const item of meta) {
    pieces.push(formatPart(item, maskOptions));
  }

  return pieces.join(" ");
}

export function createPiiSafeLogger(options = {}) {
  const {
    level = "info",
    sink = console,
    redaction = "[REDACTED]",
    sensitiveKeys,
    maskStringValues = true
  } = options;

  const maskOptions = {
    redaction,
    sensitiveKeys,
    maskStringValues
  };

  const write = (targetLevel, message, ...meta) => {
    if (!shouldLog(level, targetLevel)) {
      return;
    }

    const line = formatLine(message, meta, maskOptions);

    const method = typeof sink[targetLevel] === "function" ? sink[targetLevel].bind(sink) : sink.log.bind(sink);
    method(line);
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
    }
  };
}

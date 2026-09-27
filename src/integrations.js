import { createPiiSafeLogger, createTransactionId } from "./logger.js";
import { redact, redactString } from "./masking.js";

const WINSTON_LEVELS = ["error", "warn", "info", "debug"];
const PINO_LEVELS = ["fatal", "error", "warn", "info", "debug", "trace"];

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

export function createWinstonPiiSafeLogger(winstonLogger, options = {}) {
  return createPiiSafeLogger({
    ...options,
    sink: createSinkFromLogger(winstonLogger, WINSTON_LEVELS)
  });
}

export function createPinoPiiSafeLogger(pinoLogger, options = {}) {
  return createPiiSafeLogger({
    ...options,
    sink: createSinkFromLogger(pinoLogger, PINO_LEVELS)
  });
}

export function createWinstonRedactionFormat(options = {}) {
  return (info) => redact(info, options);
}

export function createPinoRedactionHooks(options = {}) {
  return {
    logMethod(args, method) {
      const maskedArgs = args.map((value) => {
        if (typeof value === "string") {
          return redactString(value, options);
        }

        return redact(value, options);
      });

      return method.apply(this, maskedArgs);
    }
  };
}

export function createSafeLogPayload(value, options = {}) {
  return redact(value, options);
}

export { createTransactionId };

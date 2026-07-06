export type LogLevel = "debug" | "info" | "warn" | "error";

export interface MaskOptions {
  redaction?: string;
  sensitiveKeys?: Iterable<string>;
  maskStringValues?: boolean;
}

export interface LoggerOptions extends MaskOptions {
  level?: LogLevel;
  sink?: Pick<Console, LogLevel | "log">;
}

export interface PiiSafeLogger {
  debug(message?: unknown, ...meta: unknown[]): void;
  info(message?: unknown, ...meta: unknown[]): void;
  warn(message?: unknown, ...meta: unknown[]): void;
  error(message?: unknown, ...meta: unknown[]): void;
  log(message?: unknown, ...meta: unknown[]): void;
}

export declare function createPiiSafeLogger(options?: LoggerOptions): PiiSafeLogger;
export declare function maskPii<T>(value: T, options?: MaskOptions): T;

export type LogLevel = "debug" | "info" | "warn" | "error";

export type RedactionReplacement =
  | string
  | ((match: string, ...args: unknown[]) => string);

export interface RedactionRule {
  name: string;
  reason?: string;
  pattern: RegExp;
  replacement?: RedactionReplacement;
}

export interface FieldMask {
  field: string | RegExp;
  preserveFirst?: number;
  preserveLast?: number;
  replacement?: string;
}

export interface MaskOptions {
  replacement?: string;
  redaction?: string;
  redactFields?: Array<string | RegExp>;
  sensitiveKeys?: Iterable<string>;
  maskFields?: FieldMask[];
  rules?: RedactionRule[];
  preserveFirst?: number;
  preserveLast?: number;
  maxDepth?: number;
  maxArrayLength?: number;
  maskStringValues?: boolean;
}

export interface LogEntry {
  level: LogLevel;
  message: unknown;
  timestamp: string;
  context?: unknown;
  service?: string;
  transactionId?: string;
}

export type LoggerSink = Partial<Record<LogLevel | "log", (entry: string) => void>>;

export interface LoggerOptions extends MaskOptions {
  level?: LogLevel;
  service?: string;
  sink?: LoggerSink;
  formatter?: (entry: LogEntry) => unknown;
  transactionId?: string | (() => string);
  transactionIdGenerator?: () => string;
}

export interface PiiSafeLogger {
  debug(message?: unknown, ...meta: unknown[]): void;
  info(message?: unknown, ...meta: unknown[]): void;
  warn(message?: unknown, ...meta: unknown[]): void;
  error(message?: unknown, ...meta: unknown[]): void;
  log(message?: unknown, ...meta: unknown[]): void;
  child(context?: Record<string, unknown>): PiiSafeLogger;
  withTransaction(transactionId?: string): PiiSafeLogger;
}

export declare const DEFAULT_REDACT_FIELDS: string[];
export declare const DEFAULT_REDACTION_RULES: RedactionRule[];

export declare function createPiiSafeLogger(options?: LoggerOptions): PiiSafeLogger;
export declare function createTransactionId(prefix?: string): string;
export declare function createMask(options?: MaskOptions): (value: unknown) => string;
export declare function maskValue(value: unknown, options?: MaskOptions): unknown;
export declare function redact<T>(value: T, options?: MaskOptions): T;
export declare function redactString(value: string, options?: MaskOptions): string;
export declare function maskPii<T>(value: T, options?: MaskOptions): T;

import test from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import {
  DEFAULT_REDACTION_RULES,
  createMask,
  createComplianceOptions,
  createPinoPiiSafeLogger,
  createPinoRedactionHooks,
  createPiiSafeLogger,
  createTransactionId,
  createWinstonPiiSafeLogger,
  createWinstonRedactionFormat,
  maskPii,
  maskValue,
  redact,
  redactString
} from "../src/index.js";

test("maskPii redacts common sensitive fields and patterns", () => {
  const input = {
    email: "ana@example.com",
    password: "super-secret",
    profile: {
      phone: "+1 (555) 123-4567",
      notes: "Contact ana@example.com with card 4111 1111 1111 1111"
    }
  };

  const output = maskPii(input);

  assert.equal(output.email, "[REDACTED]");
  assert.equal(output.password, "[REDACTED]");
  assert.equal(output.profile.phone, "[REDACTED]");
  assert.equal(output.profile.notes, "Contact [REDACTED] with card [REDACTED]");
});

test("maskPii handles circular references", () => {
  const input = { token: "abc", nested: {} };
  input.nested.self = input;

  const output = maskPii(input);

  assert.equal(output.token, "[REDACTED]");
  assert.equal(output.nested.self, "[Circular]");
});

test("createPiiSafeLogger emits masked logs", () => {
  const lines = [];
  const sink = {
    info(line) {
      lines.push(line);
    }
  };

  const logger = createPiiSafeLogger({ sink, level: "debug" });
  logger.info("User login", { email: "ana@example.com", password: "secret" });

  assert.equal(lines.length, 1);
  assert.match(lines[0], /User login/);
  assert.match(lines[0], /\[REDACTED\]/);
  assert.doesNotMatch(lines[0], /ana@example\.com/);
});

test("maskPii can preserve free-form strings when requested", () => {
  const output = maskPii("contact ana@example.com", { maskStringValues: false });

  assert.equal(output, "contact ana@example.com");
});

test("redactString supports partial masking", () => {
  const output = redactString("Customer luis@example.com", {
    preserveFirst: 2,
    preserveLast: 4
  });

  assert.equal(output, "Customer lu[REDACTED].com");
});

test("redact supports custom field names and field masks", () => {
  const output = redact(
    {
      accountNumber: "123456789",
      documentId: "00112345678",
      cardNumber: "4111111111111111",
      email: "luis@example.com"
    },
    {
      redactFields: ["accountNumber", /document/i],
      maskFields: [
        { field: "cardNumber", preserveFirst: 6, preserveLast: 4, replacement: "******" },
        { field: "email", preserveFirst: 2, preserveLast: 4 }
      ]
    }
  );

  assert.equal(output.accountNumber, "[REDACTED]");
  assert.equal(output.documentId, "[REDACTED]");
  assert.equal(output.cardNumber, "411111******1111");
  assert.equal(output.email, "lu[REDACTED].com");
});

test("custom rules can extend default string redaction", () => {
  const output = redactString("Customer loaded: cus_123456789 for luis@example.com", {
    rules: [
      ...DEFAULT_REDACTION_RULES,
      {
        name: "internal-customer-id",
        reason: "custom",
        pattern: /\bcus_[a-z0-9]+\b/gi,
        replacement: createMask({
          preserveFirst: 4,
          preserveLast: 4,
          replacement: "****"
        })
      }
    ]
  });

  assert.equal(output, "Customer loaded: cus_****6789 for [REDACTED]");
});

test("maskValue can preserve safe fragments", () => {
  assert.equal(maskValue("4111111111111111", { preserveFirst: 6, preserveLast: 4, replacement: "******" }), "411111******1111");
});

test("createPiiSafeLogger emits structured masked logs with child context and transactions", () => {
  const lines = [];
  const sink = {
    info(line) {
      lines.push(JSON.parse(line));
    }
  };

  const logger = createPiiSafeLogger({
    sink,
    service: "payments-service",
    transactionIdGenerator: () => "txn-payment-001"
  });

  logger
    .withTransaction()
    .child({ requestId: "req_123", userId: "usr_456" })
    .info("Payment created for luis@example.com", {
      cardNumber: "4111111111111111",
      amount: 250,
      authorization: "Bearer abc.def.ghi"
    });

  assert.equal(lines.length, 1);
  assert.equal(lines[0].level, "info");
  assert.equal(lines[0].message, "Payment created for [REDACTED]");
  assert.equal(lines[0].service, "payments-service");
  assert.equal(lines[0].transactionId, "txn-payment-001");
  assert.equal(lines[0].context.requestId, "req_123");
  assert.equal(lines[0].context.userId, "usr_456");
  assert.equal(lines[0].context.cardNumber, "[REDACTED]");
  assert.equal(lines[0].context.authorization, "[REDACTED]");
  assert.equal(lines[0].context.amount, 250);
});

test("createTransactionId creates prefixed non-sensitive identifiers", () => {
  assert.match(createTransactionId("payment"), /^payment_[a-z0-9]+_[a-f0-9]+$/);
});

test("CommonJS entrypoint exposes the same core API", () => {
  const require = createRequire(import.meta.url);
  const cjs = require("../src/index.cjs");

  assert.equal(typeof cjs.createPiiSafeLogger, "function");
  assert.equal(typeof cjs.createComplianceOptions, "function");
  assert.equal(cjs.redactString("Email: luis@example.com"), "Email: [REDACTED]");
});

test("compliance presets redact GDPR, HIPAA and PCI payloads", () => {
  const safe = redact(
    {
      email: "ana@example.com",
      ipAddress: "192.168.1.10",
      nationalId: "001-1234567-8",
      patientName: "Ana Tavarez",
      mrn: "MRN-0098123",
      diagnosis: "hypertension",
      cardNumber: "4111 1111 1111 1111",
      cvv: "123",
      trackData: "%B4111111111111111^TAVAREZ/ANA^29051200000000000000?",
      notes: "patient_id=ABCD1234 paid with 4111111111111111 from 10.0.0.2"
    },
    createComplianceOptions("gdpr", "hipaa", "pci")
  );

  const serialized = JSON.stringify(safe);
  assert.doesNotMatch(serialized, /ana@example\.com/i);
  assert.doesNotMatch(serialized, /192\.168\.1\.10/);
  assert.doesNotMatch(serialized, /001-1234567-8/);
  assert.doesNotMatch(serialized, /Ana Tavarez/);
  assert.doesNotMatch(serialized, /MRN-0098123/);
  assert.doesNotMatch(serialized, /4111/);
  assert.doesNotMatch(serialized, /%B411/);
  assert.doesNotMatch(serialized, /10\.0\.0\.2/);
});

test("Winston wrapper redacts messages before writing to the target logger", () => {
  const lines = [];
  const winston = {
    info(line) {
      lines.push(line);
    }
  };

  const logger = createWinstonPiiSafeLogger(winston, {
    ...createComplianceOptions("gdpr", "pci"),
    service: "checkout"
  });

  logger.info("Checkout for luis@example.com", {
    cardNumber: "4111111111111111",
    ipAddress: "172.16.1.9"
  });

  assert.equal(lines.length, 1);
  assert.doesNotMatch(lines[0], /luis@example\.com/);
  assert.doesNotMatch(lines[0], /4111111111111111/);
  assert.doesNotMatch(lines[0], /172\.16\.1\.9/);
});

test("Pino wrapper and hooks redact object and string arguments", () => {
  const lines = [];
  const pino = {
    info(line) {
      lines.push(line);
    }
  };

  const logger = createPinoPiiSafeLogger(pino, createComplianceOptions("pci"));
  logger.info("Card 4111111111111111", { cvv: "123" });

  assert.doesNotMatch(lines[0], /4111111111111111/);
  assert.doesNotMatch(lines[0], /123/);

  const hook = createPinoRedactionHooks(createComplianceOptions("gdpr"));
  const hookLines = [];
  hook.logMethod([
    { email: "ana@example.com" },
    "from 192.168.1.10"
  ], function capture(...args) {
    hookLines.push(args);
  });

  assert.equal(hookLines[0][0].email, "[REDACTED]");
  assert.equal(hookLines[0][1], "from [REDACTED]");
});

test("Winston format helper returns a redacted info object", () => {
  const format = createWinstonRedactionFormat(createComplianceOptions("hipaa"));
  const output = format({
    level: "info",
    message: "patient_id=ABCD1234",
    patientName: "Ana Tavarez"
  });

  assert.equal(output.patientName, "[REDACTED]");
  assert.doesNotMatch(output.message, /ABCD1234/);
});

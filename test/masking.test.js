import test from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import {
  DEFAULT_REDACTION_RULES,
  createMask,
  createPiiSafeLogger,
  createTransactionId,
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
  assert.equal(cjs.redactString("Email: luis@example.com"), "Email: [REDACTED]");
});

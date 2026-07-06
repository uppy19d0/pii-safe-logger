import test from "node:test";
import assert from "node:assert/strict";
import { createPiiSafeLogger, maskPii } from "../src/index.js";

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

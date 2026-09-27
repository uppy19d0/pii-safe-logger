import test from "node:test";
import assert from "node:assert/strict";
import { createComplianceOptions, createPiiSafeLogger, redact, redactString } from "../src/index.js";

const sampleSlackToken = ["xoxb", "123456789012", "123456789012", "abcdefghijklmnopqrstuvwx"].join("-");

const leakCorpus = [
  {
    name: "cloud and source-control secrets",
    payload: {
      message: "deploy with AKIAIOSFODNN7EXAMPLE and ghp_1234567890abcdefghijklmnopqrstuvwxyzABCDEF",
      slack: sampleSlackToken,
      databaseUrl: "postgres://app_user:superSecretPassword@db.example.com:5432/payments"
    },
    forbidden: [
      "AKIAIOSFODNN7EXAMPLE",
      "ghp_1234567890abcdefghijklmnopqrstuvwxyzABCDEF",
      sampleSlackToken,
      "postgres://app_user:superSecretPassword@db.example.com:5432/payments"
    ]
  },
  {
    name: "regulated personal and health data",
    payload: {
      patientName: "María Gómez",
      mrn: "MRN-991122",
      diagnosis: "diabetes",
      email: "maria.gomez@example.com",
      ipAddress: "203.0.113.24",
      notes: "patient_id=PAT-445566 connected from 203.0.113.24"
    },
    options: createComplianceOptions("gdpr", "hipaa"),
    forbidden: ["María Gómez", "MRN-991122", "diabetes", "maria.gomez@example.com", "203.0.113.24", "PAT-445566"]
  },
  {
    name: "payment data and magnetic stripe track data",
    payload: {
      cardNumber: "4111111111111111",
      cvv: "123",
      cardholderName: "LUIS TAVAREZ",
      trackData: "%B4111111111111111^TAVAREZ/LUIS^29051200000000000000?"
    },
    options: createComplianceOptions("pci"),
    forbidden: ["4111111111111111", "123", "LUIS TAVAREZ", "%B4111111111111111"]
  },
  {
    name: "private key blocks",
    payload: {
      key: "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----"
    },
    forbidden: ["BEGIN PRIVATE KEY", "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC", "END PRIVATE KEY"]
  }
];

for (const corpus of leakCorpus) {
  test(`security corpus redacts ${corpus.name}`, () => {
    const safe = redact(corpus.payload, corpus.options);
    const serialized = JSON.stringify(safe);

    for (const forbidden of corpus.forbidden) {
      assert.doesNotMatch(serialized, new RegExp(escapeRegExp(forbidden), "u"));
    }
  });
}

test("logger output does not leak corpus values", () => {
  const lines = [];
  const logger = createPiiSafeLogger({
    sink: {
      info(line) {
        lines.push(line);
      }
    },
    ...createComplianceOptions("gdpr", "hipaa", "pci")
  });

  for (const corpus of leakCorpus) {
    logger.info(`corpus ${corpus.name}`, corpus.payload);
  }

  const output = lines.join("\n");
  for (const corpus of leakCorpus) {
    for (const forbidden of corpus.forbidden) {
      assert.doesNotMatch(output, new RegExp(escapeRegExp(forbidden), "u"));
    }
  }
});

test("redactString removes common secret strings outside object context", () => {
  const input = [
    "Authorization: Bearer abc.def.ghi",
    "AKIAIOSFODNN7EXAMPLE",
    "ghp_1234567890abcdefghijklmnopqrstuvwxyzABCDEF",
    "redis://:secret@example.com:6379/0"
  ].join(" ");

  const output = redactString(input);

  assert.doesNotMatch(output, /Bearer abc\.def\.ghi/u);
  assert.doesNotMatch(output, /AKIAIOSFODNN7EXAMPLE/u);
  assert.doesNotMatch(output, /ghp_1234567890abcdefghijklmnopqrstuvwxyzABCDEF/u);
  assert.doesNotMatch(output, /redis:\/\/:secret@example\.com/u);
});

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

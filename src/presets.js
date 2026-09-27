import { DEFAULT_REDACT_FIELDS, DEFAULT_REDACTION_RULES } from "./masking.js";

const NATIONAL_ID_PATTERN = /\b(?:\d{3}-?\d{7}-?\d{1}|\d{9,12})\b/g;
const IP_ADDRESS_PATTERN = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g;
const MEDICAL_RECORD_PATTERN = /\b(?:mrn|medical[_\s-]?record|patient[_\s-]?id)\s*[:=]\s*["']?[A-Za-z0-9._-]{4,}\b/gi;
const PCI_TRACK_PATTERN = /%(?:B|\d)[^^\s]{6,}\^[^^\s]*\^[^^\s]*\?/g;

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

export const COMPLIANCE_PRESETS = Object.freeze({
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
    rules: [
      { name: "pci-track-data", reason: "payment-card", pattern: PCI_TRACK_PATTERN }
    ],
    maskFields: [
      { field: "last4", preserveLast: 4 },
      { field: "cardLast4", preserveLast: 4 }
    ],
    maxDepth: 8
  })
});

export function getCompliancePreset(name) {
  const preset = COMPLIANCE_PRESETS[String(name).toLowerCase()];

  if (!preset) {
    throw new Error(`Unknown compliance preset: ${name}`);
  }

  return preset;
}

export function createComplianceOptions(...presetNames) {
  const presets = presetNames.length > 0 ? presetNames.map(getCompliancePreset) : [COMPLIANCE_PRESETS.gdpr];

  return {
    redactFields: uniqueFields(...presets.map((preset) => preset.redactFields)),
    rules: presets.flatMap((preset) => preset.rules),
    maskFields: presets.flatMap((preset) => preset.maskFields || []),
    maxDepth: Math.min(...presets.map((preset) => preset.maxDepth || 12)),
    maxArrayLength: Math.min(...presets.map((preset) => preset.maxArrayLength || 100))
  };
}

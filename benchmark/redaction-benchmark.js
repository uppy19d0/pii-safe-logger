import { performance } from "node:perf_hooks";
import { createComplianceOptions, redact } from "../src/index.js";

const iterations = Number(process.env.ITERATIONS || 25_000);
const options = createComplianceOptions("gdpr", "hipaa", "pci");
const payload = {
  requestId: "req_01J9A6Y2",
  user: {
    id: "usr_123456789",
    email: "ana@example.com",
    phone: "+1 809 555 1234",
    ipAddress: "192.168.1.10",
    nationalId: "001-1234567-8"
  },
  payment: {
    cardNumber: "4111 1111 1111 1111",
    cvv: "123",
    trackData: "%B4111111111111111^TAVAREZ/ANA^29051200000000000000?"
  },
  healthcare: {
    patientName: "Ana Tavarez",
    mrn: "MRN-0098123",
    diagnosis: "follow-up"
  },
  message: "Authorization: Bearer abc.def.ghi for ana@example.com"
};

const started = performance.now();
let last;

for (let index = 0; index < iterations; index += 1) {
  last = redact(payload, options);
}

const elapsed = performance.now() - started;
const opsPerSecond = Math.round((iterations / elapsed) * 1000);

console.log(JSON.stringify({
  iterations,
  elapsedMs: Number(elapsed.toFixed(2)),
  opsPerSecond,
  sample: last
}, null, 2));

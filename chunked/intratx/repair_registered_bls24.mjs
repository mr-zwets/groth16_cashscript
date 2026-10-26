// Repair only the frozen registered BLS12-381 quotient-torus24 artifact, without running a verifier builder.
// Usage: node chunked/intratx/repair_registered_bls24.mjs original.json positives.json
// The manifest records typed compiled gates and exact original/selected program hashes.
// This tool changes code only. Native admission stays HOLD until separately qualified.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const manifest = JSON.parse(readFileSync(new URL('./registered-bls24-repair.json', import.meta.url), 'utf8'));
const sha256 = (bytes) => createHash('sha256').update(bytes).digest();
const digest = (bytes) => sha256(bytes).toString('hex');
const hash256 = (bytes) => sha256(sha256(bytes));
const repairs = new Map(manifest.repairs.map((row) => [row.input, row]));
assert.equal(manifest.originalProgramSha256.length, 24);
assert.equal(manifest.selectedProgramSha256.length, 24);
assert.equal(repairs.size, 2);
for (const repair of repairs.values()) {
  const typed = manifest.typedGuards.find((guard) => guard.length === repair.requiredLength);
  assert(typed);
  assert.equal(digest(Buffer.from(typed.source)), typed.sourceSha256);
  assert.equal(repair.gateHex, repair.argumentDepth === 0 ? typed.gateHex : `5279${typed.gateHex.slice(2)}`);
  assert(repair.input === 23 && repair.argumentDepth === 0 || repair.input === 4 && repair.argumentDepth === 2);
}

/** Only existing positive unlocking scripts are decoded; no argument is re-encoded. */
function pushes(bytes) {
  const result = [];
  let offset = 0;
  while (offset < bytes.length) {
    const start = offset;
    const opcode = bytes[offset++];
    let data;
    if (opcode === 0) data = Buffer.alloc(0);
    else if (opcode === 79) data = Buffer.from([129]);
    else if (opcode >= 81 && opcode <= 96) data = Buffer.from([opcode - 80]);
    else {
      let length;
      if (opcode >= 1 && opcode <= 75) length = opcode;
      else {
        assert(opcode === 76 || opcode === 77 || opcode === 78, 'unlocking must be push-only');
        const width = opcode === 76 ? 1 : opcode === 77 ? 2 : 4;
        assert(offset + width <= bytes.length);
        length = bytes.readUIntLE(offset, width);
        offset += width;
      }
      assert(offset + length <= bytes.length);
      data = bytes.subarray(offset, offset + length);
      offset += length;
    }
    result.push({ start, end: offset, data });
  }
  return result;
}

/** Canonical push of executable code only; proof/state/padding pushes remain verbatim. */
function pushCode(bytes) {
  assert(bytes.length > 1 && bytes.length <= 65535);
  const header = bytes.length <= 75 ? Buffer.from([bytes.length])
    : bytes.length <= 255 ? Buffer.from([76, bytes.length])
      : Buffer.from([77, bytes.length & 255, bytes.length >>> 8]);
  return Buffer.concat([header, bytes]);
}

export function repairBody(body, input) {
  assert(Number.isInteger(input) && input >= 0 && input < 24);
  assert.equal(digest(body), manifest.originalProgramSha256[input], `original body ${input}`);
  const repair = repairs.get(input);
  const selected = repair ? Buffer.concat([
    body.subarray(0, repair.gateOffset), Buffer.from(repair.gateHex, 'hex'), body.subarray(repair.gateOffset),
  ]) : body;
  assert.equal(digest(selected), manifest.selectedProgramSha256[input], `selected body ${input}`);
  return selected;
}

export function lockingBytecode(body) {
  return Buffer.concat([Buffer.from('aa20', 'hex'), hash256(body), Buffer.from('87', 'hex')]);
}

function repairRun(steps) {
  assert.equal(steps.length, 24);
  return steps.map((step, input) => {
    const unlocking = Buffer.from(step.unlocking, 'hex');
    const originalPushes = pushes(unlocking);
    const final = originalPushes.at(-1);
    assert(final);
    assert(pushCode(final.data).equals(unlocking.subarray(final.start)), 'noncanonical final code push');
    assert.equal(lockingBytecode(final.data).toString('hex'), step.locking, `original P2SH32 ${input}`);
    const repair = repairs.get(input);
    if (repair) { assert.equal(originalPushes[0].data.length, repair.requiredLength); assert.equal(originalPushes.length, repair.argumentDepth + 3); }
    const selected = repairBody(final.data, input);
    const prefix = unlocking.subarray(0, final.start);
    const next = Buffer.concat([prefix, pushCode(selected)]);
    assert(next.subarray(0, prefix.length).equals(prefix));
    return { ...step, locking: lockingBytecode(selected).toString('hex'), unlocking: next.toString('hex') };
  });
}

export function repairPositiveArtifact(originalBytes) {
  assert.equal(digest(originalBytes), manifest.inputFixtureSha256, 'requires exact frozen registered_bls24 artifact');
  const original = JSON.parse(originalBytes.toString('utf8'));
  assert.equal(original.extraValidProofs.length, 1);
  const steps = repairRun(original.steps);
  return {
    description: 'Frozen registered BLS12-381 quotient-torus24 mathematical repair: exact432-byte carrier and1632-byte terminal owner; positive contexts only. Native admission HOLD.',
    method: original.method,
    deployment: original.deployment,
    curve: original.curve,
    numInputs: 24,
    budgetPerInput: original.budgetPerInput,
    totalBytes: steps.reduce((sum, step) => sum + (step.locking.length + step.unlocking.length) / 2, 0),
    steps,
    extraValidProofs: original.extraValidProofs.map(repairRun),
    worstCaseProof: repairRun(original.worstCaseProof),
    repair: {
      schema: manifest.schema,
      originalFixtureSha256: manifest.inputFixtureSha256,
      selectedProgramSha256: manifest.selectedProgramSha256,
      statement: manifest.statement,
      premises: manifest.premises,
      nativeAdmission: 'HOLD',
      standardAdmission: 'HOLD',
      negatives: 'Original negative fixtures remain in the unchanged historical artifact; none are generated or included here.',
    },
  };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [input, output, ...extra] = process.argv.slice(2);
  assert(input && output && extra.length === 0,
    'usage: node repair_registered_bls24.mjs <exact-original.json> <new-positive-only.json>');
  assert.notEqual(resolve(input), resolve(output));
  const packet = repairPositiveArtifact(readFileSync(input));
  writeFileSync(output, `${JSON.stringify(packet, null, 2)}\n`, { flag: 'wx' });
  console.log(JSON.stringify({ inputs: 24, positiveContexts: 3, guardedPrograms: 2, nativeAdmission: 'HOLD', output }));
}

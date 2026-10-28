// Repair the frozen registered BLS12-381 residue-large artifact without running a builder.
// Positive contexts only: no invalid fixture is read, generated, or re-encoded.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const manifest = JSON.parse(readFileSync(new URL('./registered-bls-large-repair.json', import.meta.url), 'utf8'));
const sha256 = (bytes) => createHash('sha256').update(bytes).digest();
const digest = (bytes) => sha256(bytes).toString('hex');
const hash256 = (bytes) => sha256(sha256(bytes));
const repairs = new Map(manifest.repairs.map((row) => [row.input, row]));
assert.equal(manifest.originalProgramSha256.length, 3);
assert.equal(manifest.selectedProgramSha256.length, 3);
assert.equal(repairs.size, 3);

function pushes(bytes) {
  const result = [];
  let offset = 0;
  while (offset < bytes.length) {
    const start = offset;
    const opcode = bytes[offset++];
    let length;
    if (opcode === 0) length = 0;
    else if (opcode >= 1 && opcode <= 75) length = opcode;
    else if (opcode === 76) { assert(offset < bytes.length); length = bytes[offset++]; }
    else if (opcode === 77) {
      assert(offset + 2 <= bytes.length);
      length = bytes.readUIntLE(offset, 2);
      offset += 2;
    } else if (opcode === 78) {
      assert(offset + 4 <= bytes.length);
      length = bytes.readUIntLE(offset, 4);
      offset += 4;
    } else if (opcode >= 81 && opcode <= 96) {
      result.push({ start, end: offset, data: Buffer.from([opcode - 80]) });
      continue;
    } else assert.fail(`positive unlocking is not push-only: ${opcode.toString(16)}`);
    assert(offset + length <= bytes.length);
    result.push({ start, end: offset + length, data: bytes.subarray(offset, offset + length) });
    offset += length;
  }
  return result;
}

function pushCode(bytes) {
  assert(bytes.length > 0 && bytes.length <= 65535);
  const header = bytes.length <= 75 ? Buffer.from([bytes.length])
    : bytes.length <= 255 ? Buffer.from([76, bytes.length])
      : Buffer.from([77, bytes.length & 255, bytes.length >>> 8]);
  return Buffer.concat([header, bytes]);
}

export function repairBody(body, input) {
  assert(Number.isInteger(input) && input >= 0 && input < 3);
  assert.equal(digest(body), manifest.originalProgramSha256[input], `original body ${input}`);
  const repair = repairs.get(input);
  const selected = repair ? Buffer.concat([
    body.subarray(0, repair.gateOffset), Buffer.from(repair.gateHex, 'hex'), body.subarray(repair.gateOffset),
  ]) : body;
  assert.equal(digest(selected), manifest.selectedProgramSha256[input], `selected body ${input}`);
  if (repair) {
    assert.equal(digest(body.subarray(0, repair.gateOffset)), repair.registryPrefixSha256);
    assert.equal(digest(body.subarray(repair.gateOffset)), repair.registrySuffixSha256);
  }
  return selected;
}

export function lockingBytecode(body) {
  return Buffer.concat([Buffer.from('aa20', 'hex'), hash256(body), Buffer.from('87', 'hex')]);
}

function repairRun(steps) {
  assert.equal(steps.length, 3);
  return steps.map((step, input) => {
    const unlocking = Buffer.from(step.unlocking, 'hex');
    const originalPushes = pushes(unlocking);
    const final = originalPushes.at(-1);
    assert(final);
    assert(pushCode(final.data).equals(unlocking.subarray(final.start)), `noncanonical final code push ${input}`);
    assert.equal(lockingBytecode(final.data).toString('hex'), step.locking, `original P2SH32 ${input}`);
    const repair = repairs.get(input);
    if (repair) assert.equal(originalPushes[0].data.length, repair.requiredLength);
    const selected = repairBody(final.data, input);
    const prefix = unlocking.subarray(0, final.start);
    const next = Buffer.concat([prefix, pushCode(selected)]);
    assert(next.subarray(0, prefix.length).equals(prefix));
    return { ...step, locking: lockingBytecode(selected).toString('hex'), unlocking: next.toString('hex') };
  });
}

export function repairPositiveArtifact(originalBytes) {
  assert.equal(digest(originalBytes), manifest.inputFixtureSha256, 'requires exact frozen residue-large artifact');
  const original = JSON.parse(originalBytes.toString('utf8'));
  assert.equal(original.numInputs, 3);
  assert.equal(original.extraValidProofs.length, 1);
  const steps = repairRun(original.steps);
  return {
    description: 'Frozen registered BLS12-381 residue-large mathematical repair: exact 288-byte GLV carrier, 768-byte input-validation carrier, and 1632-byte terminal owner; positive contexts only. Native admission HOLD.',
    method: original.method,
    deployment: original.deployment,
    curve: original.curve,
    numInputs: 3,
    budgetPerInput: original.budgetPerInput,
    totalBytes: steps.reduce((sum, step) => sum + (step.locking.length + step.unlocking.length) / 2, 0),
    steps,
    extraValidProofs: original.extraValidProofs.map(repairRun),
    worstCaseProof: repairRun(original.worstCaseProof),
    repair: {
      schema: manifest.schema,
      originalFixtureSha256: manifest.inputFixtureSha256,
      selectedProgramSha256: manifest.selectedProgramSha256,
      statement: 'The selected positive fixture keeps every non-code byte identical and adds only the three role-specific exact frame predicates. This is an artifact correction, not a current-BCH or full-domain admission certificate.',
      scope: manifest.scope,
      sourceBinding: manifest.sourceBinding,
      negatives: 'Original invalid fixtures remain only in the unchanged historical input; none are read or emitted by this helper.',
    },
  };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [input, output, ...extra] = process.argv.slice(2);
  assert(input && output && extra.length === 0, 'usage: node repair_registered_bls_large.mjs <exact-original.json> <new-positive-only.json>');
  assert.notEqual(resolve(input), resolve(output));
  writeFileSync(output, `${JSON.stringify(repairPositiveArtifact(readFileSync(input)), null, 2)}\n`, { flag: 'wx' });
  console.log(JSON.stringify({ inputs: 3, positiveContexts: 3, guardedPrograms: 3, nativeAdmission: 'HOLD', output }));
}

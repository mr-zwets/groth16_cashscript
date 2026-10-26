// Frozen positive-artifact repair for the BN254 linked-frame profiles.
//
// This helper does not build proofs or verifier programs. It takes an existing
// positive vector fixture, inserts the compiled exact-length frame predicate
// after the archived redeem OP_DROP, and transfers only the embedded successor
// locking/hash bindings required by that byte change. All witness/state/table/
// padding pushes are retained byte-for-byte.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { compileString, utils } from 'cashc';
import {
  bigIntToVmNumber,
  encodeDataPush,
  encodeLockingBytecodeP2sh32,
  hash256,
  hexToBin,
} from '@bitauth/libauth';

const sha256 = (value) => createHash('sha256').update(value).digest('hex');

// Public allowlist: this helper is intentionally limited to the five archived
// BN positive fixtures reviewed for this correction. The hash is over the raw
// fixture bytes, not a re-serialized object.
export const SUPPORTED_FIXTURE_SHA256 = Object.freeze({
  'd40e1f8d5135d400f6b2857425f3e136537566661429aa0aed64e273efbb20ae': 'bch-groth16-intratx',
  '1aac568c7ea1e1ef36c2ba3631be90f768e24095a5e1b71f305164fd0d29057e': 'bch-groth16-grouped',
  '67d41af69ee26915c87d69dc09f2ce49db63ef02296c418cfe546a1ff2446860': 'bch-pairing-intratx',
  '593111c80eab0c8c933430770e8d622eeadf6df1f4bd08b7e2ed2c69aad17367': 'bch-groth16-intratx-residue',
  '8edb47b609f7339007af7922ffe0ec5105da90dd0335d388540a9a5fd786d190': 'bch-groth16-grouped-residue',
});

// These certificate hashes pin the selected gate bytes. A compiler change or
// instruction-boundary mistake therefore fails before a new artifact is saved.
const EXPECTED_GATE_CERTIFICATE_SHA256 = Object.freeze({
  'bch-groth16-intratx': '64204ee70e29cdacabd16c74eb0cace887412652f0d3b0a8433570a35c50288e',
  'bch-groth16-grouped': '64204ee70e29cdacabd16c74eb0cace887412652f0d3b0a8433570a35c50288e',
  'bch-pairing-intratx': '9e64d10e84692b858e10b21290e4bd2c3d1cfa8f48b0aa35179d1fca842b5720',
  'bch-groth16-intratx-residue': '3135281c35708c30910c1113a490477c188e95be805dcc05eea1efce573d7e3c',
  'bch-groth16-grouped-residue': '237a11dcc5bdc366f3b6082db857c706e380755a096681a1d008c7de7542a110',
});

export function parsePushes(bytes) {
  const pushes = [];
  let offset = 0;
  while (offset < bytes.length) {
    const start = offset;
    const opcode = bytes[offset++];
    let length;
    if (opcode === 0 || (opcode >= 0x51 && opcode <= 0x60)) length = 0;
    else if (opcode >= 1 && opcode <= 75) length = opcode;
    else if (opcode === 0x4c) { assert(offset < bytes.length); length = bytes[offset++]; }
    else if (opcode === 0x4d) { assert(offset + 1 < bytes.length); length = bytes[offset] | (bytes[offset + 1] << 8); offset += 2; }
    else if (opcode === 0x4e) { assert(offset + 3 < bytes.length); length = bytes.readUInt32LE(offset); offset += 4; }
    else throw new Error(`non-push opcode 0x${opcode.toString(16)}`);
    const data = bytes.slice(offset, offset + length);
    assert.equal(data.length, length, 'truncated push');
    offset += length;
    pushes.push({start, end: offset, opcode, length, data});
  }
  return pushes;
}

function exactGate(frameLength, depth) {
  const source = `pragma cashscript ^0.14.0;\ncontract Frame() {\n    function spend(bytes inBlob) {\n        require(inBlob.length == ${frameLength});\n        require(hash256(inBlob) == 0x${'00'.repeat(32)});\n    }\n}\n`;
  const compiled = Uint8Array.from(utils.asmToBytecode(compileString(source, {rescheduleStacks: true}).bytecode));
  let offset = 0;
  let equalVerify = -1;
  while (offset < compiled.length) {
    const start = offset;
    const opcode = compiled[offset++];
    if (opcode >= 1 && opcode <= 75) offset += opcode;
    else if (opcode === 0x4c) { assert(offset < compiled.length); offset += 1 + compiled[offset]; }
    else if (opcode === 0x4d) { assert(offset + 1 < compiled.length); offset += 2 + compiled[offset] + (compiled[offset + 1] << 8); }
    else if (opcode === 0x4e) {
      assert(offset + 3 < compiled.length);
      offset += 4 + (compiled[offset] | (compiled[offset + 1] << 8) | (compiled[offset + 2] << 16) | (compiled[offset + 3] << 24));
    }
    if (opcode === 0x9d) { equalVerify = start; break; }
    assert(offset <= compiled.length, `truncated compiled gate for ${frameLength}`);
  }
  assert(equalVerify > 0, `missing exact-length predicate for ${frameLength}`);
  const typed = compiled.slice(0, equalVerify + 1);
  let inserted;
  if (depth === 0) inserted = typed;
  else if (depth === 1) inserted = Uint8Array.from([0x7c, ...typed, 0x7c]);
  else {
    const index = depth <= 16 ? Uint8Array.from([0x50 + depth]) : encodeDataPush(bigIntToVmNumber(BigInt(depth)));
    // Check a copied state item, then remove only that checked copy.
    inserted = Uint8Array.from([...index, 0x79, ...typed, 0x75]);
  }
  return {
    inserted,
    certificate: {
      frameLength,
      depth,
      sourceSha256: sha256(Buffer.from(source)),
      compiledSha256: sha256(compiled),
      typedGateHex: Buffer.from(typed).toString('hex'),
      insertedGateHex: Buffer.from(inserted).toString('hex'),
    },
  };
}

function replaceOne(program, oldBytes, newBytes, label) {
  const offsets = [];
  for (let offset = 0; offset <= program.length - oldBytes.length; offset++) {
    if (Buffer.from(program.slice(offset, offset + oldBytes.length)).equals(oldBytes)) offsets.push(offset);
  }
  if (offsets.length === 0) return {program, transfer: undefined};
  assert.equal(offsets.length, 1, `${label}: ambiguous binding`);
  const replaced = Uint8Array.from(program);
  replaced.set(newBytes, offsets[0]);
  return {program: replaced, transfer: {offset: offsets[0]}};
}

function repairStep(raw, successorLocks, successorNewLocks, certificates) {
  const unlocking = hexToBin(raw.unlocking);
  const pushes = parsePushes(unlocking);
  assert(pushes.length >= 3, `${raw.label}: expected state, pad, redeem`);
  const state = pushes[0];
  const redeem = pushes.at(-1);
  assert.equal(redeem.end, unlocking.length, `${raw.label}: redeem must be final push`);
  const expectedHeader = state.length <= 75 ? state.length : state.length <= 255 ? 0x4c : 0x4d;
  assert.equal(state.opcode, expectedHeader, `${raw.label}: noncanonical state header`);
  assert.equal(redeem.data[0], 0x75, `${raw.label}: redeem does not begin OP_DROP`);
  const depth = pushes.slice(1, -2).length;
  const {inserted, certificate} = exactGate(state.length, depth);
  certificates.push(certificate);
  const oldProgram = redeem.data;
  let program = Uint8Array.from([oldProgram[0], ...inserted, ...oldProgram.slice(1)]);
  assert.deepEqual(program.slice(1 + inserted.length), oldProgram.slice(1), `${raw.label}: suffix changed`);
  const lockingHashTransfers = [];
  const lockingHash256Transfers = [];
  const lockingBytecodeTransfers = [];
  successorLocks.forEach((oldLocking, successorIndex) => {
    const newLocking = successorNewLocks[successorIndex];
    if (!newLocking) return;
    const oldHash = Buffer.from(sha256(hexToBin(oldLocking)), 'hex');
    const newHash = Buffer.from(sha256(hexToBin(newLocking)), 'hex');
    const hashResult = replaceOne(program, oldHash, newHash, `${raw.label}: successor hash`);
    program = hashResult.program;
    if (hashResult.transfer) lockingHashTransfers.push({successorIndex, ...hashResult.transfer, oldHash: oldHash.toString('hex'), newHash: newHash.toString('hex')});
    const oldHash256 = Buffer.from(hash256(hexToBin(oldLocking)));
    const newHash256 = Buffer.from(hash256(hexToBin(newLocking)));
    const hash256Result = replaceOne(program, oldHash256, newHash256, `${raw.label}: successor hash256`);
    program = hash256Result.program;
    if (hash256Result.transfer) lockingHash256Transfers.push({successorIndex, ...hash256Result.transfer, oldHash: oldHash256.toString('hex'), newHash: newHash256.toString('hex')});
    const oldBytes = hexToBin(oldLocking);
    const newBytes = hexToBin(newLocking);
    const byteResult = replaceOne(program, oldBytes, newBytes, `${raw.label}: successor locking`);
    program = byteResult.program;
    if (byteResult.transfer) lockingBytecodeTransfers.push({successorIndex, ...byteResult.transfer, oldLocking, newLocking});
  });
  const prefix = unlocking.slice(0, redeem.start);
  const repairedUnlocking = Uint8Array.from([...prefix, ...encodeDataPush(program)]);
  assert.deepEqual(repairedUnlocking.slice(0, prefix.length), prefix, `${raw.label}: prefix changed`);
  const repairedLocking = encodeLockingBytecodeP2sh32(hash256(program));
  return {
    ...(({invalidUnlocking: _invalidUnlocking, ...positiveRaw}) => positiveRaw)(raw),
    locking: Buffer.from(repairedLocking).toString('hex'),
    unlocking: Buffer.from(repairedUnlocking).toString('hex'),
    frameLength: state.length,
    argumentDepth: depth,
    originalProgramSha256: sha256(oldProgram),
    repairedProgramSha256: sha256(program),
    originalProgramSuffixSha256: sha256(oldProgram.slice(1)),
    repairedProgramSuffixSha256: sha256(program.slice(1 + inserted.length)),
    preservedPrefixSha256: sha256(prefix),
    originalStatePushHeaderHex: Buffer.from(unlocking.slice(state.start, state.length < 76 ? state.start + 1 : state.length < 256 ? state.start + 2 : state.start + 3)).toString('hex'),
    originalProgramBytes: oldProgram.length,
    repairedProgramBytes: program.length,
    lockingHashTransfers,
    lockingHash256Transfers,
    lockingBytecodeTransfers,
  };
}

function repairRun(run, certificates) {
  const successorLocks = run.steps.map((step) => step.locking);
  const successorNewLocks = new Array(run.steps.length);
  const steps = new Array(run.steps.length);
  for (let index = run.steps.length - 1; index >= 0; index--) {
    steps[index] = repairStep(run.steps[index], successorLocks, successorNewLocks, certificates);
    successorNewLocks[index] = steps[index].locking;
  }
  if (!run.groups) return {...run, steps};

  // Group transport is part of the verifier's public witness binding. Each
  // nonterminal group must expose the corrected locking of the first step in
  // the next group, not the archived pre-repair locking. Preserve every
  // token/state field while changing only this successor owner.
  const groups = run.groups.map((group, groupIndex) => {
    const nextGroup = run.groups[groupIndex + 1];
    if (!nextGroup) {
      assert.equal(group.outLocking ?? null, null, 'terminal group must not carry an outgoing lock');
      return {...group, outLocking: null};
    }
    const nextStepIndex = nextGroup.lo;
    assert.equal(group.hi + 1, nextStepIndex, 'group ranges must be contiguous');
    assert.equal(group.outLocking, successorLocks[nextStepIndex], 'group successor must name the archived next lock');
    const corrected = {...group, outLocking: steps[nextStepIndex].locking};
    assert.deepEqual(corrected.inToken, group.inToken, 'group input token metadata changed');
    assert.deepEqual(corrected.outToken, group.outToken, 'group output token metadata changed');
    assert.equal(corrected.outLocking, steps[nextStepIndex].locking, 'group successor does not match corrected next lock');
    return corrected;
  });
  return {...run, steps, groups};
}

function positiveRuns(fixture) {
  if (fixture.steps) return [
    {name: 'valid', steps: fixture.steps},
    ...(fixture.extraValidProofs ?? []).map((steps, i) => ({name: `extra-${i}`, steps})),
    ...(fixture.worstCaseProof ? [{name: 'worst-case', steps: fixture.worstCaseProof}] : []),
  ];
  return [
    {name: 'valid', ...fixture.valid},
    ...(fixture.extraValidProofs ?? []).map((run, i) => ({name: `extra-${i}`, ...run})),
    ...(fixture.worstCaseProof ? [{name: 'worst-case', ...fixture.worstCaseProof}] : []),
  ];
}

export function repairFixture(originalBytes) {
  assert(Buffer.isBuffer(originalBytes), 'raw original fixture bytes are required');
  const originalFixtureSha256 = sha256(originalBytes);
  const profile = SUPPORTED_FIXTURE_SHA256[originalFixtureSha256];
  assert(profile, `unsupported original fixture ${originalFixtureSha256}`);
  const fixture = JSON.parse(originalBytes.toString('utf8'));
  const certificates = [];
  const runs = positiveRuns(fixture).map((run) => repairRun(run, certificates));
  const structural = {};
  for (const key of ['category', 'numInputs', 'numGroups', 'groupSizes']) {
    if (fixture[key] !== undefined) structural[key] = fixture[key];
  }
  const positiveKeySet = new Set(['steps', 'valid', 'extraValidProofs', 'worstCaseProof']);
  const historicalOriginalMetadata = Object.fromEntries(Object.entries(fixture)
    .filter(([key]) => !positiveKeySet.has(key) && !Object.hasOwn(structural, key) && key !== 'invalid' && key !== 'invalidInputs'));
  const repaired = {...structural, invalid: [], invalidInputs: []};
  if (fixture.steps) {
    repaired.steps = runs[0].steps;
    repaired.extraValidProofs = (fixture.worstCaseProof ? runs.slice(1, -1) : runs.slice(1)).map((run) => run.steps);
    if (fixture.worstCaseProof) repaired.worstCaseProof = runs.at(-1).steps;
  } else {
    repaired.valid = runs[0];
    repaired.extraValidProofs = runs.slice(1, fixture.worstCaseProof ? -1 : undefined);
    if (fixture.worstCaseProof) repaired.worstCaseProof = runs.at(-1);
  }
  repaired.repair = {
    schema: 'bn254-exact-frame-correction/v1',
    profile,
    originalFixtureSha256,
    gateCertificates: certificates,
    gateCertificateSha256: sha256(Buffer.from(JSON.stringify(certificates))),
    positiveOnly: true,
  };
  assert.equal(repaired.repair.gateCertificateSha256, EXPECTED_GATE_CERTIFICATE_SHA256[profile], `${profile}: gate bytes changed`);
  if (Object.keys(historicalOriginalMetadata).length > 0) repaired.historicalOriginalMetadata = historicalOriginalMetadata;
  return repaired;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const [input, output] = process.argv.slice(2);
  assert(input && output, 'usage: repair_exact_frames.mjs <input.json> <output.json>');
  const originalBytes = readFileSync(input);
  const repaired = repairFixture(originalBytes);
  writeFileSync(output, `${JSON.stringify(repaired)}\n`, {flag: 'wx'});
  console.log(JSON.stringify({output, originalSha256: sha256(originalBytes), repairedSha256: sha256(Buffer.from(JSON.stringify(repaired) + '\n')),
    gates: repaired.repair.gateCertificates.length}));
}

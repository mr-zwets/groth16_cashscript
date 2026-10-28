// Frozen frame repairs for the separately qualified historical program graphs.
// This module never imports a producer, compiler, planner, or negative-case runner.
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFileSync, writeFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {
  bigIntToVmNumber, decodeAuthenticationInstructions, encodeAuthenticationInstructions,
  encodeDataPush, encodeLockingBytecodeP2sh32, hash256,
} from '@bitauth/libauth';

const manifest = JSON.parse(readFileSync(new URL('./historical-frame-repairs.json', import.meta.url)));
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const locking = code => Buffer.from(encodeLockingBytecodeP2sh32(hash256(code)));
const hex = bytes => Buffer.from(bytes).toString('hex');
const pushNumber = value => Buffer.from(encodeDataPush(bigIntToVmNumber(BigInt(value))));

function decodeStep(step) {
  const bytes = Buffer.from(step.unlocking, 'hex');
  const instructions = decodeAuthenticationInstructions(bytes);
  assert(instructions.every(i => !('error' in i) && (i.data !== undefined || i.opcode === 0 ||
    i.opcode === 0x4f || i.opcode >= 0x51 && i.opcode <= 0x60)), 'push-only archived unlocking required');
  const code = instructions.at(-1)?.data;
  assert(code && code.length > 0, 'missing final redeem');
  const codePush = Buffer.from(encodeDataPush(code));
  assert(bytes.subarray(-codePush.length).equals(codePush), 'canonical final code push required');
  assert.equal(hex(locking(code)), step.locking, 'original P2SH32 owner');
  return {instructions, code: Buffer.from(code), prefix: bytes.subarray(0, -codePush.length)};
}

function frameGate(gate) {
  // PICK copies the designated owner. SIZE/NIP leaves only its length; the comparison
  // consumes that length and its bound, preserving the entire original argument stack.
  const pick = gate.depth === 0 ? Buffer.from([0x76])
    : Buffer.concat([pushNumber(gate.depth), Buffer.from([0x79])]);
  assert(gate.comparison === 'equal' || gate.comparison === 'less-than');
  const comparison = gate.comparison === 'equal' ? [0x9d] : [0x9f, 0x69];
  return Buffer.concat([pick, Buffer.from([0x82, 0x77]), pushNumber(gate.length), Buffer.from(comparison)]);
}

function selectCases(artifact, layout) {
  if (layout === 'intratx') return [
    {name: 'primary', steps: artifact.steps},
    ...artifact.extraValidProofs.map((steps, i) => ({name: `extra-${i}`, steps})),
    {name: 'worst-case', steps: artifact.worstCaseProof},
  ];
  assert.equal(layout, 'grouped');
  return [
    {name: 'primary', ...artifact.valid},
    ...artifact.extraValidProofs.map((run, i) => ({name: `extra-${i}`, ...run})),
    {name: 'worst-case', ...artifact.worstCaseProof},
  ];
}

export function repairHistoricalPositives(profileId, originalBytes) {
  const profile = manifest.profiles.find(p => p.id === profileId);
  assert(profile, 'unknown frozen historical profile');
  assert.equal(digest(originalBytes), profile.originalFixture.sha256, 'exact original artifact required');
  const original = JSON.parse(originalBytes);
  const runs = selectCases(original, profile.layout);
  assert.equal(runs.length, profile.caseCount);
  assert.equal(profile.originalProgramSha256.length, profile.programCount);
  assert.equal(profile.repairedProgramSha256.length, profile.programCount);
  const gates = new Map(profile.gates.map(gate => [gate.input, gate]));
  assert.equal(gates.size, profile.gates.length);
  assert(gates.size > 0 && gates.size <= 2);

  const cases = runs.map(run => {
    assert.equal(run.steps.length, profile.programCount);
    const steps = run.steps.map((step, index) => {
      const decoded = decodeStep(step);
      assert.equal(digest(decoded.code), profile.originalProgramSha256[index]);
      const gate = gates.get(index);
      let code = decoded.code;
      if (gate) {
        assert.equal(code[0], 0x75, 'archived discarded padding owner');
        const frameLength = decoded.instructions[0].data?.length;
        if (gate.comparison === 'less-than') assert(frameLength < gate.length, 'original positive header bound');
        else assert.equal(frameLength, gate.length, 'original positive state frame');
        assert.equal(decoded.instructions.length - 1, gate.depth + 2, 'original argument frame arity');
        const instructions = decodeAuthenticationInstructions(code);
        assert(instructions.every(i => !('error' in i)));
        let offset = 0;
        const boundaries = instructions.map(i => {
          const start = offset;
          offset += encodeAuthenticationInstructions([i]).length;
          return start;
        });
        assert(boundaries.includes(gate.offset), 'guard must precede an actual instruction');
        const inserted = frameGate(gate);
        assert.equal(hex(inserted), gate.hex);
        code = Buffer.concat([code.subarray(0, gate.offset), inserted, code.subarray(gate.offset)]);
      }
      assert.equal(digest(code), profile.repairedProgramSha256[index]);
      const unlocking = Buffer.concat([decoded.prefix, Buffer.from(encodeDataPush(code))]);
      assert(unlocking.subarray(0, decoded.prefix.length).equals(decoded.prefix));
      return {label: step.label, locking: hex(locking(code)), unlocking: hex(unlocking)};
    });
    if (!run.groups) return {name: run.name, steps};
    const groups = run.groups.map((group, i) => {
      const next = run.groups[i + 1];
      if (!next) return {...group};
      assert.equal(group.outLocking, run.steps[next.lo].locking, 'original grouped successor owner');
      return {...group, outLocking: steps[next.lo].locking};
    });
    return {name: run.name, steps, groups};
  });
  return {schema: 'historical-frame-positive-packet/v1', id: profile.id,
    originalFixtureSha256: profile.originalFixture.sha256, layout: profile.layout, cases};
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [profileId, input, output, ...extra] = process.argv.slice(2);
  assert(profileId && input && output && extra.length === 0,
    'usage: node repair_historical_frames.mjs profile-id original.json new-positive.json');
  assert.notEqual(resolve(input), resolve(output));
  const packet = repairHistoricalPositives(profileId, readFileSync(input));
  writeFileSync(output, JSON.stringify(packet, null, 2) + '\n', {flag: 'wx'});
  console.log(JSON.stringify({id: packet.id, cases: packet.cases.length, output}));
}

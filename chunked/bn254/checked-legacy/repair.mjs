import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {decodeAuthenticationInstructions, encodeDataPush} from '@bitauth/libauth';
import {buildGuard} from './guard.mjs';

const sha = bytes => createHash('sha256').update(bytes).digest();
const hash256 = bytes => sha(sha(bytes));
const locking = redeem => Buffer.concat([Buffer.from([0xaa, 0x20]), hash256(redeem), Buffer.from([0x87])]);
const decode = hex => {
  const bytes = Buffer.from(hex, 'hex');
  const instructions = decodeAuthenticationInstructions(bytes);
  assert(instructions.every(i => i.data !== undefined || i.opcode === 0x4f || (i.opcode >= 0x51 && i.opcode <= 0x60)),
    'archived unlocking must consist of pushes');
  const redeem = Buffer.from(instructions.at(-1).data);
  const suffix = Buffer.from(encodeDataPush(redeem));
  assert(bytes.subarray(-suffix.length).equals(suffix));
  return {bytes, instructions, redeem, prefix: bytes.subarray(0, -suffix.length)};
};

// Only code and coherent locking transport are replaced. All original argument
// instructions remain byte-identical, including their push encodings and padding.
export function repairExistingPositives(artifactBytes, profile) {
  assert.equal(sha(artifactBytes).toString('hex'), profile.originalSha256);
  const artifact = JSON.parse(artifactBytes);
  const cases = [{name: 'primary', steps: artifact.steps},
    ...(artifact.extraValidProofs ?? []).map((steps, i) => ({name: `extra-${i}`, steps})),
    ...(artifact.worstCaseProof ? [{name: 'worst-case', steps: artifact.worstCaseProof}] : [])];
  assert.equal(cases.length, 5);
  const first = cases[0].steps;
  const original = first.map(step => decode(step.unlocking));
  const guardInput = profile.guardInput, terminal = first.length - 1;
  const guard = buildGuard(profile);
  const programs = original.map(({redeem}) => redeem);
  const guardInLocking = profile.guardPlacement === 'locking';
  if (guardInLocking) assert.equal(guardInput, terminal);
  else programs[guardInput] = Buffer.concat([guard.bytecode, programs[guardInput]]);
  const oldRoot = hash256(Buffer.concat(first.slice(0, terminal).map(step => hash256(Buffer.from(step.locking, 'hex')))));
  const selectedLockings = programs.map(locking);
  const newRoot = hash256(Buffer.concat(selectedLockings.slice(0, terminal).map(hash256)));
  if (!oldRoot.equals(newRoot)) {
    const code = programs[terminal], offset = code.indexOf(oldRoot);
    assert(offset > 0 && code[offset - 1] === 0x20);
    assert.equal(code.indexOf(oldRoot, offset + 1), -1);
    const instructions = decodeAuthenticationInstructions(code);
    const owner = instructions.findIndex(i => i.data && Buffer.from(i.data).equals(oldRoot));
    assert(owner > 0 && instructions[owner].opcode === 0x20);
    assert.equal(instructions[owner - 1].opcode, 0xaa); // HASH256(worker locking hashes)
    assert.equal(instructions[owner + 1].opcode, 0x88); // EQUALVERIFY
    programs[terminal] = Buffer.concat([code.subarray(0, offset), newRoot, code.subarray(offset + 32)]);
    selectedLockings[terminal] = locking(programs[terminal]);
  }
  if (guardInLocking) {
    // Slim stages locate state from the end of the terminal's original redeem
    // push. Keep that wire frame intact: execute the guard in a bare terminal
    // locking, dropping the archived redeem data before the unchanged program.
    // This is a mathematical reference transport, with native admission HOLD.
    selectedLockings[terminal] = Buffer.concat([Buffer.from([0x75]), guard.bytecode, programs[terminal]]);
  }
  const positiveCases = cases.map(({name, steps}) => ({name, steps: steps.map((step, i) => {
    const decoded = decode(step.unlocking);
    assert(decoded.redeem.equals(original[i].redeem), 'positive cases must share one immutable program set');
    assert(Buffer.from(step.locking, 'hex').equals(locking(decoded.redeem)));
    if (i === guardInput) assert.equal(decoded.instructions.length - 1, profile.argumentCount);
    if (i === profile.proofInput) assert.equal(decoded.instructions[0].data.length, 448);
    const unlocking = Buffer.concat([decoded.prefix, Buffer.from(encodeDataPush(programs[i]))]);
    assert(unlocking.subarray(0, decoded.prefix.length).equals(decoded.prefix));
    return {...step, locking: selectedLockings[i].toString('hex'), unlocking: unlocking.toString('hex')};
  })}));
  return {id: profile.id, originalSha256: profile.originalSha256, positiveCases,
    catalog: {programs: programs.map(p => p.toString('hex')), lockings: selectedLockings.map(p => p.toString('hex')),
      equationLoaderSha256: guard.equationLoaderSha256, bridgeSource: guard.bridgeSource},
    qualification: 'Complete deterministic fixed-VK equation guard; legacy auxiliary checks receive no independent soundness credit. Native admission HOLD pending declared-mode outcomes.'};
}

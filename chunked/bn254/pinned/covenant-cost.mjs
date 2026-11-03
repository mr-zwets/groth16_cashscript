// Track 12: op cost and size of the template block in role 2 (test-key controls).
//   node covenant-cost.mjs
// Role 2's 'covenant' mark is followed by other role-2 code (the psi(B) kernel) before the next mark, so the block is
// measured as a difference: op cost from the 'statement' mark to the 'slices' mark in the template build, minus the
// same range in the plain build (bn-native-sound, no hook), both spending the SAME proof and statement (the control
// proof of pinned-test.mjs: the first mint of the seed `track12:<system>`).
import assert from 'node:assert/strict';
import {decodeAuthenticationInstructions, encodeAuthenticationInstruction} from '@bitauth/libauth';
import {loadKey} from './keys.mjs';
import {publicInputsFor} from './pv.mjs';
import {OUTS} from './example-params.mjs';

const K = await loadKey('test');
function rangeCost(prog, U, mode, from, to) {
  const L = U.map(() => K.tx.lockingOf(prog));
  const d = decodeAuthenticationInstructions(prog.funcCodes.role2); const offs = []; let x = 0; for (const t of d) { offs.push(x); x += encodeAuthenticationInstruction(t).length; }
  const m = Object.fromEntries(prog.marks.filter((q) => q.role === 2).map((q) => [q.name, q.roff]));
  let first = null, last = null;
  for (const s of K.vm.VMS[mode].debug(K.vm.programOf(L, U, 2))) {
    if (s.instructions?.length !== d.length) continue; const off = offs[s.ip] ?? Infinity;
    if (first === null && off >= m[from]) first = s.metrics.operationCost;
    if (first !== null && last === null && off >= m[to]) last = s.metrics.operationCost;
  }
  assert.ok(first !== null && last !== null); return {op: last - first, bytes: m[to] - m[from]};
}
const plain = K.script.buildProgram();
const {INSTANCE, TEST_PROGRAM_VKEY, TEST_IMAGE_ID} = await import('./example-params.mjs');
for (const system of ['sp1', 'risc0']) {
  const P = system === 'sp1' ? {system, programVKey: TEST_PROGRAM_VKEY, instanceId: INSTANCE} : {system, imageId: TEST_IMAGE_ID, instanceId: INSTANCE};
  const prog = K.tpl.buildPinnedProgram(P); const [n0, n1] = publicInputsFor(P, OUTS);
  const fx = {proof: K.mint.mint(n0, n1, K.mint.rng(`track12:${system}`)).proof, publicInputs: [n0, n1].map(String)};
  K.vm.setOutputs(OUTS.map((o) => ({lockingBytecode: Buffer.from(o.lockingBytecode, 'hex'), valueSatoshis: o.valueSatoshis})));
  const Ut = K.tx.transactionFor(fx, prog).unlockings, Up = K.tx.transactionFor(fx, plain).unlockings;
  for (const mode of ['standard', 'consensus']) {
    const t = rangeCost(prog, Ut, mode, 'r2:statement', 'r2:slices'), p = rangeCost(plain, Up, mode, 'r2:statement', 'r2:slices');
    console.log(`${system} ${mode}: template block ${t.bytes - p.bytes} B of role-2 code, op cost ${t.op - p.op} (statement..slices: template ${t.op}, plain ${p.op}); ${OUTS.length} outputs`);
  }
}

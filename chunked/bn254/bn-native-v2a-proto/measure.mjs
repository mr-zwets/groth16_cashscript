// v2a prototype measurement: build, fixture accept (both modes), per-input op / unlocking / margin, score, and ordinary
// rejection checks for every changed binding (flipped bytes in X1/X2/S_1'/C, 2-input tx). CUTS=..., MARGIN=..., FIX=...
import assert from 'node:assert/strict';
import {FIXTURES} from '../sound-si-gls/math.mjs';
import {buildProgram} from './script.mjs';
import {proveCore, ROLES, CUTS, ST_SIZE, HAND_SIZE, runRange, startState, zOf, zTail} from './protocol.mjs';
import {sizeFills, unlockingsFor, lockingOf, MARGIN} from './transaction.mjs';
import {spendAll} from './vm.mjs';
const prog = buildProgram();
console.log(`CUTS ${CUTS.join(',')} code ${prog.code.length} B, R ${prog.R.length} B, roles ${prog.info.roles.join('/')}, funcs`, Object.entries(prog.info.funcs).map(([n, f]) => n + ':' + f.bytes).join(' '));
const fi = Number(process.env.FIX ?? 0);
const core = proveCore(FIXTURES.fixtures[fi]);
const {fills} = sizeFills(core, prog);
const {unlockings, pushes} = unlockingsFor(core, prog, fills); const lock = lockingOf(prog);
const out = {};
for (const m of ['consensus', 'standard']) { const r = spendAll(unlockings.map(() => lock), unlockings, m); r.forEach((x, i) => assert.ok(x.accepted, `${m} input ${i}: ${x.error}`)); out[m] = r; }
const total = unlockings.reduce((a, u) => a + u.length, 0);
console.log(`fixture ${fi} margin ${MARGIN}: fills ${fills.join('/')}, unlocking ${unlockings.map((u) => u.length).join(' / ')} = ${total}, score ${total + 3 * 35 + 149}`);
const content = unlockings.map((u, i) => u.length - fills[i] - (fills[i] >= 256 ? 2 : fills[i] >= 76 ? 1 : fills[i] ? 0 : 0) - (fills[i] ? 1 : 0) + (fills[i] ? 1 : 0));
for (const i of [0, 1, 2]) { const s = out.standard[i], c = out.consensus[i];
  console.log(`  input ${i}: op std ${s.opCost} cons ${c.opCost} budget ${s.budget} margin ${(100 * (1 - s.opCost / s.budget)).toFixed(2)}% content(fill 0) ~${unlockings[i].length - fills[i]} need@6% ${Math.ceil(s.opCost / 752) - 41} need@3% ${Math.ceil(s.opCost / 776) - 41}`); }
console.log('  op total std', out.standard.reduce((a, x) => a + x.opCost, 0));
if (process.env.NOTAMPER) process.exit(0);
// ---- ordinary rejection checks on the changed bindings ----
const enc = (await import('./vm.mjs')).encodeUnlocking;
const S0 = ROLES[0].streamSize;
const cases = {
  'X1: HAND_1 word (x_T) flipped': [1, 0, S0 + 5],
  'X1: HAND_1 R word flipped': [1, 0, S0 + 130],
  'X1: S_12 (last state of S_0) flipped': [1, 0, S0 - 10],
  'X1: S_0 first t flipped': [1, 0, 3],
  "S_1' byte flipped": [1, 1, 40],
  'X2: S_cut flipped': [2, 2, 7],
  'X2: HAND_2 y_T flipped': [2, 2, ST_SIZE + 70],
  'code byte flipped': [0, 0, 1000],
  'DG d1 flipped': [2, 0, 40],
};
for (const [name, [inp, item, off]] of Object.entries(cases)) {
  const ps = pushes.map((x) => x.map((b) => Buffer.from(b))); ps[inp][item][off] ^= 1;
  const us = ps.map((x) => enc(x)); const r = spendAll(us.map(() => lock), us, 'consensus');
  console.log(`  reject ${name}: ${r.every((x) => x.accepted) ? 'ACCEPTED (BAD)' : 'rejected by inputs ' + r.map((x, i) => (x.accepted ? '' : i)).filter((x) => x !== '').join(',')}`);
}
{ const us = unlockings.slice(0, 2); const r = spendAll(us.map(() => lock), us, 'consensus'); console.log('  reject 2-input tx:', r.every((x) => x.accepted) ? 'ACCEPTED (BAD)' : 'rejected'); }

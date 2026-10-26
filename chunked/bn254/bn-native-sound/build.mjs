// Build the bn-native-sound program (code blob + 3-input redeem R), deterministically, and check it.
//   node build.mjs        -> writes build.json (R, code pieces, layout, fixture-0 numbers), prints the digests
// Checks (any failure aborts the build):
//   - every baked constant is recomputed and asserted against noble when ../sound-si-gls/math.mjs loads;
//   - the per-role schedules (digits, boundary flags), the delta slices and start states are asserted against the
//     single-input schedule and the single delta chain when protocol.mjs loads;
//   - the program is built twice and must be byte-identical;
//   - fixtures 0 and 4: the 33 states equal the reviewed single-input SI-GLS prover's states (same classes), and the
//     role-split value-level run (chained by the handovers) equals one uninterrupted run over all 65 events;
//   - the code is exactly what R hashes (pieces concatenate to the hashed item), function ids are distinct;
//   - fixture 0 is accepted in consensus and standard mode with prover-sized fillers; a tampered state is rejected.
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {writeFileSync} from 'node:fs';
import {FIXTURES, FACTS, DIGITS, NE} from '../sound-si-gls/math.mjs';
import {prove as proveSI} from '../sound-si-gls/protocol.mjs';
import {proveCore, runRange, startState, zOf, zTail, ROLES, CUTS, DS, DSTATE, SCHEDULE, NQ_MAX, BOUNDS, NSTATES, K_IDS, TAG, VK_DIGEST} from './protocol.mjs';
import {buildProgram} from './script.mjs';
import {sizeFills, unlockingsFor, lockingOf, MARGIN} from './transaction.mjs';
import {spendAll} from './vm.mjs';

const hex = (b) => Buffer.from(b).toString('hex');
const sha = (b) => createHash('sha256').update(b).digest('hex');
// ---- deterministic build ----
const b1 = buildProgram(), b2 = buildProgram();
assert.deepEqual(Buffer.from(b1.code), Buffer.from(b2.code), 'deterministic build (code)');
assert.deepEqual(Buffer.from(b1.R), Buffer.from(b2.R), 'deterministic build (R)');
const prog = b1;
// ---- code identity: R concatenates the pieces at fixed ranges and hashes exactly the defined item ----
assert.deepEqual(Buffer.concat(prog.pieces.map((x) => Buffer.from(x))), Buffer.from(prog.code));
assert.equal(sha(prog.code), Buffer.from(prog.Kcode).toString('hex'));
{ const ids = Object.values(prog.info.funcs).map((f) => f.id); assert.equal(new Set(ids).size, ids.length, 'function ids distinct'); assert.ok(!ids.includes(1), 'id 1 is the body');
  const roleIds = [0, 1, 2].map((i) => prog.info.roleId + i); assert.ok(roleIds.every((x) => !ids.includes(x)), 'role ids distinct'); }
// ---- schedule / chain facts (protocol.mjs asserts the per-role schedules at load) ----
assert.deepEqual(CUTS, [0, 24, 48, 65]); assert.equal(ROLES.reduce((s, r) => s + r.nStates, 0), NSTATES);
assert.equal(DS.reduce((s, d) => s + d.length, 0), 88 * 64);
// ---- fixtures 0 and 4: same states as SI-GLS; role-split run == single run ----
for (const fi of [0, 4]) {
  const fx = FIXTURES.fixtures[fi]; const core = proveCore(fx); const si = proveSI(fx);
  assert.deepEqual(core.states.map((s) => s.join()), si.states.map((s) => s.join()), `fixture ${fi}: states equal SI-GLS`);
  assert.deepEqual(core.Sc.join(), si.Sc.join(), `fixture ${fi}: residue root equals SI-GLS`);
  const z = zOf(core, zTail(0, core.WQ));
  const single = runRange(core, z, 0, NE, startState(core, z));
  let s = startState(core, z); for (let i = 0; i < 3; i++) s = runRange(core, z, CUTS[i], CUTS[i + 1], s);
  assert.equal(s.R, single.R); assert.equal(s.Fp, single.Fp); assert.equal(s.Fm, single.Fm);
}
// ---- smoke: fixture 0 ----
const core = proveCore(FIXTURES.fixtures[0]);
const {fills} = sizeFills(core, prog);
const {unlockings} = unlockingsFor(core, prog, fills); const lock = lockingOf(prog);
const runs = Object.fromEntries(['consensus', 'standard'].map((m) => { const r = spendAll(unlockings.map(() => lock), unlockings, m); r.forEach((x, i) => assert.ok(x.accepted, `${m} input ${i}: ${x.error}`)); return [m, r]; }));
{ const bad = unlockings.map((u) => Buffer.from(u)); bad[1][100] ^= 1; assert.ok(!spendAll(bad.map(() => lock), bad, 'consensus').every((x) => x.accepted), 'tampered stream accepted'); }
const total = unlockings.reduce((a, u) => a + u.length, 0);
const out = {
  codeBytes: prog.code.length, codeSha256: sha(prog.code), redeemBytes: prog.R.length, redeemHex: hex(prog.R), redeemSha256: sha(prog.R),
  lockingHex: hex(lock), lockingSha256: sha(lock), tag: hex(TAG), vkDigest: hex(VK_DIGEST),
  codePieces: prog.pieces.map((x, i) => ({host: i, bytes: x.length})), codePiecesHex: prog.pieces.map(hex),
  layout: {codeLens: prog.lay.codeLens, rawFixed: prog.lay.rawFixed, zt: prog.lay.zt, pushR: prog.lay.pushR,
    offsets: prog.lay.off.map((m) => Object.fromEntries(Object.entries(m).filter(([k]) => k !== 'end').map(([k, v]) => [k, {data: v.data, size: v.size}])))},
  roles: ROLES.map((r, i) => ({events: [r.a, r.b], states: r.nStates, bSteps: r.nB, stream: r.streamSize, deltaSlice: DS[i].length, deltaStart: DSTATE[r.a].j,
    schedule: {firstDigit: SCHEDULE[i].d0, digits: hex(SCHEDULE[i].sch), boundaries: hex(SCHEDULE[i].bnd)}, codeBytes: prog.info.roles[i]})),
  functions: prog.info.funcs, roleFunctionIds: [0, 1, 2].map((i) => prog.info.roleId + i), prologueBytes: prog.info.prologue,
  degreeBound: {NQ_MAX, states: NSTATES, identities: K_IDS, note: 'affine B lines have the SI-GLS slot degrees (<= 9), so the SI-GLS bound (deg <= 275, n_q <= 132) carries over'},
  fixture0: {nq: core.nq, fills, margin: MARGIN, unlocking: unlockings.map((u) => u.length), unlockingTotal: total,
    // bench score model: unlockings + 3 P2SH32 lockings + tx overhead (envelope 8, input/output counts 2, OP_RETURN output 10,
    // per input outpoint+sequence 40 + script-length varint 3)
    score: total + 3 * 35 + 8 + 2 + 10 + 3 * 43,
    inputs: [0, 1, 2].map((i) => ({consensus: runs.consensus[i].opCost, standard: runs.standard[i].opCost, budget: runs.standard[i].budget,
      marginStandard: +(100 * (1 - runs.standard[i].opCost / runs.standard[i].budget)).toFixed(2), marginConsensus: +(100 * (1 - runs.consensus[i].opCost / runs.consensus[i].budget)).toFixed(2)}))},
  facts: FACTS, digits: DIGITS.join(''),
};
writeFileSync(new URL('./build.json', import.meta.url), JSON.stringify(out, null, 1) + '\n');
console.log(`code ${prog.code.length} B sha256 ${out.codeSha256}; R ${prog.R.length} B; locking sha256 ${out.lockingSha256}`);
console.log(`code pieces ${prog.pieces.map((x) => x.length).join(' + ')}; role code ${prog.info.roles.join(' / ')}; prologue ${prog.info.prologue}`);
console.log(`fixture 0: n_q ${core.nq}, fills ${fills.join('/')}, unlocking ${unlockings.map((u) => u.length).join(' / ')} = ${total}, score ${out.fixture0.score}`);
for (const i of [0, 1, 2]) { const x = out.fixture0.inputs[i]; console.log(`  input ${i}: op ${x.consensus} cons / ${x.standard} std of ${x.budget} (margin ${x.marginConsensus}% / ${x.marginStandard}%)`); }

// Rejection suite (ordinary negative tests: malformed, mutated or mis-assembled transactions must be rejected). Every case
// is evaluated on the real bch-2026 VM in consensus and standard mode; the whole transaction must be invalid, and the
// report names the inputs that reject and their errors. Positive controls must be accepted. No case searches for an
// accepting input: each is one fixed mutation of an honest transaction (or an honest proof of a malformed point).
//   node redteam.mjs redteam.json redteam-report.json
// redteam.json: the maintainer red-team file of the bench (only the cases expressible as unlocking patches).
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {writeFileSync} from 'node:fs';
import {FIXTURES, G1, G2, F2, f2, p, r, mod, randomTwistPoint, synthetic} from './math.mjs';
import {prove, finishWitness, txPushes, pushesOf, ROLES, STMT, N_MIN, NQ_MAX, W, W48, rdle, leN, K_BLOCKS} from './protocol.mjs';
import {R, blob, locking, LABELS, encodeWith} from './transaction.mjs';
import {VMS, txOf, encodeUnlocking} from './vm.mjs';
assert.equal(process.argv.length, 4, 'usage: node redteam.mjs redteam.json redteam-report.json');
const sha = (b) => createHash('sha256').update(b).digest('hex');

const honest = prove(FIXTURES.committed);
const basePushes = txPushes(honest, blob);
const idx = (h, name) => { const k = pushesOf(h).findIndex((x) => x.name === name); assert.ok(k >= 0, `no ${name} in input ${h}`); return k; };
// a case: build (pushes per input, redeems per input, lockings, extra tx edits) -> evaluate
const results = [], bench = [];
function run(name, kind, edit, {expect = 'reject', owner = null} = {}) {
  const c = {ps: basePushes.map((x) => x.map((b) => Buffer.from(b))), red: [R, R, R, R].map((x) => Buffer.from(x)), lock: [0, 1, 2, 3].map(() => Buffer.from(locking)), raw: [null, null, null, null], order: null, extra: 0};
  edit?.(c);
  let unl = c.ps.map((ps, i) => c.raw[i] ?? Buffer.from(encodeWith(ps, c.red[i])));
  let lk = c.lock.slice();
  if (c.order) { unl = c.order.map((j) => unl[j]); lk = c.order.map((j) => lk[j]); }
  for (let k = 0; k < c.extra; k++) { unl.push(unl[1]); lk.push(lk[1]); }
  const ctx = txOf(unl, lk);
  const row = {name, kind};
  for (const mode of ['consensus', 'standard']) {
    const vm = VMS[mode]; const v = vm.verify(ctx);
    const per = ctx.transaction.inputs.map((_, i) => { const st = vm.evaluate({inputIndex: i, sourceOutputs: ctx.sourceOutputs, transaction: ctx.transaction}); const top = st.stack.at(-1);
      return st.error === undefined && st.stack.length === 1 && top?.length === 1 && top[0] === 1 ? 'ok' : (st.error ?? `stack ${st.stack.length}`); });
    row[mode] = {valid: v === true, rejectingInputs: per.map((x, i) => (x === 'ok' ? null : i)).filter((x) => x !== null), errors: per};
  }
  row.ok = expect === 'accept' ? row.consensus.valid && row.standard.valid : !row.consensus.valid && !row.standard.valid;
  if (row.ok && expect === 'reject' && owner !== null) row.ownerRejects = row.consensus.rejectingInputs.includes(owner) && row.standard.rejectingInputs.includes(owner);
  results.push(row);
  const rej = row.standard.rejectingInputs; const e0 = rej.length ? row.standard.errors[rej[0]] : '';
  console.log(row.ok ? 'ok  ' : 'FAIL', kind.padEnd(14), name.padEnd(62), '->', expect === 'accept' ? 'accepted' : `rejected by input(s) ${rej.join(',')}${owner !== null ? (row.ownerRejects ? ` (owner ${owner})` : ` (OWNER ${owner} DOES NOT REJECT)`) : ''}: ${String(e0).slice(0, 70)}`);
  // bench red-team run: only unlocking patches of the 4-input transaction
  if (expect === 'reject' && !c.order && !c.extra && c.lock.every((l) => l.equals(locking))) {
    const patches = []; unl.forEach((u, i) => { const base = Buffer.from(encodeWith(basePushes[i], R)); if (!Buffer.from(u).equals(base)) patches.push({input: i, unlocking: Buffer.from(u).toString('hex')}); });
    if (patches.length) bench.push({label: name, kind, patches});
  }
}
const flip = (b, at) => { b[at] ^= 1; };
const word = (b, o) => rdle(b, o, 48);
const setWord = (b, o, v) => leN(v, 48).copy(b, o);
// re-derive a consistent transcript, quotient and claims for re-encoded regions (aliases must then fail their range check)
const reproved = (mutRegions) => { const regions = honest.regions.map((g) => Buffer.from(g)); mutRegions(regions); return txPushes(finishWitness(honest, regions), blob); };
// honest proof of a malformed proof point (forge mode skips the prover's own validity asserts)
const proofWith = (fx) => txPushes(prove(fx, {forge: true}), blob);
const fxWith = (pts) => ({inputs: FIXTURES.committed.inputs, proof: {...FIXTURES.committed.proof, ...pts}});
const oS = (h) => (h === 0 ? 864 : 0);                       // states start in region h
const oSl = (h) => oS(h) + 288 * ROLES[h].states.length;     // slopes start in region h

// ---- positive controls ----
run('honest transaction (fixture committed)', 'control', null, {expect: 'accept'});
run('honest transaction (fixture dense)', 'control', (c) => { c.ps = txPushes(prove(FIXTURES.dense), blob); }, {expect: 'accept'});
// ---- pins: input count, order, sibling code ----
run('a 5th input (copy of input 1)', 'pins', (c) => { c.extra = 1; });
run('inputs 1 and 2 swapped', 'pins', (c) => { c.order = [0, 2, 1, 3]; });
run('inputs 0 and 3 swapped', 'pins', (c) => { c.order = [3, 1, 2, 0]; });
run('input 2 spends a foreign locking (P2SH32 of another redeem)', 'pins', (c) => { const r2 = Buffer.from(R); r2[r2.length - 3] ^= 1; c.red[2] = r2; c.lock[2] = Buffer.from([0xaa, 0x20, ...createHash('sha256').update(createHash('sha256').update(r2).digest()).digest(), 0x87]); }, {owner: 0});
run('redeem byte changed in input 1 (P2SH32 mismatch)', 'pins', (c) => { const r2 = Buffer.from(R); flip(r2, 40); c.red[1] = r2; });
// ---- layout: push count and sizes ----
run('input 1: region one byte longer', 'layout', (c) => { c.ps[1][0] = Buffer.concat([c.ps[1][0], Buffer.of(0)]); }, {owner: 1});
run('input 3: an extra push before the witness', 'layout', (c) => { c.ps[3] = [Buffer.from([1, 2, 3]), ...c.ps[3]]; }, {owner: 3});
run('input 2: a non-push opcode in the unlocking', 'layout', (c) => { c.raw[2] = Buffer.concat([Buffer.of(0x61), Buffer.from(encodeWith(c.ps[2], R))]); });
run('input 0: claims push one byte short', 'layout', (c) => { c.ps[0][idx(0, 'CL')] = c.ps[0][idx(0, 'CL')].subarray(1); }, {owner: 0});
run('relocated constant pieces swapped in input 1 (K0_1 <-> K1_0)', 'layout', (c) => { const a = idx(1, 'K0_1'), b = idx(1, 'K1_0'); [c.ps[1][a], c.ps[1][b]] = [c.ps[1][b], c.ps[1][a]]; });
run('relocated constant piece resized (48 B moved from K3_1 to K1_0 in input 1)', 'layout', (c) => { const a = idx(1, 'K1_0'), b = idx(1, 'K3_1'); c.ps[1][a] = Buffer.concat([c.ps[1][a], c.ps[1][b].subarray(0, 48)]); c.ps[1][b] = c.ps[1][b].subarray(48); });
run('filler push not zero (input 2)', 'layout', (c) => { const k = idx(2, 'PAD'); c.ps[2][k] = Buffer.from(c.ps[2][k]); c.ps[2][k][5] = 1; }, {owner: 2});
// ---- program and constants ----
run('program part 0 (input 3) tampered', 'program', (c) => { const k = idx(3, 'BLOB'); c.ps[3][k] = Buffer.from(c.ps[3][k]); flip(c.ps[3][k], 100); });
run('program part 1 (input 2) tampered', 'program', (c) => { const k = idx(2, 'BLOB'); c.ps[2][k] = Buffer.from(c.ps[2][k]); flip(c.ps[2][k], 10); });
run('delta constant block K2 tampered (wrong K_const)', 'constants', (c) => { const k = idx(2, 'K2_0'); flip(c.ps[2][k], 500); }, {owner: 2});
run('delta constant piece K0_1 (hosted in input 1) tampered', 'constants', (c) => { const k = idx(1, 'K0_1'); flip(c.ps[1][k], 7); }, {owner: 0});
run('delta start point of K3 replaced by K2\'s', 'constants', (c) => { const k = idx(3, 'K3_0'); c.ps[3][k] = Buffer.from(K_BLOCKS[2].subarray(0, c.ps[3][k].length)); }, {owner: 3});
// ---- transcript: committed bytes changed after the challenges (claims no longer match) ----
run('statement x_A changed', 'transcript', (c) => { flip(c.ps[0][idx(0, 'G')], STMT.xA + 3); }, {owner: 0});
run('state word changed (region 2)', 'transcript', (c) => { flip(c.ps[2][0], oS(2) + 100); }, {owner: 0});
run('B slope changed (region 1, first slope)', 'transcript', (c) => { flip(c.ps[1][0], oSl(1) + 5); }, {owner: 0});
run('GLS nibble changed (N0[9] ^ 1)', 'transcript', (c) => { flip(c.ps[0][idx(0, 'G')], STMT.N0 + 9); }, {owner: 0});
run('residue root s^c changed', 'transcript', (c) => { flip(c.ps[0][idx(0, 'G')], STMT.sc + 50); }, {owner: 0});
run('public input n0 + 1', 'statement', (c) => { const g = c.ps[0][idx(0, 'G')]; leN(rdle(g, STMT.n0, 32) + 1n, 32).copy(g, STMT.n0); }, {owner: 0});
run('public input n1 = n1 + r', 'statement', (c) => { const g = c.ps[0][idx(0, 'G')]; leN(rdle(g, STMT.n1, 32) + r, 32).copy(g, STMT.n1); }, {owner: 0});
run('quotient word + 1 (middle)', 'quotient', (c) => { const q = c.ps[0][idx(0, 'WQ')]; const o = 48 * (q.length / 96 | 0); setWord(q, o, mod(word(q, o) + 1n)); }, {owner: 0});
// ---- quotient length and canonical form ----
run(`WQ with ${N_MIN - 1} words (below the floor)`, 'quotient', (c) => { const k = idx(0, 'WQ'); c.ps[0][k] = c.ps[0][k].subarray(48 * (c.ps[0][k].length / 48 - (N_MIN - 1))); }, {owner: 0});
run(`WQ with ${NQ_MAX + 1} words (above the cap, zero-padded)`, 'quotient', (c) => { const k = idx(0, 'WQ'); c.ps[0][k] = Buffer.concat([Buffer.alloc(48 * (NQ_MAX + 1) - c.ps[0][k].length), c.ps[0][k]]); }, {owner: 0});
run('WQ with a leading zero word above the floor', 'quotient', (c) => { const k = idx(0, 'WQ'); c.ps[0][k] = Buffer.concat([Buffer.alloc(48), c.ps[0][k]]); }, {owner: 0});
run('WQ length not a multiple of 48', 'quotient', (c) => { const k = idx(0, 'WQ'); c.ps[0][k] = Buffer.concat([Buffer.of(0), c.ps[0][k]]); }, {owner: 0});
// ---- claims: z~, rho~ (head), R~_i and T~_i (producers), aliases (consumers) ----
run('z~ + 1', 'claims', (c) => { const zr = c.ps[0][idx(0, 'ZR')]; setWord(zr, 0, word(zr, 0) + 1n); }, {owner: 0});
run('z~ + p (non-canonical alias)', 'claims', (c) => { const zr = c.ps[0][idx(0, 'ZR')]; setWord(zr, 0, word(zr, 0) + p); }, {owner: 0});
run('rho~ + 1', 'claims', (c) => { const zr = c.ps[0][idx(0, 'ZR')]; setWord(zr, 48, word(zr, 48) + 1n); }, {owner: 0});
run('rho~ + p (non-canonical alias)', 'claims', (c) => { const zr = c.ps[0][idx(0, 'ZR')]; setWord(zr, 48, word(zr, 48) + p); }, {owner: 0});
for (const h of [0, 1, 2, 3]) run(`R~_${h} + 1`, 'claims', (c) => { const cl = c.ps[h][idx(h, 'CL')]; setWord(cl, 0, mod(word(cl, 0) + 1n)); }, {owner: h});
run('R~_2 + p (non-canonical alias)', 'claims', (c) => { const cl = c.ps[2][idx(2, 'CL')]; setWord(cl, 0, word(cl, 0) + p); }, {owner: 2});
run('R~_3 one byte changed', 'claims', (c) => { flip(c.ps[3][idx(3, 'CL')], 20); }, {owner: 3});
for (const h of [0, 1, 2]) run(`T~_${h} x.c0 + 1`, 'claims', (c) => { const cl = c.ps[h][idx(h, 'CL')]; setWord(cl, W, mod(word(cl, W) + 1n)); }, {owner: h});
run('T~_1 y.c1 + p (non-canonical alias)', 'claims', (c) => { const cl = c.ps[1][idx(1, 'CL')]; setWord(cl, 4 * W, word(cl, 4 * W) + p); }, {owner: 1});
run('T~_0 one byte changed', 'claims', (c) => { flip(c.ps[0][idx(0, 'CL')], 100); }, {owner: 0});
// ---- canonical decoding: +p aliases with a re-derived consistent transcript (only the range check can reject) ----
run('alias: B slope + p (region 1), consistent transcript', 'canonical', (c) => { c.ps = reproved((g) => setWord(g[1], oSl(1), word(g[1], oSl(1)) + p)); }, {owner: 1});
run('alias: state word + p (region 2), consistent transcript', 'canonical', (c) => { c.ps = reproved((g) => setWord(g[2], oS(2) + 48, word(g[2], oS(2) + 48) + p)); }, {owner: 2});
run('alias: last state of region 1 + p (read by input 2), consistent transcript', 'canonical', (c) => { const o = oS(1) + 288 * (ROLES[1].states.length - 1); c.ps = reproved((g) => setWord(g[1], o, word(g[1], o) + p)); });
run('alias: x_A + p, consistent transcript', 'canonical', (c) => { c.ps = reproved((g) => setWord(g[0], STMT.xA, word(g[0], STMT.xA) + p)); });
run('alias: s^c word + p, consistent transcript', 'canonical', (c) => { c.ps = reproved((g) => setWord(g[0], STMT.sc, word(g[0], STMT.sc) + p)); });
run('alias: n0 + r, consistent transcript', 'canonical', (c) => { c.ps = reproved((g) => leN(rdle(g[0], STMT.n0, 32) + r, 32).copy(g[0], STMT.n0)); }, {owner: 0});
run('nibble 0x10 (out of range), consistent transcript', 'canonical', (c) => { c.ps = reproved((g) => { g[0][STMT.N0 + 20] |= 0x10; }); }, {owner: 0});
// ---- malformed proof points (honest prover, forge mode): curve, twist, subgroup ----
{ const A = FIXTURES.committed.proof.a.toAffine(), C = FIXTURES.committed.proof.c.toAffine();
  const offA = {px: A.x, py: mod(A.y + 1n)}, offC = {px: C.x, py: mod(C.y + 1n)};
  const bad = (P, x, y) => { try { return P.fromAffine({x, y}); } catch { return null; } };
  const pa = bad(G1, offA.px, offA.py); if (pa) run('A off the curve (y + 1), consistent witness', 'points', (c) => { c.ps = proofWith(fxWith({a: pa})); }, {owner: 0});
  const pc = bad(G1, offC.px, offC.py); if (pc) run('C off the curve (y + 1), consistent witness', 'points', (c) => { c.ps = proofWith(fxWith({c: pc})); }, {owner: 0});
  run('A negated (-A), consistent witness', 'points', (c) => { c.ps = proofWith(fxWith({a: FIXTURES.committed.proof.a.negate()})); });
  const T = randomTwistPoint(3); const pb = G2.fromAffine({x: T.x, y: T.y});
  run('B on the twist but not in G2, consistent witness', 'points', (c) => { c.ps = proofWith(fxWith({b: pb})); }, {owner: 3});
  const B = FIXTURES.committed.proof.b.toAffine(); const pb2 = bad(G2, B.x, F2.add(B.y, f2(1n, 0n)));
  if (pb2) run('B off the twist (y + 1), consistent witness', 'points', (c) => { c.ps = proofWith(fxWith({b: pb2})); }, {owner: 0});
  run('a different valid proof\'s B (proof1) with this proof\'s A, C', 'points', (c) => { c.ps = proofWith(fxWith({b: FIXTURES.proof1.proof.b})); });
}
// ---- stapling: inputs from two different valid proofs in one transaction ----
{ const other = txPushes(prove(FIXTURES.proof1), blob);
  for (const k of [1, 2, 3]) run(`staple: inputs ${k}.. from proof1, 0..${k - 1} from committed`, 'staple', (c) => { for (let i = k; i < 4; i++) c.ps[i] = other[i]; }); }

const failed = results.filter((x) => !x.ok), ownerMiss = results.filter((x) => x.ownerRejects === false);
console.log(`${results.length - failed.length}/${results.length} as expected; owner checks: ${results.filter((x) => x.ownerRejects).length} ok, ${ownerMiss.length} missed`);
writeFileSync(process.argv[3], JSON.stringify({generator: 'redteam.mjs', locking: locking.toString('hex'), results}, null, 1) + '\n');
writeFileSync(process.argv[2], JSON.stringify({
  id: 'bch-groth16-bls12381-sound-native',
  description: 'Ordinary rejection tests on the 4-input transaction: layout pins (push sizes, relocated constant pieces swapped or resized, non-zero filler), program parts and delta constant blocks tampered, committed bytes changed after the challenges, public inputs (+1, +r), quotient length, cap, floor and canonical form, head and producer claims (z~, rho~, R~_i, T~_i: +1, +p aliases, byte flips), +p aliases with a re-derived consistent transcript (slopes, states, coordinates, s^c, n + r, nibble 0x10), malformed proof points (A, C off the curve, -A, B off the twist, B on the twist outside G2, a foreign B) and stapled proofs. Every run must be rejected.',
  generator: 'groth16_cashscript chunked/bls12-381/bls-native-sound/redteam.mjs',
  lockingSha256: [0, 1, 2, 3].map(() => sha(locking)), runs: bench}, null, 1) + '\n');
console.log('bench red-team runs', bench.length);
assert.equal(failed.length, 0, 'unexpected: ' + failed.map((x) => x.name).join('; '));
void [G1, synthetic, encodeUnlocking, LABELS];

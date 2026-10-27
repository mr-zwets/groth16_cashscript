// Liveness sweep on the real bch-2026 VM, consensus and standard modes: every case must be a valid transaction (every
// input accepted within its budget (41 + unlocking length) * 800), and every unlocking must fit the standard 10,000-byte
// cap and the transaction 100,000 bytes. Op cost model (worst.mjs): ~24k op per nonzero GLS nibble, ~0.2k op per extra
// set bit, ~2k op (sd) from B and C; only input 0's budget grows with n_q (48 B per WQ word). So the extremes are
//  * inputs 1-3: the every-nibble-15 statement ALL15 (n_q = NQ_MAX = 116, also the cap-size regression case for
//    input 0's unlocking), swept with random B and C;
//  * input 0: the forced witnesses at the floor n_q = N_MIN (most op at the smallest n_q), swept with random B and C,
//    both with the `j mod 4` digit placement and with the bits in digit 3 first (the longest binding-loop TB lookups).
// Random proofs land between (their inputs 1-3 are within ~0.2% of ALL15) and are sampled widely.
// Cases: the 6 fixtures, forced n_q targets, every nibble nonzero, ALL15, the zero statement, special public inputs,
// SWEEP_W x (ALL15, forced N_MIN, forced N_MIN + 1) and 2 SWEEP_W x forced N_MIN digit 3 first, with random B and C, SWEEP_W random B and C, SWEEP_N random proofs.
//   [SWEEP_N=400] [SWEEP_W=40] [SWEEP_SEED=bls-native-sound-v2] [SWEEP_SHARD=k/n] node sweep.mjs [sweep.json]
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {writeFileSync} from 'node:fs';
import {FIXTURES, FIXTURE_NAMES, r, mint, synthetic} from './math.mjs';
import {N_MIN, NQ_MAX} from './protocol.mjs';
import {forcedCases, maxSlots, statementFor, ALL15, D3FIRST} from './worst.mjs';
import {pushesFor, unlockingsOf, ctxOf} from './transaction.mjs';
import {evalTx, verifyTx, txSize} from './vm.mjs';

const N = Number(process.env.SWEEP_N ?? 400), NW = Number(process.env.SWEEP_W ?? 40), seed = process.env.SWEEP_SEED ?? 'bls-native-sound-v2';
const [shard, shards] = (process.env.SWEEP_SHARD ?? '0/1').split('/').map(Number);
export function sweepCases() {
  let ctr = 0; const rnd = () => BigInt('0x' + createHash('sha256').update(`${seed}:${ctr++}`).digest('hex')) % r;
  const cases = [];
  for (const n of FIXTURE_NAMES) cases.push({label: `fixture ${n}`, fx: FIXTURES[n]});
  const targets = [N_MIN, N_MIN + 1, N_MIN + 2, N_MIN + 3, N_MIN + 4, N_MIN + 6, N_MIN + 8, N_MIN + 10, N_MIN + 12, N_MIN + 16, N_MIN + 20];
  for (const c of forcedCases(targets)) cases.push({label: c.label, fx: mint(c.ns)});
  for (const [label, ns] of [['n = (0, 0)', [0n, 0n]], ['n = (1, 0)', [1n, 0n]], ['n = (r-1, r-1)', [r - 1n, r - 1n]], ['n = (r-1, 0)', [r - 1n, 0n]], ['n = (2^64, 2^128)', [1n << 64n, 1n << 128n]], ['n = (r/2, r/3)', [r / 2n, r / 3n]]])
    cases.push({label, fx: mint(ns)});
  const sc = () => 1n + rnd() % (r - 1n);
  const f0 = statementFor(maxSlots(N_MIN)).ns, f0d3 = statementFor(maxSlots(N_MIN), D3FIRST).ns, f1 = statementFor(maxSlots(N_MIN + 1)).ns;
  for (let i = 0; i < NW; i++) cases.push({label: `ALL15, random B and C #${i}`, fx: synthetic([ALL15, ALL15], sc(), sc())});
  for (let i = 0; i < NW; i++) cases.push({label: `forced n_q<=${N_MIN}, random B and C #${i}`, fx: synthetic(f0, sc(), sc())});
  for (let i = 0; i < 2 * NW; i++) cases.push({label: `forced n_q<=${N_MIN}, digit 3 first, random B and C #${i}`, fx: synthetic(f0d3, sc(), sc())});
  for (let i = 0; i < NW; i++) cases.push({label: `forced n_q<=${N_MIN + 1}, random B and C #${i}`, fx: synthetic(f1, sc(), sc())});
  for (let i = 0; i < NW; i++) { const ns = [rnd(), rnd()]; cases.push({label: `random B and C #${i}`, fx: synthetic(ns, 1n + rnd() % (r - 1n), 1n + rnd() % (r - 1n))}); }
  for (let i = 0; i < N; i++) cases.push({label: `random proof #${i}`, fx: mint([rnd(), rnd()])});
  return cases;
}
if (import.meta.url === `file://${process.argv[1]}`) {
const cases = sweepCases();
const results = [];
for (const [k, c] of cases.entries()) {
  if (k % shards !== shard) continue;
  const {w, pushes} = pushesFor(c.fx); const unl = unlockingsOf(pushes); const ctx = ctxOf(unl);
  const row = {label: c.label, inputs: c.fx.inputs.map(String), nq: w.nq, unlocking: unl.map((u) => u.length), txBytes: txSize(ctx)};
  for (const mode of ['consensus', 'standard']) {
    const v = verifyTx(ctx, mode); const rs = evalTx(ctx, mode);
    row[mode] = {valid: v === true, error: v === true ? null : String(v), op: rs.map((x) => x.op), budget: rs.map((x) => x.budget), margin: rs.map((x) => x.budget - x.op), marginPct: rs.map((x) => +(100 * (1 - x.op / x.budget)).toFixed(3))};
  }
  row.standardSize = unl.every((u) => u.length <= 10000) && row.txBytes <= 100000;
  results.push(row);
  console.log(`${c.label.padEnd(52)} n_q ${String(w.nq).padStart(3)} U ${row.unlocking.join(',')} | cons ${row.consensus.valid ? 'ok' : 'FAIL'} ${row.consensus.marginPct.map((x) => x.toFixed(2)).join('/')}% | std ${row.standard.valid ? 'ok' : 'FAIL'} ${row.standard.marginPct.map((x) => x.toFixed(2)).join('/')}%`);
  if (process.argv[2]) writeFileSync(process.argv[2], JSON.stringify({seed, shard: `${shard}/${shards}`, N_MIN, NQ_MAX, results}, null, 1) + '\n');
}
const failed = results.filter((x) => !x.consensus.valid || !x.standard.valid || !x.standardSize);
console.log(`cases ${results.length}, failed ${failed.length}`);
for (const mode of ['consensus', 'standard']) for (let i = 0; i < 4; i++) {
  const m = results.reduce((a, x) => (x[mode].marginPct[i] < a[mode].marginPct[i] ? x : a));
  console.log(`min ${mode} margin input ${i}: ${m[mode].marginPct[i].toFixed(2)}% (${m[mode].margin[i]} op of ${m[mode].budget[i]}) at ${m.label}`);
}
assert.equal(failed.length, 0, `failed: ${failed.map((x) => x.label).join(', ')}`);
}

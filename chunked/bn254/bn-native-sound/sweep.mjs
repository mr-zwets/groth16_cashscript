// Liveness sweep (bch-2026, consensus and standard mode): every case must be accepted with prover-sized fillers
// (6% standard margin per input, each unlocking capped at 10,000 B), and every input must meet the CAP RULE:
// op <= 0.94 x (41 + 10,000) x 800 = 7,550,832, i.e. even the forced worst case keeps a 6% margin at the cap.
// Cases: the 5 fixtures; special public inputs; forced GT-GLS witnesses (every nibble 15: max degree, n_q 132;
// every nibble 0: min degree, n_q 60; every nibble 1: full lookup cost at low degree; the review's worst case: zero
// nibbles at the 5 addition-first events and nibble 4 elsewhere, n_q 66); the lowest-n_q statements of a search;
// a lattice-shifted (non-Babai) valid witness; random proofs minted under the fixture VK.
// The first 5 forced cases also give the per-input op profile (merge item 5 of the design).
// Usage: [SWEEP_N=400] [SWEEP_SPARSE=8] [SWEEP_SEED=bn-native-sound-v1] [SWEEP_SHARD=k/n] node sweep.mjs [out.json]
import assert from 'node:assert/strict';
import {readFileSync, writeFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {FIXTURES, r, PI, glsDecompose, GLS_OFFSET, LATTICE, DIGITS, NE} from '../sound-si-gls/math.mjs';
import {mint, rng, denseStatement, thinDenseStatement, zeroStatement} from '../sound-si-gls/mint.mjs';
import {NQ_MAX, nqFor, BOUNDS} from './protocol.mjs';
import {buildProgram} from './script.mjs';
import {transactionFor} from './transaction.mjs';
import {spendAll, budgetOf} from './vm.mjs';

const N = Number(process.env.SWEEP_N ?? 400), SPARSE = Number(process.env.SWEEP_SPARSE ?? 8);
const seed = process.env.SWEEP_SEED ?? 'bn-native-sound-v1';
const [shard, shards] = (process.env.SWEEP_SHARD ?? '0/1').split('/').map(Number);
const CAP_BUDGET = budgetOf(new Uint8Array(10000)), CAP_RULE = Math.floor(0.94 * CAP_BUDGET);
const prog = buildProgram();
const built = JSON.parse(readFileSync(new URL('./build.json', import.meta.url), 'utf8'));
assert.equal(createHash('sha256').update(prog.code).digest('hex'), built.codeSha256, 'build.json is stale: run build.mjs');
const rnd = rng(seed);
const modr = (x) => ((x % r) + r) % r;
const nOf = (es) => modr(es.reduce((a, v, i) => a + v * PI[i], 0n));
const nqOf = (ns) => { const us = ns.map((n) => glsDecompose(n).map((e) => e + GLS_OFFSET)); return nqFor((ev) => us.flat().filter((u) => (u >> BigInt(64 - ev)) & 1n).length); };
const cases = [];
FIXTURES.fixtures.forEach((f, i) => cases.push({label: `fixture ${i}`, fx: f}));
{ const d = denseStatement(); cases.push({label: `forced: every nibble 15 (max degree, n_q ${NQ_MAX})`, fx: mint(...d.n, rnd), opts: {es: d.es}}); }
{ const d = zeroStatement(); cases.push({label: 'forced: every nibble 0 (min degree)', fx: mint(...d.n, rnd), opts: {es: d.es}}); }
{ const d = thinDenseStatement(); cases.push({label: 'forced: every nibble 1 (full lookups, low degree)', fx: mint(...d.n, rnd), opts: {es: d.es}}); }
// the review's worst case: nibble 4 (bit 2 only) at every event except the addition-first events (first event of a
// 2-event chunk that is an addition), where the nibble is 0
{ const addFirst = BOUNDS.map((b, k) => (k ? BOUNDS[k - 1] : 0)).filter((a, k) => BOUNDS[k] - a === 2 && DIGITS[a]);
  assert.deepEqual(addFirst, [20, 26, 34, 50, 54]);
  let u2 = (1n << 65n) - 1n; for (const e of addFirst) u2 -= 1n << BigInt(64 - e);
  const es = [0n, 0n, u2, 0n].map((u) => u - GLS_OFFSET); const n = nOf(es);
  cases.push({label: 'forced: nibble 4 except 0 at the addition-first events (review worst case)', fx: mint(n, n, rnd), opts: {es: [es, es]}}); }
for (const [label, ns] of [['n = (0, 0)', [0n, 0n]], ['n = (1, 0)', [1n, 0n]], ['n = (r-1, r-1)', [r - 1n, r - 1n]], ['n = (2^64, 0)', [1n << 64n, 0n]], ['n = (2^64-1, 2^64)', [(1n << 64n) - 1n, 1n << 64n]], ['n = (r/2, r/3)', [r / 2n, r / 3n]]])
  cases.push({label, fx: mint(...ns, rnd)});
{ const cand = []; for (let a = 0n; a < 64n; a++) for (const b of [0n, 1n, 1n << 64n, (1n << 64n) - 1n]) cand.push([a << 64n, b], [(a << 64n) + 1n, b], [b, a << 64n]);
  const srch = rng(seed + ':sparse'); for (let i = 0; i < 20000; i++) cand.push([srch(), srch()]);
  const scored = cand.map((ns) => ({ns: ns.map(modr), q: 0})); scored.forEach((x) => (x.q = nqOf(x.ns)));
  scored.sort((x, y) => x.q - y.q); for (const x of scored.slice(0, SPARSE)) cases.push({label: `sparse: n_q ${x.q}`, fx: mint(...x.ns, rnd)}); }
{ const es = FIXTURES.fixtures[0].publicInputs.map((n) => glsDecompose(BigInt(n))); let done = false;
  for (const v of LATTICE) for (const sg of [1n, -1n]) { const e2 = es[0].map((x, i) => x + sg * v[i]); if (!done && e2.every((x) => x >= -GLS_OFFSET && x < GLS_OFFSET)) { done = true; cases.push({label: 'fixture 0, lattice-shifted GLS witness', fx: FIXTURES.fixtures[0], opts: {es: [e2, es[1]]}}); } } }
for (let i = 0; i < N; i++) cases.push({label: `random #${i}`, fx: mint(rnd(), rnd(), rnd)});

const results = [];
for (const [k, c] of cases.entries()) {
  if (k % shards !== shard) continue;
  const t = transactionFor(c.fx, prog, c.opts ?? {});
  const row = {label: c.label, publicInputs: c.fx.publicInputs, nq: t.core.nq, fills: t.fills, unlocking: t.unlockings.map((u) => u.length)};
  for (const mode of ['consensus', 'standard']) {
    const xs = spendAll(t.unlockings.map(() => t.locking), t.unlockings, mode);
    row[mode] = {accepted: xs.every((x) => x.accepted), inputs: xs.map((x) => ({op: x.opCost, budget: x.budget, margin: +(1 - x.opCost / x.budget).toFixed(5), capMargin: +(1 - x.opCost / CAP_BUDGET).toFixed(5), error: x.error}))};
  }
  row.capRule = row.standard.inputs.every((x) => x.op <= CAP_RULE) && row.consensus.inputs.every((x) => x.op <= CAP_RULE);
  results.push(row);
  const f = (m) => row[m].inputs.map((x) => `${(x.op / 1e6).toFixed(3)}M ${(100 * x.margin).toFixed(2)}%`).join(' | ');
  console.log(`${c.label.slice(0, 60).padEnd(60)} nq=${String(row.nq).padStart(3)} U=${row.unlocking.join('/')} cons ${row.consensus.accepted} [${f('consensus')}] std ${row.standard.accepted} [${f('standard')}] cap ${row.capRule}`);
  if (process.argv[2]) writeFileSync(process.argv[2], JSON.stringify({seed, shard: `${shard}/${shards}`, capBudget: CAP_BUDGET, capRule: CAP_RULE, results}, null, 1) + '\n');
}
const failed = results.filter((x) => !x.consensus.accepted || !x.standard.accepted || !x.capRule);
console.log(`cases ${results.length}, failed ${failed.length}`);
for (const mode of ['consensus', 'standard']) for (let i = 0; i < 3; i++) {
  const m = results.reduce((a, x) => (x[mode].inputs[i].margin < a[mode].inputs[i].margin ? x : a)); const M = results.reduce((a, x) => (x[mode].inputs[i].op > a[mode].inputs[i].op ? x : a));
  console.log(`${mode} input ${i}: min margin ${(100 * m[mode].inputs[i].margin).toFixed(2)}% at ${m.label}; max op ${M[mode].inputs[i].op} (cap margin ${(100 * M[mode].inputs[i].capMargin).toFixed(2)}%) at ${M.label}`);
}
assert.equal(failed.length, 0, `failed: ${failed.map((x) => x.label).join(', ')}`);

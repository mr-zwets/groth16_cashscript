// Liveness sweep on the proposed bch-spec VM, consensus and standard modes: every case must be accepted, and
// the op-cost must fit the input's budget (10,000 + unlocking length) * 800. The op-cost is nearly constant
// (fixed schedule, table-based GLS), so the binding constraint is the SMALLEST unlocking, i.e. the smallest
// quotient n_q: the sweep includes the lowest-n_q statements a search finds, the maximum-degree witness
// (every GLS nibble 15 -> n_q = NQ_MAX), special inputs, the fixtures and random proofs minted under the fixture VK.
// Usage: [SWEEP_N=300] [SWEEP_SPARSE=8] [SWEEP_SEED=sound-si-gls-v1] [SWEEP_SHARD=k/n] node sweep.mjs [out.json]
import assert from 'node:assert/strict';
import {writeFileSync} from 'node:fs';
import {FIXTURES, r, glsDecompose, GLS_OFFSET, LATTICE} from './math.mjs';
import {NQ_MAX, nqFor} from './protocol.mjs';
import {locking, unlocking} from './transaction.mjs';
import {spend} from './vm.mjs';
import {mint, rng, denseStatement, thinDenseStatement, zeroStatement} from './mint.mjs';

const N = Number(process.env.SWEEP_N ?? 300), SPARSE = Number(process.env.SWEEP_SPARSE ?? 8);
const seed = process.env.SWEEP_SEED ?? 'sound-si-gls-v1';
const [shard, shards] = (process.env.SWEEP_SHARD ?? '0/1').split('/').map(Number);
const rnd = rng(seed);
const nqOf = (ns) => { const us = ns.map((n) => glsDecompose(n).map((e) => e + GLS_OFFSET)); return nqFor((ev) => us.flat().filter((u) => (u >> BigInt(64 - ev)) & 1n).length); };
const cases = [];
FIXTURES.fixtures.forEach((f, i) => cases.push({label: `fixture ${i}`, fx: f}));
for (const [label, ns] of [['n = (0, 0)', [0n, 0n]], ['n = (1, 0)', [1n, 0n]], ['n = (r-1, r-1)', [r - 1n, r - 1n]], ['n = (2^64, 0)', [1n << 64n, 0n]], ['n = (2^64-1, 2^64)', [(1n << 64n) - 1n, 1n << 64n]], ['n = (r/2, r/3)', [r / 2n, r / 3n]]])
  cases.push({label, fx: mint(...ns, rnd)});
{ const d = denseStatement(); cases.push({label: `max degree: every GLS nibble 15 (n_q ${NQ_MAX})`, fx: mint(...d.n, rnd), opts: {es: d.es}}); }
{ const d = zeroStatement(); cases.push({label: 'minimum degree: every GLS nibble 0', fx: mint(...d.n, rnd), opts: {es: d.es}}); }
{ const d = thinDenseStatement(); cases.push({label: 'liveness extreme: every nibble = 1 (full op, low degree)', fx: mint(...d.n, rnd), opts: {es: d.es}}); }
// lowest n_q found: structured candidates and random search (smallest unlocking = smallest budget)
{ const cand = []; for (let a = 0n; a < 64n; a++) for (const b of [0n, 1n, 1n << 64n, (1n << 64n) - 1n]) { cand.push([a << 64n, b], [(a << 64n) + 1n, b], [b, a << 64n]); }
  const srch = rng(seed + ':sparse'); for (let i = 0; i < 20000; i++) cand.push([srch(), srch()]);
  const scored = cand.map((ns) => ({ns: ns.map((x) => ((x % r) + r) % r), q: 0})); scored.forEach((x) => (x.q = nqOf(x.ns)));
  scored.sort((x, y) => x.q - y.q); for (const x of scored.slice(0, SPARSE)) cases.push({label: `sparse: n_q ${x.q}`, fx: mint(...x.ns, rnd)}); }
// a valid non-Babai witness (lattice-shifted decomposition) for fixture 0
{ const es = FIXTURES.fixtures[0].publicInputs.map((n) => glsDecompose(BigInt(n)));
  for (const v of LATTICE) for (const sg of [1n, -1n]) { const e2 = es[0].map((x, i) => x + sg * v[i]); if (!cases.some((c) => c.label.startsWith('fixture 0, lattice')) && e2.every((x) => x >= -GLS_OFFSET && x < GLS_OFFSET)) cases.push({label: 'fixture 0, lattice-shifted GLS witness', fx: FIXTURES.fixtures[0], opts: {es: [e2, es[1]]}}); } }
for (let i = 0; i < N; i++) cases.push({label: `random #${i}`, fx: mint(rnd(), rnd(), rnd)});

const results = [];
for (const [k, c] of cases.entries()) {
  if (k % shards !== shard) continue;
  const {w, unlocking: u} = unlocking(c.fx, c.opts);
  const row = {label: c.label, publicInputs: c.fx.publicInputs, nq: w.nq, unlockingLength: u.length};
  for (const mode of ['consensus', 'standard']) { const x = spend(locking, u, mode); row[mode] = {accepted: x.accepted, opCost: x.opCost, budget: x.budget, margin: x.budget - x.opCost, error: x.error}; }
  results.push(row);
  console.log(`${c.label.padEnd(44)} nq=${String(w.nq).padStart(3)} len=${u.length} cons ${row.consensus.accepted} ${row.consensus.opCost} (margin ${row.consensus.margin}, ${(100 * row.consensus.opCost / row.consensus.budget).toFixed(2)}%) std ${row.standard.accepted} ${row.standard.opCost} (margin ${row.standard.margin})`);
  if (process.argv[2]) writeFileSync(process.argv[2], JSON.stringify({seed, shard: `${shard}/${shards}`, results}, null, 1) + '\n');
}
const failed = results.filter((x) => !x.consensus.accepted || !x.standard.accepted);
console.log(`cases ${results.length}, failed ${failed.length}`);
for (const mode of ['consensus', 'standard']) { const m = results.reduce((a, x) => (x[mode].margin < a[mode].margin ? x : a)); const M = results.reduce((a, x) => (x[mode].opCost > a[mode].opCost ? x : a));
  console.log(`min ${mode} margin ${m[mode].margin} (${(100 * m[mode].opCost / m[mode].budget).toFixed(2)}% of ${m[mode].budget}) at ${m.label}; max op ${M[mode].opCost} at ${M.label}`); }
assert.equal(failed.length, 0, `rejected: ${failed.map((x) => x.label).join(', ')}`);

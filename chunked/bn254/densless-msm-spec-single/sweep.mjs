// Liveness sweep on the proposed bch-spec VM, consensus and standard modes. Every case must be
// accepted by both; prints op-cost, budget ((10,000 + unlocking length) * 800) and margin.
// Cases: the five public fixtures; the constructed MSM case n0 = 40988...880, n1 = 0; forced
// witnesses with all 128 Straus nibbles nonzero (the maximum number of mixed additions any
// witness can make, an upper bound for the canonical GLV decomposition); SWEEP_N uniformly
// random proofs; SWEEP_DENSE proofs whose public inputs were picked for few zero nibbles out of
// 20,000 candidates (as in ../densless-msm-slim/sweep.mjs). Proofs are minted under the fixture
// VK from the bench's pairing-vector trapdoor scalars.
// Usage: VERIFIER_DIR=<zk-verifier-bench> [SWEEP_N=300] [SWEEP_DENSE=40] [SWEEP_FORCED=10]
//        [SWEEP_SEED=densless-msm-spec-single-v1] [SWEEP_SHARD=k/n] node sweep.mjs [out.json]
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFileSync, writeFileSync} from 'node:fs';
import {bn254} from '@noble/curves/bn254.js';
import {createVirtualMachineBchSpec} from '@bitauth/libauth';
import {producePushes, encodeUnlocking, program} from './transaction.mjs';

const VDIR = process.env.VERIFIER_DIR;
const N = Number(process.env.SWEEP_N ?? 300), DENSE = Number(process.env.SWEEP_DENSE ?? 40), FORCED = Number(process.env.SWEEP_FORCED ?? 10);
const seed = process.env.SWEEP_SEED ?? 'densless-msm-spec-single-v1';
const [shard, shards] = (process.env.SWEEP_SHARD ?? '0/1').split('/').map(Number);
const glv = await import('../../pairing/gen_vkx_glv.mjs');
const mm = await import('../../pairing/_millermath.mjs');
const s = JSON.parse(readFileSync(VDIR + '/src/checkpoints/pairing-vectors.json')).scalars;
const fx = JSON.parse(readFileSync(new URL('../densless-recovered/public-fixtures.json', import.meta.url)));
const r = bn254.fields.Fr.ORDER, P = bn254.fields.Fp.ORDER;
const modr = (x) => ((x % r) + r) % r, inv = (x) => bn254.fields.Fr.inv(modr(x)), mod = (x) => ((x % P) + P) % P;
let counter = 0;
const rnd = () => modr(BigInt('0x' + createHash('sha256').update(`${seed}:${counter++}`).digest('hex')));
const G1 = bn254.G1.Point.BASE, G2 = bn254.G2.Point.BASE;
const [al, be, ga, de] = [s.alpha, s.beta, s.gamma, s.delta].map(BigInt), ic = s.ic.map(BigInt);
const g1 = (Pt) => { const a = Pt.toAffine(); return {x: a.x.toString(), y: a.y.toString()}; };
const g2 = (Pt) => { const a = Pt.toAffine(); return {x: {c0: a.x.c0.toString(), c1: a.x.c1.toString()}, y: {c0: a.y.c0.toString(), c1: a.y.c1.toString()}}; };
const mint = (n0, n1) => {
  const as = rnd(), bs = rnd(), vkx = modr(ic[0] + n0 * ic[1] + n1 * ic[2]);
  const cs = modr((as * bs - al * be - vkx * ga) * inv(de));
  return {proof: {a: g1(G1.multiply(as)), b: g2(G2.multiply(bs)), c: g1(G1.multiply(cs))}, publicInputs: [n0.toString(), n1.toString()]};
};
const zeroNibbles = (n0, n1) => { const ks = glv.glvDecomposeJoint(n0, n1); let z = 0; for (let i = 0; i < 128; i++) if (ks.every((k) => ((k >> BigInt(i)) & 1n) === 0n)) z++; return z; };

// Forced witness: 64 bytes with both nibbles nonzero; n0, n1 are what the on-chain GLV check
// rebuilds from them (S0 = k10 + lambda*k20, S1 = k11 + lambda*k21 mod r); zInv from the same
// Jacobian Straus the script runs (copied from ../pairfold5-msm/vkx-msm-asm.mjs).
const TABLE = Buffer.from(glv.GLV_SPLIT_TABLE_HEX.slice(2), 'hex'), LAM = glv.GLV_LAMBDA;
const Q0 = bn254.G1.Point.BASE.toAffine(), FINAL = mm.vk.ic[0].subtract(bn254.G1.Point.BASE.multiply(1n << 64n)).toAffine();
const dblJ = ([X, Y, Z]) => { const a = mod(X * X), b = mod(Y * Y), c = mod(b * b), d = mod(4n * X * b), e = 3n * a, f = mod(e * e), nx = mod(f - 2n * d); return [nx, mod((d - nx) * e - 8n * c), mod(2n * Y * Z)]; };
const maddJ = ([X, Y, Z], [bx, by]) => { const z1z1 = mod(Z * Z), u2 = mod(bx * z1z1); assert(u2 !== X); const s2 = mod(mod(z1z1 * Z) * by), h = mod(u2 - X), rr = mod(s2 - Y); const hh = mod(h * h), hhh = mod(h * hh), vv = mod(hh * X), nx = mod(rr * rr - hhh - 2n * vv); return [nx, mod((vv - nx) * rr - Y * hhh), mod(Z * h)]; };
const entry = (half, idx) => { const e = TABLE.subarray(half * 960 + (idx - 1) * 64, half * 960 + idx * 64); return [BigInt('0x' + Buffer.from(e.subarray(0, 32)).reverse().toString('hex')), BigInt('0x' + Buffer.from(e.subarray(32)).reverse().toString('hex'))]; };
const forced = () => {
  const w = Buffer.from(Array.from({length: 64}, () => { const x = Number(rnd() % 225n); return (1 + (x % 15)) + 16 * (1 + Math.floor(x / 15)); }));
  let s0lo = 0n, s1lo = 0n, s0hi = 0n, s1hi = 0n, acc = [Q0.x, Q0.y, 1n];
  for (const b of w) {
    const lo = BigInt(b % 16), hi = BigInt(b >> 4);
    s0lo = 2n * s0lo + lo % 2n + (lo / 2n % 2n) * LAM; s1lo = 2n * s1lo + lo / 4n % 2n + (lo / 8n) * LAM;
    s0hi = 2n * s0hi + hi % 2n + (hi / 2n % 2n) * LAM; s1hi = 2n * s1hi + hi / 4n % 2n + (hi / 8n) * LAM;
    acc = dblJ(acc); acc = maddJ(acc, entry(0, b % 16)); acc = maddJ(acc, entry(1, b >> 4));
  }
  acc = maddJ(acc, [FINAL.x, FINAL.y]);
  return {n0: modr(s0hi * (1n << 64n) + s0lo), n1: modr(s1hi * (1n << 64n) + s1lo), msm: {w, zInv: bn254.fields.Fp.inv(acc[2])}};
};

const cases = [];
fx.fixtures.forEach((f, i) => cases.push({label: `fixture ${i}`, ...f}));
cases.push({label: 'constructed n0=40988...880, n1=0', ...mint(4098837807667863457121099046250385181231815853636468318656855208660132831880n, 0n)});
for (let i = 0; i < FORCED; i++) { const f = forced(); cases.push({label: `forced 128 additions #${i}`, ...mint(f.n0, f.n1), msm: f.msm}); }
for (let i = 0; i < N; i++) cases.push({label: `random #${i}`, ...mint(rnd(), rnd())});
for (let i = 0; i < DENSE; i++) {
  let best, z = 999;
  for (let t = 0; t < 20000 && z > 0; t++) { const a = rnd(), b = rnd(), d = zeroNibbles(a, b); if (d < z) { z = d; best = [a, b]; } }
  cases.push({label: `dense #${i}`, ...mint(...best)});
}

const {locking} = program();
const vms = {consensus: createVirtualMachineBchSpec(false), standard: createVirtualMachineBchSpec(true)};
const results = [];
for (const [k, c] of cases.entries()) {
  if (k % shards !== shard) continue;
  const unlocking = encodeUnlocking(producePushes(fx.vk, c.proof, c.publicInputs, undefined, c.msm));
  const transaction = {version: 2, locktime: 0, inputs: [{outpointIndex: 0, outpointTransactionHash: new Uint8Array(32), sequenceNumber: 0, unlockingBytecode: unlocking}],
    outputs: [{lockingBytecode: Uint8Array.of(0x6a), valueSatoshis: 1000n}]};
  const sourceOutputs = [{lockingBytecode: locking, valueSatoshis: 1000n}];
  const budget = (10000 + unlocking.length) * 800;
  const row = {label: c.label, publicInputs: c.publicInputs, unlockingLength: unlocking.length, budget,
    zeroNibbles: c.msm ? 0 : zeroNibbles(...c.publicInputs.map(BigInt))};
  for (const [mode, vm] of Object.entries(vms)) {
    const st = vm.evaluate({inputIndex: 0, sourceOutputs, transaction});
    const verified = vm.verify({inputIndex: 0, sourceOutputs, transaction});
    row[mode] = {accepted: verified === true && vm.stateSuccess(st) === true, opCost: st.metrics.operationCost, margin: budget - st.metrics.operationCost, error: verified === true ? null : String(verified)};
  }
  results.push(row);
  console.log(`${c.label.padEnd(34)} zero=${String(row.zeroNibbles).padStart(3)} len=${row.unlockingLength} cons ${row.consensus.accepted} ${row.consensus.opCost} (margin ${row.consensus.margin}, ${(100 * row.consensus.opCost / budget).toFixed(1)}%) std ${row.standard.accepted} ${row.standard.opCost} (margin ${row.standard.margin})`);
  if (process.argv[2]) writeFileSync(process.argv[2], JSON.stringify({seed, shard: `${shard}/${shards}`, results}, null, 2) + '\n');
}
const min = (mode) => results.reduce((a, x) => (x[mode].margin < a[mode].margin ? x : a));
const failed = results.filter((x) => !x.consensus.accepted || !x.standard.accepted);
console.log(`cases ${results.length}, failed ${failed.length}`);
for (const mode of ['consensus', 'standard']) { const m = min(mode); console.log(`min ${mode} margin ${m[mode].margin} (${(100 * m[mode].opCost / m.budget).toFixed(2)}% of ${m.budget}) at ${m.label}`); }
assert.equal(failed.length, 0, `rejected: ${failed.map((x) => x.label).join(', ')}`);

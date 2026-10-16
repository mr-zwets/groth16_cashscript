// Reproducible dense-witness sweep under the fixture VK. Search for few zero Straus
// nibbles, then verify every whole transaction on standard BCH2026. This finite
// search does not prove a universal worst-case resource bound.
// Usage: VERIFIER_DIR=<zk-verifier-bench> SWEEP_N=30 node sweep.mjs
import assert from 'node:assert/strict';
import {readFileSync, writeFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {bn254} from '@noble/curves/bn254.js';
import {createVirtualMachineBch2026, hexToBin} from '@bitauth/libauth';
import {produceTransaction} from './transaction.mjs';
const VDIR = process.env.VERIFIER_DIR; const N = Number(process.env.SWEEP_N ?? 30);
const glv = await import('../../pairing/gen_vkx_glv.mjs');
const s = JSON.parse(readFileSync(VDIR + '/src/checkpoints/pairing-vectors.json')).scalars;
const fx = JSON.parse(readFileSync(new URL('../densless-recovered/public-fixtures.json', import.meta.url)));
const r = bn254.fields.Fr.ORDER, modr = (x) => ((x % r) + r) % r, inv = (x) => bn254.fields.Fr.inv(modr(x));
const seed = process.env.SWEEP_SEED ?? 'densless-msm-slim-v1';
let counter = 0;
const rnd = () => modr(BigInt('0x' + createHash('sha256').update(`${seed}:${counter++}`).digest('hex')));
const G1 = bn254.G1.Point.BASE, G2 = bn254.G2.Point.BASE;
const [al, be, ga, de] = [s.alpha, s.beta, s.gamma, s.delta].map(BigInt), ic = s.ic.map(BigInt);
const dense = (n0, n1) => { const ks = glv.glvDecomposeJoint(n0, n1); let z = 0; for (let i = 0; i < 128; i++) if (ks.every((k) => ((k >> BigInt(i)) & 1n) === 0n)) z++; return z; };
const g1 = (P) => { const a = P.toAffine(); return {x: a.x.toString(), y: a.y.toString()}; };
const g2 = (P) => { const a = P.toAffine(); return {x: {c0: a.x.c0.toString(), c1: a.x.c1.toString()}, y: {c0: a.y.c0.toString(), c1: a.y.c1.toString()}}; };
const vm = createVirtualMachineBch2026(true);
const peak = [0, 0, 0, 0, 0];
const FIX = process.env.SWEEP_FIXTURE;
const runs = [];
console.log(`seed=${seed}`);
for (let i = 0; i < N; i++) {
  let n0, n1, z = 999, tries = 0;
  while (z > 0 && tries++ < 20000) { const a = rnd(), b = rnd(); const d = dense(a, b); if (d < z) { z = d; n0 = a; n1 = b; } }
  const as = rnd(), bs = rnd(), vkx = modr(ic[0] + n0 * ic[1] + n1 * ic[2]);
  const cs = modr((as * bs - al * be - vkx * ga) * inv(de));
  const proof = {a: g1(G1.multiply(as)), b: g2(G2.multiply(bs)), c: g1(G1.multiply(cs))};
  const sample = FIX !== undefined ? fx.fixtures[FIX] : {proof, publicInputs: [n0.toString(), n1.toString()]};
  const zeros = FIX !== undefined ? dense(...sample.publicInputs.map(BigInt)) : z;
  const steps = produceTransaction(fx.vk, sample.proof, sample.publicInputs);
  const inputs = steps.map((st, n) => ({outpointIndex: n, outpointTransactionHash: new Uint8Array(32), sequenceNumber: 0, unlockingBytecode: hexToBin(st.unlocking)}));
  const sourceOutputs = steps.map((st) => ({lockingBytecode: hexToBin(st.locking), valueSatoshis: 1000n}));
  const transaction = {version: 2, locktime: 0, inputs, outputs: [{lockingBytecode: Uint8Array.of(0x6a), valueSatoshis: 1000n}]};
  const outcomes = steps.map((st, k) => {
    const state = vm.evaluate({inputIndex: k, sourceOutputs, transaction});
    const ok = vm.stateSuccess(state) === true;
    const p = 100 * state.metrics.operationCost / ((41 + inputs[k].unlockingBytecode.length) * 800);
    peak[k] = Math.max(peak[k], p);
    return {accepted: ok, error: state.error ?? null, operationCost: state.metrics.operationCost, budgetPercent: p};
  });
  const verified = vm.verify({inputIndex: 0, sourceOutputs, transaction});
  runs.push({proof: sample.proof, publicInputs: sample.publicInputs, zeroNibbles: zeros, outcomes, verified});
  if (process.env.SWEEP_JSON) writeFileSync(process.env.SWEEP_JSON, JSON.stringify({seed, runs, peak}, null, 2) + '\n');
  assert.equal(verified, true, `proof ${i}: ${verified}`);
  assert(outcomes.every(x => x.accepted), `proof ${i}: an input failed`);
  const row = outcomes.map(x => x.budgetPercent.toFixed(1));
  console.log(`proof ${i} zeroNibbles=${zeros}: ${row.join(' / ')}`);
}
console.log('PEAK %', peak.map((p) => p.toFixed(1)).join(' / '));

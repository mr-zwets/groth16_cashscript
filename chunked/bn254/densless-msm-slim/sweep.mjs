// Worst-case op-cost sweep: N fresh proofs under the fixture VK whose public inputs are chosen so
// every 4-bit Straus table index is nonzero (every position does both table adds), evaluated on the
// standard BCH 2026 VM inside one intra-tx transaction. Prints each input's op-cost / budget.
// Usage: VERIFIER_DIR=<zk-verifier-bench> SWEEP_N=30 node sweep.mjs
import {readFileSync} from 'node:fs';
import {randomBytes} from 'node:crypto';
import {bn254} from '@noble/curves/bn254.js';
import {createVirtualMachineBch2026, hexToBin} from '@bitauth/libauth';
import {produceTransaction} from './transaction.mjs';
const VDIR = process.env.VERIFIER_DIR; const N = Number(process.env.SWEEP_N ?? 30);
const glv = await import('../../pairing/gen_vkx_glv.mjs');
const s = JSON.parse(readFileSync(VDIR + '/src/checkpoints/pairing-vectors.json')).scalars;
const fx = JSON.parse(readFileSync(new URL('../densless-recovered/public-fixtures.json', import.meta.url)));
const r = bn254.fields.Fr.ORDER, modr = (x) => ((x % r) + r) % r, inv = (x) => bn254.fields.Fr.inv(modr(x));
const rnd = () => modr(BigInt('0x' + randomBytes(40).toString('hex')));
const G1 = bn254.G1.Point.BASE, G2 = bn254.G2.Point.BASE;
const [al, be, ga, de] = [s.alpha, s.beta, s.gamma, s.delta].map(BigInt), ic = s.ic.map(BigInt);
const dense = (n0, n1) => { const ks = glv.glvDecomposeJoint(n0, n1); let z = 0; for (let i = 0; i < 128; i++) if (ks.every((k) => ((k >> BigInt(i)) & 1n) === 0n)) z++; return z; };
const g1 = (P) => { const a = P.toAffine(); return {x: a.x.toString(), y: a.y.toString()}; };
const g2 = (P) => { const a = P.toAffine(); return {x: {c0: a.x.c0.toString(), c1: a.x.c1.toString()}, y: {c0: a.y.c0.toString(), c1: a.y.c1.toString()}}; };
const vm = createVirtualMachineBch2026(true);
const peak = [0, 0, 0, 0, 0];
const FIX = process.env.SWEEP_FIXTURE;
for (let i = 0; i < N; i++) {
  let n0, n1, z = 999, tries = 0;
  while (z > 0 && tries++ < 20000) { const a = rnd(), b = rnd(); const d = dense(a, b); if (d < z) { z = d; n0 = a; n1 = b; } }
  const as = rnd(), bs = rnd(), vkx = modr(ic[0] + n0 * ic[1] + n1 * ic[2]);
  const cs = modr((as * bs - al * be - vkx * ga) * inv(de));
  const proof = {a: g1(G1.multiply(as)), b: g2(G2.multiply(bs)), c: g1(G1.multiply(cs))};
  const steps = FIX !== undefined ? produceTransaction(fx.vk, fx.fixtures[FIX].proof, fx.fixtures[FIX].publicInputs) : produceTransaction(fx.vk, proof, [n0.toString(), n1.toString()]);
  const inputs = steps.map((st, n) => ({outpointIndex: n, outpointTransactionHash: new Uint8Array(32), sequenceNumber: 0, unlockingBytecode: hexToBin(st.unlocking)}));
  const sourceOutputs = steps.map((st) => ({lockingBytecode: hexToBin(st.locking), valueSatoshis: 1000n}));
  const transaction = {version: 2, locktime: 0, inputs, outputs: [{lockingBytecode: Uint8Array.of(0x6a), valueSatoshis: 1000n}]};
  const row = steps.map((st, k) => {
    const state = vm.evaluate({inputIndex: k, sourceOutputs, transaction});
    const ok = state.error === undefined && state.stack.length === 1;
    const p = 100 * state.metrics.operationCost / ((41 + inputs[k].unlockingBytecode.length) * 800);
    peak[k] = Math.max(peak[k], p);
    return `${ok ? '' : 'FAIL ' + state.error + ' '}${p.toFixed(1)}`;
  });
  console.log(`proof ${i} zeroNibbles=${z}: ${row.join(' / ')}`);
}
console.log('PEAK %', peak.map((p) => p.toFixed(1)).join(' / '));

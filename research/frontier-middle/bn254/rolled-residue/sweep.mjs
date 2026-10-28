// Liveness sweep (budget-loosened BCH 2026, consensus + standard): proofs minted under the singleton VK from the
// bench's pairing-vector trapdoor scalars (checked against the VK), special public inputs and random statements.
//   [SWEEP_N=12] node sweep.mjs [out.json]
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFileSync, writeFileSync} from 'node:fs';
import {bn254} from '@noble/curves/bn254.js';
import {VEC, VK, r} from './math.mjs';
import {prove} from './protocol.mjs';
import {p2sh32, encodeUnlocking, spend} from './vm.mjs';
const redeem = Buffer.from(readFileSync(new URL('./redeem.hex', import.meta.url), 'utf8').trim(), 'hex'); const locking = Buffer.from(p2sh32(redeem));
const s = VEC.scalars; const modr = (x) => ((x % r) + r) % r, inv = (x) => bn254.fields.Fr.inv(modr(x));
const G1 = bn254.G1.Point.BASE, G2 = bn254.G2.Point.BASE; const [al, be, ga, de] = [s.alpha, s.beta, s.gamma, s.delta].map(BigInt), ic = s.ic.map(BigInt);
assert.ok(VK.alpha.equals(G1.multiply(al)) && VK.beta.equals(G2.multiply(be)) && VK.gamma.equals(G2.multiply(ga)) && VK.delta.equals(G2.multiply(de)) && VK.ic.every((P, i) => P.equals(G1.multiply(ic[i]))), 'trapdoor matches the VK');
let c = 0; const rnd = () => modr(BigInt('0x' + createHash('sha256').update(`t2-sweep:${c++}`).digest('hex')));
const a1 = (P) => { const a = P.toAffine(); return {x: a.x.toString(), y: a.y.toString()}; }, a2 = (P) => { const a = P.toAffine(); return {x: {c0: a.x.c0.toString(), c1: a.x.c1.toString()}, y: {c0: a.y.c0.toString(), c1: a.y.c1.toString()}}; };
const mint = (n0, n1) => { const as = rnd(), bs = rnd(), vkx = modr(ic[0] + n0 * ic[1] + n1 * ic[2]); const cs = modr((as * bs - al * be - vkx * ga) * inv(de));
  return {proof: {a: a1(G1.multiply(as)), b: a2(G2.multiply(bs)), c: a1(G1.multiply(cs))}, publicInputs: [n0.toString(), n1.toString()]}; };
const cases = [['(0,0)', 0n, 0n], ['(1,0)', 1n, 0n], ['(0,1)', 0n, 1n], ['(r-1,r-1)', r - 1n, r - 1n], ['(2^253, 2^253-1)', 1n << 253n, (1n << 253n) - 1n], ['dense (2^254-1 mod r)', ((1n << 254n) - 1n) % r, ((1n << 254n) - 1n) % r]];
for (let i = 0; i < Number(process.env.SWEEP_N ?? 12); i++) cases.push([`random #${i}`, rnd(), rnd()]);
const out = [];
for (const [label, n0, n1] of cases) { const w = prove(mint(n0, n1)); const u = encodeUnlocking([w.W, redeem]); const row = {label};
  for (const m of ['consensus', 'standard']) { const x = spend(locking, u, m); row[m] = {accepted: x.accepted, opCost: x.opCost, error: x.error}; }
  out.push(row); console.log(label.padEnd(24), row.consensus.accepted, row.standard.accepted, row.consensus.opCost); }
if (process.argv[2]) writeFileSync(process.argv[2], JSON.stringify(out, null, 1) + '\n');
const bad = out.filter((x) => !x.consensus.accepted || !x.standard.accepted); console.log('cases', out.length, 'failed', bad.length, 'max op', Math.max(...out.map((x) => x.consensus.opCost)));
assert.equal(bad.length, 0);

// Mint valid Groth16 proofs under the fixture VK (for liveness tests) from the bench's pairing-vector trapdoor
// scalars (VERIFIER_DIR/src/checkpoints/pairing-vectors.json); the trapdoor is checked against the fixture VK.
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {existsSync, readFileSync} from 'node:fs';
import {bn254} from '@noble/curves/bn254.js';
import {FIXTURES, r, PI, GLS_OFFSET, g1, g2} from './math.mjs';
// VERIFIER_DIR: a zk-verifier-bench checkout. Default: the sibling of this repository's checkout, as zk-verifier-bench/
// (side-by-side clones) or bench/ (the work/<task>/{src,bench} worktree layout), whichever has the vectors.
const REPO_PARENT = new URL('../../../../../', import.meta.url).pathname;
const VDIR = process.env.VERIFIER_DIR ?? (['zk-verifier-bench', 'bench'].map((d) => REPO_PARENT + d).find((d) => existsSync(d + '/src/checkpoints/pairing-vectors.json')) ?? REPO_PARENT + 'zk-verifier-bench');
const s = JSON.parse(readFileSync(VDIR + '/src/checkpoints/pairing-vectors.json')).scalars;
const modr = (x) => ((x % r) + r) % r, inv = (x) => bn254.fields.Fr.inv(modr(x));
const G1 = bn254.G1.Point.BASE, G2 = bn254.G2.Point.BASE;
const [al, be, ga, de] = [s.alpha, s.beta, s.gamma, s.delta].map(BigInt), ic = s.ic.map(BigInt);
{ const vk = FIXTURES.vk; assert.ok(g1(vk.alpha).equals(G1.multiply(al)) && g2(vk.beta).equals(G2.multiply(be)) && g2(vk.gamma).equals(G2.multiply(ga)) && g2(vk.delta).equals(G2.multiply(de)));
  vk.ic.forEach((P, i) => assert.ok(g1(P).equals(G1.multiply(ic[i]))), 'trapdoor matches the fixture VK'); }
const aff1 = (P) => { const a = P.toAffine(); return {x: a.x.toString(), y: a.y.toString()}; };
const aff2 = (P) => { const a = P.toAffine(); return {x: {c0: a.x.c0.toString(), c1: a.x.c1.toString()}, y: {c0: a.y.c0.toString(), c1: a.y.c1.toString()}}; };
export const rng = (seed) => { let c = 0; return () => modr(BigInt('0x' + createHash('sha256').update(`${seed}:${c++}`).digest('hex'))); };
export const mint = (n0, n1, rnd) => {
  const as = rnd(), bs = rnd(), vkx = modr(ic[0] + n0 * ic[1] + n1 * ic[2]);
  const cs = modr((as * bs - al * be - vkx * ga) * inv(de));
  return {proof: {a: aff1(G1.multiply(as)), b: aff2(G2.multiply(bs)), c: aff1(G1.multiply(cs))}, publicInputs: [n0.toString(), n1.toString()]};
};
// a valid statement whose GLS witness has every nibble = 15 (u_{k,i} = 2^65 - 1, e = 2^64 - 1): the maximum degree
export const denseStatement = () => { const e = [0, 1, 2, 3].map(() => GLS_OFFSET - 1n); const n = modr(e.reduce((a, v, i) => a + v * PI[i], 0n)); return {n: [n, n], es: [e, e]}; };
// the liveness extreme: every nibble nonzero (full table-lookup op cost) with ONE bit per group and event (near-minimal degree):
// u_{k,0} = 2^65 - 1, u_{k,1..3} = 0, i.e. e = (2^64 - 1, -2^64, -2^64, -2^64)
export const thinDenseStatement = () => { const e = [GLS_OFFSET - 1n, -GLS_OFFSET, -GLS_OFFSET, -GLS_OFFSET]; const n = modr(e.reduce((a, v, i) => a + v * PI[i], 0n)); return {n: [n, n], es: [e, e]}; };
// the minimum degree: every nibble 0 (u = 0, e = -2^64): smallest possible quotient, hence smallest budget
export const zeroStatement = () => { const e = [0, 1, 2, 3].map(() => -GLS_OFFSET); const n = modr(e.reduce((a, v, i) => a + v * PI[i], 0n)); return {n: [n, n], es: [e, e]}; };

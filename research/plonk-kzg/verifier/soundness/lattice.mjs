// Numeric checks behind SOUNDNESS.md (run: node soundness/lattice.mjs from the verifier directory).
//   1. GLV: lambda^2 + lambda + 1 = 0 mod r and phi(x, y) = (beta x, y) = [lambda](x, y) on G1 (the pair the script uses).
//   2. Lemma 2: the lattice L = {(a, b) in Z^2 : a + lambda b = 0 mod r}. Lagrange-Gauss reduction gives a reduced basis;
//      its first vector is a shortest nonzero vector. If ||v1||^2 > 2 (2^64 - 1)^2, no nonzero (a, b) with
//      |a|, |b| < 2^64 lies in L, so (u1, u2) -> u1 + lambda u2 mod r is injective on [0, 2^64)^2.
//   3. Lemma 1: 1 + t' takes 2^128 distinct values mod r (2^128 < r).
//   4. Ranges the proof relies on: the digit offsets keep s' < 2^255 (51 windows) and u_i' < 2^70 (14 windows).
//   5. The SI term (SI-GLS argument with this build's degrees) and the hash-bias factors; the total bound for Q = 2^64.
import assert from 'node:assert/strict';
import {p, r, mod, GLV, G1} from '../math.mjs';
import {NW, NWR} from '../plonk.mjs';
import {digitOffset} from '../script.mjs';
import {NQ_MAX, NSTATES, K_IDS, chunkDegP, TERM_DEG_P, nqMax} from '../si.mjs';
import {PI as GT_PI, GLS_OFFSET, glsDecompose} from '../gt.mjs';

const bits = (x) => (x < 0n ? -x : x).toString(2).length;
const log2 = (x) => { const b = bits(x); return b <= 60 ? Math.log2(Number(x)) : b - 60 + Math.log2(Number(x >> BigInt(b - 60))); };
const lg = (num, den) => log2(num) - log2(den); // log2(num / den)
const out = {};

// 1. GLV pair
const lam = GLV.lambda, beta = GLV.beta;
assert.equal(mod(lam * lam + lam + 1n, r), 0n);
assert.equal(mod(beta * beta * beta, p), 1n); assert.notEqual(beta, 1n);
for (const k of [1n, 2n, 3n, 0xdeadbeefn, r - 1n, (1n << 200n) + 12345n]) {
  const P = G1.BASE.multiply(k).toAffine();
  assert.ok(G1.fromAffine({x: mod(beta * P.x), y: P.y}).equals(G1.BASE.multiply(k).multiply(lam)), 'phi != [lambda]');
}
out.glv = {lambda: '0x' + lam.toString(16), lambdaBits: bits(lam), beta: '0x' + beta.toString(16)};

// 2. lattice {(a, b): a + lambda b = 0 mod r}: basis (r, 0), (-lambda, 1); Lagrange-Gauss reduction
const dot = (u, v) => u[0] * v[0] + u[1] * v[1];
const sub = (u, v, q) => [u[0] - q * v[0], u[1] - q * v[1]];
const rnd = (n, d) => { const q = n / d, rem = n - q * d; return 2n * (rem < 0n ? -rem : rem) >= (d < 0n ? -d : d) ? q + ((rem < 0n) !== (d < 0n) ? -1n : 1n) : q; };
let b1 = [r, 0n], b2 = [-lam, 1n];
if (dot(b1, b1) < dot(b2, b2)) [b1, b2] = [b2, b1];
for (;;) { // invariant: ||b1|| >= ||b2||
  b1 = sub(b1, b2, rnd(dot(b1, b2), dot(b2, b2)));
  if (dot(b1, b1) >= dot(b2, b2)) { [b1, b2] = [b2, b1]; break; }
  [b1, b2] = [b2, b1];
}
// now b1 is the shorter; reduced: 2 |<b1, b2>| <= ||b1||^2 <= ||b2||^2
const inL = (v) => mod(v[0] + lam * v[1], r) === 0n;
assert.ok(inL(b1) && inL(b2)); assert.equal((b1[0] * b2[1] - b1[1] * b2[0]) ** 2n, r * r, 'not a basis');
assert.ok(2n * (dot(b1, b2) < 0n ? -dot(b1, b2) : dot(b1, b2)) <= dot(b1, b1) && dot(b1, b1) <= dot(b2, b2), 'not reduced');
const B = (1n << 64n) - 1n;
assert.ok(dot(b1, b1) > 2n * B * B, 'shortest vector too short: injectivity fails');
out.lattice = {
  v1: b1.map(String), v2: b2.map(String), v1ComponentBits: b1.map(bits), v2ComponentBits: b2.map(bits),
  log2_lambda1: log2(dot(b1, b1)) / 2, log2_lambda2: log2(dot(b2, b2)) / 2, log2_maxDifferenceNorm: log2(2n * B * B) / 2,
  cosAngle: Number(dot(b1, b2)) / Math.sqrt(Number(dot(b1, b1)) * Number(dot(b2, b2))), log2_sqrt_r: log2(r) / 2,
  log2_hermiteBound: (log2(r) + Math.log2(2 / Math.sqrt(3))) / 2, // lambda1^2 <= (2/sqrt 3) det
  log2_minkowskiBound: (log2(r) + Math.log2(4 / Math.PI)) / 2,      // lambda1^2 <= (4/pi) det
};
assert.ok(out.lattice.log2_lambda1 <= out.lattice.log2_hermiteBound);

// 3. t' range
assert.ok(1n << 128n < r);
out.tprime = {log2_r: log2(r), note: '1 + t\' in [1, 2^128] are distinct mod r'};

// 4. digit ranges (signed base-32, digit = ((s' >> 5i) & 31) - 16): need 0 <= s' < 32^nw
const C51 = digitOffset(NW), C14 = digitOffset(NWR);
assert.ok(r - 1n + C51 < 1n << BigInt(5 * NW)); assert.equal(5 * NW, 255);
assert.ok(B + C14 < 1n << BigInt(5 * NWR));
out.digits = {log2_maxSprime: log2(r - 1n + C51), windowsBits: 5 * NW, log2_maxUprime: log2(B + C14), windowsBitsR: 5 * NWR};

// 5. bias factors, SI term, totals
const ceilDiv = (a, b) => (a + b - 1n) / b;
const T = 1n << 256n;
const biasR = Number(ceilDiv(T, r)) / Number(T * 1000000n / r) * 1e6, biasP = Number(ceilDiv(T, p)) / Number(T * 1000000n / p) * 1e6;
const degD = Math.max(...Array.from({length: NSTATES}, (_, k) => chunkDegP(k) + 6), TERM_DEG_P + 22);
const degQM = 2 * NQ_MAX - 1 + 12;
const degSI = Math.max(degD, degQM);
const log2eSI = Math.log2(biasP * ((K_IDS - 1) + degSI)) - log2(p);
// Bad (Lemma 0): reduced-output collisions mod r and early use, <= Q^2 * 15 * 2^-256 (each residue has mass <= ceil(2^256/r) / 2^256)
const perResidue = Number(ceilDiv(T, r)); // 6
const log2Bad = Math.log2((perResidue / 2) + 2 * perResidue) - 256; // pairwise collisions + use-before-query (2 positions per query)
out.si = {NQ_MAX, K_IDS, maxDegD: degD, degQM, degSI, biasP, log2_perQuery: log2eSI};
out.bias = {ceil_2_256_over_r: perResidue, biasR, ceil_2_256_over_p: Number(ceilDiv(T, p)), biasP};
out.bad = {log2_perQsquared: log2Bad};
// 6. Track 7 GT fold (Lemma 4): degrees with m folded bases (up to 4 monic degree-6 factors per base and event), the SI
//    term with them, and the GT decomposition range: Babai gives |e| < 2^64, so u = e + 2^64 has 65 bits (65 events)
out.gtFold = {};
// m = 8, 9: v1 (Qk absent / present); 10, 11: BSB22 with one commitment (Qcp_0 folded; Qk absent / present)
for (const m of [8, 9, 10, 11]) { const dD = Math.max(...Array.from({length: NSTATES}, (_, k) => chunkDegP(k, m) + 6)); const nq = nqMax(m); const deg = Math.max(dD, 2 * nq - 1 + 12);
  out.gtFold['m' + m] = {NQ: nq, maxDegD: dD, degSI: deg, log2_perQuery: Math.log2(biasP * ((K_IDS - 1) + deg)) - log2(p)}; }
for (const n of [0n, 1n, r - 1n, (r - 1n) / 2n, 0x1234567890abcdefn * (r / 0x1000000000000000n)]) glsDecompose(n).forEach((e) => assert.ok(e > -GLS_OFFSET && e < GLS_OFFSET));
assert.equal(mod(GT_PI[1] ** 4n - GT_PI[1] ** 2n + 1n, r), 0n, 'p is a primitive 12th root of unity mod r (Phi_12(p) = 0)');
const log2eSIfold = Math.max(...Object.values(out.gtFold).map((x) => x.log2_perQuery)); // the worst folded build
const Q = 64;
const terms = {kzgBatch_tprime: Q - 128, si: Q + Math.max(log2eSI, log2eSIfold), bad: 2 * Q + log2Bad, hashTargets: Q + Math.log2(9) - 256};
const total = Math.log2(Object.values(terms).reduce((a, x) => a + 2 ** x, 0));
out.totalForQ2e64 = {log2_terms: terms, log2_total_excluding_epsPLONK: total};
console.log(JSON.stringify(out, null, 1));

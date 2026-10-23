// Honest-prover reference for the hybrid-direct protocol (JS only, no VM):
//  - exact affine Miller lines for (-A,B) [runtime], (vk_x,gamma), (C,delta) [fixed], plus baked
//    K = Miller(alpha,beta), residue root c in the quotient torus (u = c1/c0),
//  - torus-normalized checkpoint states G_j (6 limbs), per-segment odd quotients Q_j,
//  - Fiat-Shamir g, z; the batched identity  sum_j g^j (R_j(z) - R_j(-z)) == Q(z) M(z)
//    evaluated the way the script would (scalars only, lines from (lambda, beta, x_P, y_P)),
//  - the exact terminal verdict [tau(G_J) c^{p^2}] == [c^p c^{p^3}] in Fp12*/Fp6*,
//  - a consistency check that every R_j has the degree schedule.mjs predicts.
// Usage: node ref.mjs [fixtureIndex]
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {digits, EVENTS, LAST, segDeg, qOdd, bestSegmentation} from './schedule.mjs';

import {bn254} from '@noble/curves/bn254.js';
import {psiFrobenius} from '@noble/curves/abstract/tower.js';
import * as RW from '../../../../chunked/bn254/densless-recovered/root-witness.mjs';
const fx = JSON.parse(readFileSync(new URL('../../../../chunked/bn254/densless-recovered/public-fixtures.json', import.meta.url)));

const {Fp, Fp2, Fp6, Fp12} = bn254.fields;
const P = Fp.ORDER;
const mod = (x) => ((x % P) + P) % P;
const fixture = fx.fixtures[Number(process.argv[2] ?? 0)];
const {vk} = fx; const {proof, publicInputs} = fixture;

// ---------- points ----------
const g1 = (p) => bn254.G1.Point.fromAffine({x: BigInt(p.x), y: BigInt(p.y)});
const g2 = (p) => bn254.G2.Point.fromAffine({x: {c0: BigInt(p.x.c0), c1: BigInt(p.x.c1)}, y: {c0: BigInt(p.y.c0), c1: BigInt(p.y.c1)}});
const A = g1(proof.a), C = g1(proof.c);
const B = bn254.G2.Point.fromAffine({x: {c0: BigInt(proof.b.x.c0), c1: BigInt(proof.b.x.c1)}, y: {c0: BigInt(proof.b.y.c0), c1: BigInt(proof.b.y.c1)}});
let vkx = g1(vk.ic[0]);
publicInputs.forEach((n, i) => { if (BigInt(n)) vkx = vkx.add(g1(vk.ic[i + 1]).multiply(BigInt(n))); });
const pairs = [
  {P: A.negate().toAffine(), Q: B, runtime: true},
  {P: vkx.toAffine(), Q: g2(vk.gamma), runtime: false},
  {P: C.toAffine(), Q: g2(vk.delta), runtime: false},
];

// ---------- tower <-> flat <-> polynomial ----------
const flat = (x) => [x.c0.c0.c0, x.c0.c0.c1, x.c0.c1.c0, x.c0.c1.c1, x.c0.c2.c0, x.c0.c2.c1,
  x.c1.c0.c0, x.c1.c0.c1, x.c1.c1.c0, x.c1.c1.c1, x.c1.c2.c0, x.c1.c2.c1];
const f6 = (t) => Fp6.create({c0: Fp2.fromBigTuple([t[0], t[1]]), c1: Fp2.fromBigTuple([t[2], t[3]]), c2: Fp2.fromBigTuple([t[4], t[5]])});
const mk12 = (lo, hi) => Fp12.create({c0: f6(lo), c1: f6(hi)});
const f6flat = (a) => [a.c0.c0, a.c0.c1, a.c1.c0, a.c1.c1, a.c2.c0, a.c2.c1];
// w -> X, v = w^2 -> X^2, u = w^6 - 9 -> X^6 - 9 ; Fp12 = Fp[X]/(X^12 - 18 X^6 + 82)
const polyOf = (c) => {
  const out = Array(12).fill(0n);
  for (const [i, d] of [0, 2, 4, 1, 3, 5].entries()) { out[d] = mod(c[2 * i] - 9n * c[2 * i + 1]); out[d + 6] = c[2 * i + 1]; }
  return out;
};
const pmul = (a, b) => { const o = Array(a.length + b.length - 1).fill(0n); for (let i = 0; i < a.length; i++) if (a[i]) for (let j = 0; j < b.length; j++) o[i + j] += a[i] * b[j]; return o.map(mod); };
const trim = (a) => { const b = a.slice(); while (b.length > 1 && b.at(-1) === 0n) b.pop(); return b; };
const peval = (a, z) => a.reduceRight((acc, c) => mod(acc * z + c), 0n);
const tau = (g) => mk12([1n, 0n, 0n, 0n, 0n, 0n], g); // 1 + w*g
const neg6 = (g) => g.map((x) => mod(-x));

// ---------- exact affine Miller lines (scale dropped: Fp2 factors die in Fp12*/Fp6*) ----------
const {psi} = psiFrobenius(Fp, Fp2, Fp2.NONRESIDUE);
const events = Array.from({length: EVENTS}, () => []); // per event: [{pair, lam, beta}]
const running = pairs.map((p) => p.Q.toAffine());
const addAff = (T, U) => { const lam = Fp2.div(Fp2.sub(U.y, T.y), Fp2.sub(U.x, T.x)); const x = Fp2.sub(Fp2.sub(Fp2.sqr(lam), T.x), U.x); return {lam, beta: Fp2.sub(Fp2.mul(lam, T.x), T.y), R: {x, y: Fp2.sub(Fp2.mul(lam, Fp2.sub(T.x, x)), T.y)}}; };
const dblAff = (T) => { const lam = Fp2.div(Fp2.mul(Fp2.sqr(T.x), 3n), Fp2.add(T.y, T.y)); const x = Fp2.sub(Fp2.sqr(lam), Fp2.add(T.x, T.x)); return {lam, beta: Fp2.sub(Fp2.mul(lam, T.x), T.y), R: {x, y: Fp2.sub(Fp2.mul(lam, Fp2.sub(T.x, x)), T.y)}}; };
for (let e = 0; e < EVENTS; e++) {
  for (let j = 0; j < 3; j++) {
    const d = dblAff(running[j]); events[e].push({pair: j, lam: d.lam, beta: d.beta}); running[j] = d.R;
    if (digits[e]) {
      const q = pairs[j].Q.toAffine(), tgt = digits[e] < 0 ? {x: q.x, y: Fp2.neg(q.y)} : q;
      const a = addAff(running[j], tgt); events[e].push({pair: j, lam: a.lam, beta: a.beta}); running[j] = a.R;
    }
  }
}
for (let j = 0; j < 3; j++) {
  const q = pairs[j].Q.toAffine(), q1 = psi(q.x, q.y), q2 = psi(q1[0], q1[1]);
  for (const t of [{x: q1[0], y: q1[1]}, {x: q2[0], y: Fp2.neg(q2[1])}]) {
    const a = addAff(running[j], t); events[LAST].push({pair: j, lam: a.lam, beta: a.beta}); running[j] = a.R;
  }
}
// subgroup endpoint (as minop): R_final for pair 0 must equal -psi^3(B) ... here we just check the
// trajectory ended where the optimal-ate relation says: [6x+2]B + psi(B) - psi^2(B) = -psi^3(B)
{
  const q = B.toAffine(), q1 = psi(q.x, q.y), q2 = psi(q1[0], q1[1]), q3 = psi(q2[0], q2[1]);
  assert.ok(Fp2.eql(running[0].x, q3[0]) && Fp2.eql(running[0].y, Fp2.neg(q3[1])), 'B endpoint relation');
}
const lineFlat = (L) => { const {x, y} = pairs[L.pair].P; return [y, 0n, 0n, 0n, 0n, 0n, mod(-L.lam.c0 * x), mod(-L.lam.c1 * x), L.beta.c0, L.beta.c1, 0n, 0n]; };
const lineFp12 = (L) => { const c = lineFlat(L); return mk12(c.slice(0, 6), c.slice(6)); };

// raw Miller product, K, final exponentiation sanity
let raw = Fp12.ONE;
for (let e = 0; e < EVENTS; e++) { raw = Fp12.sqr(raw); for (const L of events[e]) raw = Fp12.mul(raw, lineFp12(L)); }
const alpha = g1(vk.alpha), beta = g2(vk.beta);
const Kfull = bn254.pairing(alpha, beta, false);
const fAll = Fp12.mul(raw, Kfull);
assert.ok(Fp12.eql(Fp12.finalExponentiate(fAll), Fp12.ONE), 'pairing product must be 1');
const Kt = f6flat(Fp6.mul(Kfull.c1, Fp6.inv(Kfull.c0))); // baked torus coordinate of K

// residue root in the quotient torus
const wit = RW.residueWitness(fAll);
assert.ok(Fp6.eql(wit.w.c1, Fp6.ZERO), 'w lies in Fp6 (killed by the torus quotient)');
assert.ok(!Fp6.eql(wit.c.c0, Fp6.ZERO), 'c in the finite torus chart (else apply the kernel shift)');
const u = f6flat(Fp6.mul(wit.c.c1, Fp6.inv(wit.c.c0)));

// ---------- exact fused accumulator and checkpoint states ----------
const best = bestSegmentation();
const segs = best.segs;
const ends = new Set(segs.map(([, b]) => b));
const cFold = (d) => tau(d > 0 ? neg6(u) : u); // c^{-d}
let F = tau(neg6(u));
const states = []; // G_j after each segment end
for (let e = 0; e < EVENTS; e++) {
  F = Fp12.sqr(F);
  for (const L of events[e]) F = Fp12.mul(F, lineFp12(L));
  if (digits[e]) F = Fp12.mul(F, cFold(digits[e]));
  if (e === LAST) F = Fp12.mul(F, tau(Kt));
  if (ends.has(e)) states.push(f6flat(Fp6.mul(F.c1, Fp6.inv(F.c0))));
}
// terminal verdict (exact): [tau(G_J) c^{p^2}] == [c^p c^{p^3}]
{
  const cT = tau(u), GJ = tau(states.at(-1));
  const lhs = Fp12.mul(GJ, Fp12.frobeniusMap(cT, 2)), rhs = Fp12.mul(Fp12.frobeniusMap(cT, 1), Fp12.frobeniusMap(cT, 3));
  const ratio = Fp12.mul(lhs, Fp12.inv(rhs));
  assert.ok(Fp6.eql(ratio.c1, Fp6.ZERO), 'terminal torus verdict');
}

// ---------- polynomial side: R_j, odd quotients Q_j ----------
const M = [82n, 0n, 0n, 0n, 0n, 0n, mod(-18n), 0n, 0n, 0n, 0n, 0n, 1n];
const divM = (num) => { // exact division by monic M; returns quotient, asserts zero remainder
  const r = num.slice(); const q = Array(Math.max(1, r.length - 12)).fill(0n);
  for (let i = r.length - 1; i >= 12; i--) { const v = r[i]; if (!v) continue; q[i - 12] = v; r[i] = 0n; r[i - 6] = mod(r[i - 6] + 18n * v); r[i - 12] = mod(r[i - 12] - 82n * v); }
  return {q, rem: r.slice(0, 12)};
};
const flip = (a) => a.map((c, i) => (i % 2 ? mod(-c) : c)); // a(-X)
const Rpolys = [], Qs = [];
let prev = neg6(u);
segs.forEach(([a, b], j) => {
  let Pp = polyOf(flat(tau(prev)));
  for (let e = a; e <= b; e++) {
    Pp = pmul(Pp, Pp);
    for (const L of events[e]) Pp = pmul(Pp, polyOf(lineFlat(L)));
    if (digits[e]) Pp = pmul(Pp, polyOf(flat(cFold(digits[e]))));
    if (e === LAST) Pp = pmul(Pp, polyOf(flat(tau(Kt))));
  }
  const R = pmul(Pp, polyOf(flat(tau(neg6(states[j])))));
  assert.equal(trim(R).length - 1, segDeg(a, b), `degree schedule, segment ${j}`);
  const D = R.map((c, i) => mod(c - flip(R)[i]));
  const {q, rem} = divM(D);
  assert.ok(rem.every((x) => x === 0n), `segment ${j}: odd part of R_j mod M must vanish`);
  assert.ok(q.every((x, i) => i % 2 === 1 || x === 0n), 'Q_j is odd');
  Rpolys.push(R); Qs.push(q); prev = states[j];
});

// ---------- transcript ----------
const be32 = (x) => Buffer.from(mod(x).toString(16).padStart(64, '0'), 'hex');
const H = (...bufs) => createHash('sha256').update(Buffer.concat(bufs)).digest();
const toF = (h) => mod(BigInt('0x' + h.toString('hex')));
const aA = A.toAffine(), aB = B.toAffine(), aC = C.toAffine();
const T0 = H(Buffer.from('hybrid-direct/v1'), Buffer.alloc(32, 0x5a) /* VK digest constant */,
  ...[aA.x, aA.y, aB.x.c0, aB.x.c1, aB.y.c0, aB.y.c1, aC.x, aC.y, ...publicInputs.map(BigInt)].map(be32),
  ...u.map(be32), ...states.flat().map(be32));
const g = toF(H(T0, Buffer.from([1])));
const nQ = qOdd(best.D);
const Qagg = Array(2 * nQ + 1).fill(0n);
let gp = 1n;
for (const q of Qs) { trim(q).forEach((c, i) => { assert.ok(i < Qagg.length || c === 0n); Qagg[i] = mod(Qagg[i] + gp * c); }); gp = mod(gp * g); }
const Qodd = Qagg.filter((_, i) => i % 2 === 1);
assert.ok(Qodd.length <= nQ);
while (Qodd.length < nQ) Qodd.push(0n); // fixed-length format
const z = toF(H(T0, be32(g), ...Qodd.map(be32)));

// ---------- on-chain-style scalar evaluation ----------
let mulCount = 0; const mm = (a, b) => { mulCount++; return mod(a * b); };
const z2 = mm(z, z), z3 = mm(z2, z), z4 = mm(z2, z2), z6 = mm(z3, z3), s = mod(z6 - 9n);
const basis6 = [1n, s, z2, mm(s, z2), z4, mm(s, z4)];
const g6 = (G) => mod(G.reduce((acc, x, i) => acc + x * basis6[i], 0n)); mulCount += 0; // lazy dot (6 raw mul, 1 mod)
const tauPM = (G) => { const t = mm(z, g6(G)); return [mod(1n + t), mod(1n - t)]; }; // tau(G)(z), tau(G)(-z)
const z3s = mm(z3, s);
const pre = pairs.map((p) => { const a1 = mm(mod(-p.P.x), z); return {e: p.P.y, a1, a2: mm(a1, s)}; });
const lineOdd = (L) => { const k = pre[L.pair]; return mod(k.a1 * L.lam.c0 + k.a2 * L.lam.c1 + z3 * L.beta.c0 + z3s * L.beta.c1); }; // 4 raw mul, 1 mod
const [cmP, cmM] = tauPM(neg6(u)); // c^{-1}(+-z)
const [cpP, cpM] = [cmM, cmP];     // c(+-z) = tau(u)(+-z) = tau(-u)(-+z)
const [kP, kM] = tauPM(Kt);
let accP = cmP, accM = cmM, S = 0n, gj = 1n;
segs.forEach(([a, b], j) => {
  for (let e = a; e <= b; e++) {
    accP = mm(accP, accP); accM = mm(accM, accM);
    for (const L of events[e]) { const o = lineOdd(L), y = pre[L.pair].e; accP = mm(accP, mod(y + o)); accM = mm(accM, mod(y - o)); }
    if (digits[e] > 0) { accP = mm(accP, cmP); accM = mm(accM, cmM); }
    if (digits[e] < 0) { accP = mm(accP, cpP); accM = mm(accM, cpM); }
    if (e === LAST) { accP = mm(accP, kP); accM = mm(accM, kM); }
  }
  const [tP, tM] = tauPM(states[j]);
  const Rz = mm(accP, tM), Rmz = mm(accM, tP); // R_j(z) = P(z) tau(-G)(z) = P(z) tau(G)(-z)
  assert.equal(Rz, peval(Rpolys[j], z)); assert.equal(Rmz, peval(Rpolys[j], mod(-z)));
  S = mod(S + mm(gj, mod(Rz - Rmz))); gj = mm(gj, g);
  accP = tP; accM = tM;
});
let Qz = 0n; for (let i = nQ - 1; i >= 0; i--) Qz = mm(Qz, z2) + Qodd[i], Qz = mod(Qz); Qz = mm(Qz, z); // Horner in z^2
const Mz = mod(mm(z6, z6) - 18n * z6 + 82n);
assert.equal(S, mm(Qz, Mz), 'batched SZ identity');

// negative control: perturb one state limb -> no quotient exists for that segment
{
  const bad = states.map((x) => x.slice()); bad[10][3] = mod(bad[10][3] + 1n);
  const [a, b] = segs[10];
  let Pp = polyOf(flat(tau(bad[9])));
  for (let e = a; e <= b; e++) { Pp = pmul(Pp, Pp); for (const L of events[e]) Pp = pmul(Pp, polyOf(lineFlat(L))); if (digits[e]) Pp = pmul(Pp, polyOf(flat(cFold(digits[e])))); }
  const R = pmul(Pp, polyOf(flat(tau(neg6(bad[10])))));
  const {rem} = divM(R.map((c, i) => mod(c - flip(R)[i])));
  assert.ok(rem.some((x) => x !== 0n), 'perturbed state leaves a nonzero odd residue');
}
console.log(JSON.stringify({
  fixture: Number(process.argv[2] ?? 0), events: EVENTS, lines: events.flat().length, segments: segs.length,
  maxDeg: best.D, quotientOddCoeffs: nQ, stateLimbs: 6 * states.length,
  onChainStyleModMuls: mulCount, sz: 'ok', terminal: 'ok', degreesMatchSchedule: true, negativeControl: 'ok',
}));

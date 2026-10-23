// Honest-prover witness for the measurement prototype (adapted from ../ref.mjs).
// B lines: 'proj' = homogeneous projective walk with Fp2-scaled lines (no slope witness),
//          'aff'  = affine walk with witnessed slopes.
// gamma/delta lines: affine, lambda baked (F2); T recomputed on-chain.
// Transcript (as the prototype script computes it; enc = 32-byte LE, canonical):
//   T0 = SHA256(DOMAIN32 || enc(n0) enc(n1) enc(Ax) enc(Ay) enc(Bx0) enc(Bx1) enc(By0) enc(By1) enc(Cx) enc(Cy) || enc(u0..u5) || STATES)
//   g  = LE(SHA256(T0 || 01)) mod p ;  z = LE(SHA256(T0 || 02 || QBLOB)) mod p
//   STATES = enc(G_0[0..5]) || ... || enc(G_35[0..5]);  QBLOB = enc(q_161) || enc(q_159) || ... || enc(q_1)
import {pathToFileURL} from 'node:url';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {digits, EVENTS, LAST, segDeg, qOdd, bestSegmentation} from './schedule.mjs';

import {bn254} from '@noble/curves/bn254.js';
import {psiFrobenius} from '@noble/curves/abstract/tower.js';
import * as RW from '../../../../chunked/bn254/densless-recovered/root-witness.mjs';
export const fx = JSON.parse(readFileSync(new URL('../../../../chunked/bn254/densless-recovered/public-fixtures.json', import.meta.url)));
const {Fp, Fp2, Fp6, Fp12} = bn254.fields;
export const P = Fp.ORDER;
const mod = (x) => ((x % P) + P) % P;
export {digits, EVENTS, LAST};
export const DOMAIN = createHash('sha256').update('hybrid-direct/v1 VKDIGEST placeholder').digest();

// Fp2 as [a0, a1] bigint pairs (u^2 = -1)
export const f2 = {
  mul: ([a, b], [c, d]) => [mod(a * c - b * d), mod(a * d + b * c)],
  sqr: (a) => f2.mul(a, a), add: ([a, b], [c, d]) => [mod(a + c), mod(b + d)], sub: ([a, b], [c, d]) => [mod(a - c), mod(b - d)],
  sc: ([a, b], k) => [mod(a * k), mod(b * k)], neg: ([a, b]) => [mod(-a), mod(-b)],
  inv: (a) => { const t = Fp2.inv(Fp2.fromBigTuple(a)); return [t.c0, t.c1]; },
  of: (x) => [x.c0, x.c1], eq: (a, b) => mod(a[0] - b[0]) === 0n && mod(a[1] - b[1]) === 0n,
};
export const BTW = f2.of(Fp2.div(Fp2.fromBigTuple([3n, 0n]), Fp2.NONRESIDUE)); // twist b' = 3/(9+u)
const {psi} = psiFrobenius(Fp, Fp2, Fp2.NONRESIDUE);
const PSI_X = f2.of(Fp2.pow(Fp2.NONRESIDUE, (P - 1n) / 3n)), PSI_Y = f2.of(Fp2.pow(Fp2.NONRESIDUE, (P - 1n) / 2n));
const PSI2_X = f2.of(Fp2.pow(Fp2.NONRESIDUE, (P * P - 1n) / 3n));
export const PSI = {PSI_X, PSI_Y, PSI2_X};
export const psiA = ([x, y]) => [f2.mul([x[0], mod(-x[1])], PSI_X), f2.mul([y[0], mod(-y[1])], PSI_Y)];
export const psi2A = ([x, y]) => [f2.mul(x, PSI2_X), f2.neg(y)];

// projective formulas exactly as the script computes them (values mod p)
export const projDbl = ([X, Y, Z]) => {
  const XX = f2.sqr(X), YY = f2.sqr(Y), ZZ = f2.sqr(Z), E = f2.mul(f2.sc(BTW, 3n), ZZ);
  const XY = f2.mul(X, Y), YZ = f2.mul(Y, Z);
  const X3 = f2.sc(f2.mul(XY, f2.sub(YY, f2.sc(E, 3n))), 2n);
  const Y3 = f2.sub(f2.sqr(f2.add(YY, f2.sc(E, 3n))), f2.sc(f2.sqr(E), 12n));
  const Z3 = f2.sc(f2.mul(YY, YZ), 8n);
  return {T: [X3, Y3, Z3], cy: f2.sc(YZ, 2n), cl: f2.sc(XX, 3n), cb: f2.sub(YY, E)};
};
export const projAdd = ([X, Y, Z], [xq, yq]) => {
  const th = f2.sub(Y, f2.mul(yq, Z)), la = f2.sub(X, f2.mul(xq, Z));
  const C = f2.sqr(th), D = f2.sqr(la), E = f2.mul(la, D), F = f2.mul(Z, C), G = f2.mul(X, D);
  const H = f2.sub(f2.add(E, F), f2.sc(G, 2n));
  const X3 = f2.mul(la, H), Y3 = f2.sub(f2.mul(th, f2.sub(G, H)), f2.mul(Y, E)), Z3 = f2.mul(Z, E);
  // line through T and Q scaled by la: c_y = la, c_lambda = th, c_beta = th*xq - la*yq
  return {T: [X3, Y3, Z3], cy: la, cl: th, cb: f2.sub(f2.mul(th, xq), f2.mul(la, yq))};
};
const affDbl = ([x, y]) => { const lam = f2.mul(f2.sc(f2.sqr(x), 3n), f2.inv(f2.sc(y, 2n))); const x3 = f2.sub(f2.sqr(lam), f2.sc(x, 2n)); const beta = f2.sub(f2.mul(lam, x), y); return {T: [x3, f2.sub(beta, f2.mul(lam, x3))], lam, beta}; };
const affAdd = ([x, y], [xq, yq]) => { const lam = f2.mul(f2.sub(yq, y), f2.inv(f2.sub(xq, x))); const x3 = f2.sub(f2.sub(f2.sqr(lam), x), xq); const beta = f2.sub(f2.mul(lam, x), y); return {T: [x3, f2.sub(beta, f2.mul(lam, x3))], lam, beta}; };

const flat = (x) => [x.c0.c0.c0, x.c0.c0.c1, x.c0.c1.c0, x.c0.c1.c1, x.c0.c2.c0, x.c0.c2.c1, x.c1.c0.c0, x.c1.c0.c1, x.c1.c1.c0, x.c1.c1.c1, x.c1.c2.c0, x.c1.c2.c1];
const f6 = (t) => Fp6.create({c0: Fp2.fromBigTuple([t[0], t[1]]), c1: Fp2.fromBigTuple([t[2], t[3]]), c2: Fp2.fromBigTuple([t[4], t[5]])});
const mk12 = (lo, hi) => Fp12.create({c0: f6(lo), c1: f6(hi)});
const f6flat = (a) => [a.c0.c0, a.c0.c1, a.c1.c0, a.c1.c1, a.c2.c0, a.c2.c1];
const polyOf = (c) => { const out = Array(12).fill(0n); for (const [i, d] of [0, 2, 4, 1, 3, 5].entries()) { out[d] = mod(c[2 * i] - 9n * c[2 * i + 1]); out[d + 6] = c[2 * i + 1]; } return out; };
const pmul = (a, b) => { const o = Array(a.length + b.length - 1).fill(0n); for (let i = 0; i < a.length; i++) if (a[i]) for (let j = 0; j < b.length; j++) o[i + j] += a[i] * b[j]; return o.map(mod); };
const trim = (a) => { const b = a.slice(); while (b.length > 1 && b.at(-1) === 0n) b.pop(); return b; };
const tau = (g) => mk12([1n, 0n, 0n, 0n, 0n, 0n], g);
const neg6 = (g) => g.map((x) => mod(-x));
export const le32 = (x) => Buffer.from(mod(x).toString(16).padStart(64, '0'), 'hex').reverse();
const leToBig = (b) => BigInt('0x' + (Buffer.from(b).reverse().toString('hex') || '0'));
const H = (...bufs) => createHash('sha256').update(Buffer.concat(bufs)).digest();

export function makeWitness(fi = 0, bMode = 'proj') {
  const {vk} = fx; const {proof, publicInputs} = fx.fixtures[fi];
  const g1 = (p) => bn254.G1.Point.fromAffine({x: BigInt(p.x), y: BigInt(p.y)});
  const g2 = (p) => bn254.G2.Point.fromAffine({x: {c0: BigInt(p.x.c0), c1: BigInt(p.x.c1)}, y: {c0: BigInt(p.y.c0), c1: BigInt(p.y.c1)}});
  const A = g1(proof.a), C = g1(proof.c), B = g2(proof.b);
  let vkx = g1(vk.ic[0]); publicInputs.forEach((n, i) => { if (BigInt(n)) vkx = vkx.add(g1(vk.ic[i + 1]).multiply(BigInt(n))); });
  const aff2 = (Q) => { const a = Q.toAffine(); return [f2.of(a.x), f2.of(a.y)]; };
  const Ps = [A.negate().toAffine(), vkx.toAffine(), C.toAffine()];
  const Qs = [aff2(B), aff2(g2(vk.gamma)), aff2(g2(vk.delta))];
  // events: per event a list of {pair, kind:'dbl'|'add'|'frob', line:{cy,cl,cb}, lam?}
  const events = Array.from({length: EVENTS}, () => []);
  const run = [[Qs[0][0], Qs[0][1], [1n, 0n]], Qs[1], Qs[2]];
  const slopes = []; // affine B slopes in order (aff mode)
  // bMode: 'proj' | 'aff' | K (number): B steps of events < K affine (witnessed slopes), the rest
  // projective; the two Frobenius additions are affine only when K >= EVENTS.
  let curE = 0;
  const isAff = (kind) => bMode === 'aff' || (typeof bMode === 'number' && (kind === 'frob' ? bMode >= EVENTS : curE < bMode));
  const step = (j, kind, Q) => {
    if (j === 0 && !isAff(kind)) {
      const r = kind === 'dbl' ? projDbl(run[0]) : projAdd(run[0], Q);
      run[0] = r.T; return {pair: j, kind, cy: r.cy, cl: r.cl, cb: r.cb};
    }
    const T = j === 0 ? [run[0][0], run[0][1]] : run[j];
    const r = kind === 'dbl' ? affDbl(T) : affAdd(T, Q);
    if (j === 0) { run[0] = [...r.T, [1n, 0n]]; slopes.push(r.lam); } else run[j] = r.T;
    return {pair: j, kind, cy: [1n, 0n], cl: r.lam, cb: r.beta, lam: r.lam, xq: Q?.[0]};
  };
  for (let e = 0; e < EVENTS; e++) {
    curE = e;
    for (let j = 0; j < 3; j++) events[e].push(step(j, 'dbl'));
    if (digits[e]) for (let j = 0; j < 3; j++) { const q = Qs[j]; events[e].push(step(j, 'add', digits[e] < 0 ? [q[0], f2.neg(q[1])] : q)); }
  }
  const frobQ = Qs.map((q) => { const q1 = psiA(q), q2 = psi2A(q); return [q1, [q2[0], f2.neg(q2[1])]]; });
  for (let j = 0; j < 3; j++) for (const q of frobQ[j]) events[LAST].push(step(j, 'frob', q));
  // B endpoint: T_B == -psi^3(B)
  { const q3 = psiA(psi2A(Qs[0])); const [X, Y, Z] = run[0];
    assert.ok(f2.eq(X, f2.mul(q3[0], Z)) && f2.eq(Y, f2.neg(f2.mul(q3[1], Z))), 'B endpoint'); }
  const lineFlat = (L) => { const {x, y} = Ps[L.pair]; return [mod(y * L.cy[0]), mod(y * L.cy[1]), 0n, 0n, 0n, 0n, mod(-x * L.cl[0]), mod(-x * L.cl[1]), L.cb[0], L.cb[1], 0n, 0n]; };
  const lineFp12 = (L) => { const c = lineFlat(L); return mk12(c.slice(0, 6), c.slice(6)); };
  let raw = Fp12.ONE;
  for (let e = 0; e < EVENTS; e++) { raw = Fp12.sqr(raw); for (const L of events[e]) raw = Fp12.mul(raw, lineFp12(L)); }
  const Kfull = bn254.pairing(g1(vk.alpha), g2(vk.beta), false);
  const fAll = Fp12.mul(raw, Kfull);
  assert.ok(Fp12.eql(Fp12.finalExponentiate(fAll), Fp12.ONE), 'pairing product');
  const kappa = f6flat(Fp6.mul(Kfull.c1, Fp6.inv(Kfull.c0)));
  const wit = RW.residueWitness(fAll);
  assert.ok(Fp6.eql(wit.w.c1, Fp6.ZERO));
  const u = f6flat(Fp6.mul(wit.c.c1, Fp6.inv(wit.c.c0)));
  const best = bestSegmentation(32); const segs = best.segs; const ends = new Set(segs.map(([, b]) => b));
  const cFold = (d) => tau(d > 0 ? neg6(u) : u);
  let F = tau(neg6(u)); const states = [];
  for (let e = 0; e < EVENTS; e++) {
    F = Fp12.sqr(F);
    for (const L of events[e]) F = Fp12.mul(F, lineFp12(L));
    if (digits[e]) F = Fp12.mul(F, cFold(digits[e]));
    if (e === LAST) F = Fp12.mul(F, tau(kappa));
    if (ends.has(e)) states.push(f6flat(Fp6.mul(F.c1, Fp6.inv(F.c0))));
  }
  { const cT = tau(u), GJ = tau(states.at(-1));
    const r = Fp12.mul(Fp12.mul(GJ, Fp12.frobeniusMap(cT, 2)), Fp12.inv(Fp12.mul(Fp12.frobeniusMap(cT, 1), Fp12.frobeniusMap(cT, 3))));
    assert.ok(Fp6.eql(r.c1, Fp6.ZERO), 'terminal verdict'); }
  // polynomials and odd quotients
  const divM = (num) => { const r = num.slice(); const q = Array(Math.max(1, r.length - 12)).fill(0n);
    for (let i = r.length - 1; i >= 12; i--) { const v = r[i]; if (!v) continue; q[i - 12] = v; r[i] = 0n; r[i - 6] = mod(r[i - 6] + 18n * v); r[i - 12] = mod(r[i - 12] - 82n * v); }
    return {q, rem: r.slice(0, 12)}; };
  const flip = (a) => a.map((c, i) => (i % 2 ? mod(-c) : c));
  const Qj = []; let prev = neg6(u);
  segs.forEach(([a, b], j) => {
    let Pp = polyOf(flat(tau(prev)));
    for (let e = a; e <= b; e++) {
      Pp = pmul(Pp, Pp);
      for (const L of events[e]) Pp = pmul(Pp, polyOf(lineFlat(L)));
      if (digits[e]) Pp = pmul(Pp, polyOf(flat(cFold(digits[e]))));
      if (e === LAST) Pp = pmul(Pp, polyOf(flat(tau(kappa))));
    }
    const R = pmul(Pp, polyOf(flat(tau(neg6(states[j])))));
    assert.ok(trim(R).length - 1 <= segDeg(a, b));
    const {q, rem} = divM(R.map((c, i) => mod(c - flip(R)[i])));
    assert.ok(rem.every((x) => x === 0n), 'odd part vanishes');
    Qj.push(q); prev = states[j];
  });
  const aA = A.toAffine(), aB = B.toAffine(), aC = C.toAffine();
  const proofVals = {Ax: aA.x, Ay: aA.y, Bx0: aB.x.c0, Bx1: aB.x.c1, By0: aB.y.c0, By1: aB.y.c1, Cx: aC.x, Cy: aC.y};
  const n = publicInputs.map(BigInt);
  const STATES = Buffer.concat(states.flat().map(le32));
  const T0 = H(DOMAIN, ...[n[0], n[1], ...Object.values(proofVals), ...u].map(le32), STATES);
  const g = mod(leToBig(H(T0, Buffer.from([1]))));
  const nQ = qOdd(best.D);
  const Qagg = Array(2 * nQ + 1).fill(0n); let gp = 1n;
  for (const q of Qj) { trim(q).forEach((c, i) => { assert.ok(i < Qagg.length || c === 0n); if (i < Qagg.length) Qagg[i] = mod(Qagg[i] + gp * c); }); gp = mod(gp * g); }
  const Qodd = Array.from({length: nQ}, (_, i) => Qagg[2 * i + 1]);
  assert.ok(Qagg.every((c, i) => i % 2 === 1 || c === 0n));
  const QBLOB = Buffer.concat(Qodd.slice().reverse().map(le32));
  const z = mod(leToBig(H(T0, Buffer.from([2]), QBLOB)));
  const zeroLimbs = [...states.flat(), ...Qodd].filter((x) => x === 0n).length;
  return {fi, bMode, proofVals, n, vkx: Ps[1], u, states, STATES, QBLOB, Qodd, g, z, segs, kappa, slopes, events,
    gammaQ: Qs[1], deltaQ: Qs[2], frobQ, nQ, zeroLimbs, maxDeg: best.D};
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  for (const mode of ['proj', 'aff']) {
    const w = makeWitness(Number(process.argv[2] ?? 0), mode);
    console.log(mode, {segments: w.segs.length, nQ: w.nQ, maxDeg: w.maxDeg, zeroLimbs: w.zeroLimbs, statesBytes: w.STATES.length, qBytes: w.QBLOB.length, slopes: w.slopes.length,
      q161: w.Qodd.at(-1).toString(16).slice(0, 8)});
  }
}

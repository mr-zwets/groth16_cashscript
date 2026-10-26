// BLS12-381 SI-GLS protocol for a multi-input bch-2026 verifier (design prototype):
// witness layout, transcript, honest prover, degree bookkeeping, and a value-level reference verifier
// that evaluates the identities input by input (partial batched sums R_i, B-point handoffs).
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {bls12_381} from '@noble/curves/bls12-381.js';
import {p, r, mod, F2, F12, f2, AX, EVENTS, NEV, LAMBDA, N6R, PI, GLS_BITS, GLS_OFFSET, PI_SUM_OFFSET, glsDecompose,
  ETA, B_TWIST, frob1Monic, linePoly, fromPoly, monicRep, millerClass, pmul, psub, pneg, psubst, peval, pdivM, M, psiAff,
  projDbl, projAdd, affDbl, affAdd, Phi} from './math.mjs';

const G1 = bls12_381.G1.Point, G2 = bls12_381.G2.Point;
// ---------------- VK (the bench BLS12-381 fixture VK: alpha=3, beta=5, gamma=7, delta=11, IC=[2,4,6]) ----------------
export const VK = {alpha: G1.BASE.multiply(3n), beta: G2.BASE.multiply(5n), gamma: G2.BASE.multiply(7n), delta: G2.BASE.multiply(11n), ic: [2n, 4n, 6n].map((k) => G1.BASE.multiply(k))};
export function mintProof(n0, n1, cS = 13n, bS = 1n) { // A = (ab + vx g + c d) / b (scalars), B = b G2, C = c G1
  const vx = mod(2n + n0 * 4n + n1 * 6n, r); const As = mod((3n * 5n + vx * 7n + cS * 11n) * modInv(bS, r), r);
  return {A: G1.BASE.multiply(As), B: G2.BASE.multiply(bS), C: G1.BASE.multiply(cS), ns: [n0, n1]};
}
function modInv(a, m) { let [x, y, s0, s1] = [mod(a, m), m, 1n, 0n]; while (y) { const q = x / y; [x, y, s0, s1] = [y, x - q * y, s1, s0 - q * s1]; } assert.equal(x, 1n); return mod(s0, m); }

// ---------------- constants derived from the VK (all classes via our own Miller formulas) ----------------
const rawMiller = (P, Q) => millerClass(P.toAffine(), Q.toAffine()).f; // f_{|x|,Q}(P), FE(.) = e(P,Q)^-1
export const VKC = (() => {
  const mIC = VK.ic.map((P) => rawMiller(P, VK.gamma));
  const mConst = F12.mul(rawMiller(VK.alpha, VK.beta), mIC[0]);
  const R = [1, 2].map((k) => [monicRep(mIC[k]), monicRep(F12.frobeniusMap(mIC[k], 1))]);
  R.forEach((Rk, k) => [0, 1].forEach((i) => { const sh = psubst(Rk[i], ETA); assert.equal(sh[6], 1n); }));
  let corr = F12.ONE; for (const k of [1, 2]) for (let i = 0; i < 4; i++) corr = F12.mul(corr, F12.frobeniusMap(mIC[k], i));
  corr = F12.conjugate(F12.pow(corr, GLS_OFFSET));
  const Rconst = monicRep(F12.mul(mConst, corr));
  // delta walk: slopes for 63 doublings + 5 additions (affine), state recursion as in the BN SI-GLS
  const d = VK.delta.toAffine(); let T = VK.delta; const lams = [];
  const slopeDbl = (a) => F2.div(F2.mul(f2(3n, 0n), F2.sqr(a.x)), F2.add(a.y, a.y));
  const slopeAdd = (a, q) => F2.div(F2.sub(q.y, a.y), F2.sub(q.x, a.x));
  for (const b of EVENTS) { lams.push(slopeDbl(T.toAffine())); T = T.double(); if (b) { lams.push(slopeAdd(T.toAffine(), d)); T = T.add(VK.delta); } }
  assert.equal(lams.length, 68);
  return {mIC, mConst, R, Rconst, deltaAff: d, lams};
})();
export const glsFactorPoly = (k, i) => { let f = VKC.R[k][i % 2]; if (i >= 2) f = psubst(f, ETA); return f; };

// ---------------- schedule and chunking ----------------
// GLS positions g = 0..63 (g = 0: initial factor; g >= 1: after event g). Events e = 1..63.
// chunk 0 = event {1} (start = S_c(-X) * G_0), chunk j >= 1 = events {2j, 2j+1}; states after chunks 0..30;
// chunk 31 (events 62, 63) is multiplied by Rconst and compared with W = Frob(S_c) (terminal merged).
export const NCHUNK = 32, NSTATES = 31;
export const chunkEvents = (j) => (j === 0 ? [1] : [2 * j, 2 * j + 1]);
export const isAdd = (e) => EVENTS[e - 1] === 1;
// line degrees: projective B line 9, affine B line 8, delta line 8, c factor 6, GLS factor 6 per set bit
export const eventDeg = (e, bits, affB) => (affB ? 8 : 9) + 8 + (isAdd(e) ? (affB ? 8 : 9) + 8 + 6 : 0) + 6 * bits;
export function chunkDegP(j, bitsOf, affOf) {
  let d = j === 0 ? 6 + 6 * bitsOf(0) : 6;
  for (const e of chunkEvents(j)) d = 2 * d + eventDeg(e, bitsOf(e), affOf(e));
  if (j === NCHUNK - 1) d += 6; // Rconst
  return d;
}
const termWDeg = 12; // W = Frob(S_c) has degree <= 11 (<= 12 counted)
export const nqOf = (bitsOf, affOf) => { let mx = 0; for (let j = 0; j < NCHUNK; j++) { const dD = chunkDegP(j, bitsOf, affOf) + (j === NCHUNK - 1 ? termWDeg : 6); const dq = (dD % 2 ? dD : dD - 1) - 12; mx = Math.max(mx, (dq + 1) / 2); } return mx; };
export const NQ_MAX_FOR = (affOf) => nqOf(() => 8, affOf);

// ---------------- encodings ----------------
export const W48 = 48;
export const le = (x, n = W48) => { assert.ok(x >= 0n && x < 1n << BigInt(8 * n)); const b = Buffer.alloc(n); let v = x; for (let i = 0; i < n; i++) { b[i] = Number(v & 255n); v >>= 8n; } return b; };
export const sha = (...parts) => createHash('sha256').update(Buffer.concat(parts)).digest();
const rdle = (b) => { let v = 0n; for (let i = b.length - 1; i >= 0; i--) v = v * 256n + BigInt(b[i]); return v; };
export const toFp = (h) => rdle(h) % p;

// ---------------- the B walk (mixed: affine witnessed-slope events first, projective after; aff(e) decides) ----------------
// returns per-event B line polynomials (at P = -A) and the slope witness for affine events, and the endpoint
export function bWalk(st, affOf) {
  const {xA, yA, xB, yB} = st; const yP = mod(-yA);
  let Ta = [xB, yB], Tp = null; const lines = {}, slopes = [];
  for (let e = 1; e <= NEV; e++) {
    const L = [];
    if (affOf(e)) {
      assert.ok(Tp === null, 'affine after projective is not supported');
      const lam = F2.div(F2.mul(f2(3n, 0n), F2.sqr(Ta[0])), F2.add(Ta[1], Ta[1])); slopes.push(lam);
      let o = affDbl(Ta, lam); L.push(linePoly(xA, yP, ...o.line)); Ta = o.T;
      if (isAdd(e)) { assert.ok(!F2.eql(Ta[0], xB)); const la = F2.div(F2.sub(yB, Ta[1]), F2.sub(xB, Ta[0])); slopes.push(la); o = affAdd(Ta, [xB, yB], la); L.push(linePoly(xA, yP, ...o.line)); Ta = o.T; }
    } else {
      if (Tp === null) Tp = [Ta[0], Ta[1], F2.ONE];
      let o = projDbl(Tp); L.push(linePoly(xA, yP, ...o.line)); Tp = o.T;
      if (isAdd(e)) { o = projAdd(Tp, [xB, yB]); L.push(linePoly(xA, yP, ...o.line)); Tp = o.T; }
    }
    lines[e] = L;
  }
  // endpoint: T = [|x|]B must equal -psi(B) (psi(B) = [x]B iff B in G2)
  const [px, py] = psiAff(xB, yB);
  let endpoint;
  if (Tp) { const [X, Y, Z] = Tp; endpoint = !F2.is0(Z) && F2.eql(X, F2.mul(px, Z)) && F2.eql(Y, F2.mul(F2.neg(py), Z)); }
  else endpoint = F2.eql(Ta[0], px) && F2.eql(Ta[1], F2.neg(py));
  return {lines, slopes, endpoint};
}
// delta lines at C (affine, baked slopes; c_j = lam_j x_j - y_j)
export function deltaLines(xC, yC) {
  const d = VKC.deltaAff; let T = [d.x, d.y], j = 0; const lines = {};
  for (let e = 1; e <= NEV; e++) {
    const L = []; const lam = VKC.lams[j++]; let o = affDbl(T, lam); L.push(linePoly(xC, yC, ...o.line)); T = o.T;
    if (isAdd(e)) { const la = VKC.lams[j++]; o = affAdd(T, [d.x, d.y], la); L.push(linePoly(xC, yC, ...o.line)); T = o.T; }
    lines[e] = L;
  }
  return lines;
}
const tbl = (k, n) => { let poly = [1n]; for (let i = 0; i < 4; i++) if ((n >> i) & 1) poly = pmul(poly, glsFactorPoly(k, i)); return poly; };

// ---------------- prover ----------------
export function prove({A, B, C, ns}, {affOf = () => true} = {}) {
  A.assertValidity(); B.assertValidity(); C.assertValidity();
  const es = ns.map((n) => glsDecompose(mod(n, r)));
  const us = es.map((e) => e.map((v) => { const u = v + GLS_OFFSET; assert.ok(u >= 0n && u < 1n << 64n); return u; }));
  const N = us.map((u) => Array.from({length: GLS_BITS}, (_, g) => u.reduce((s, v, i) => s | (Number((v >> BigInt(GLS_BITS - 1 - g)) & 1n) << i), 0)));
  const Aa = A.toAffine(), Ba = B.toAffine(), Ca = C.toAffine();
  const st = {xA: Aa.x, yA: Aa.y, xB: Ba.x, yB: Ba.y, xC: Ca.x, yC: Ca.y};
  const bw = bWalk(st, affOf); assert.ok(bw.endpoint, 'B endpoint');
  const dl = deltaLines(Ca.x, Ca.y);
  const G = (g) => pmul(tbl(0, N[0][g]), tbl(1, N[1][g]));
  const evFactors = (e) => [...bw.lines[e], ...dl[e], G(e)];
  // raw product f' (no c): FE must be 1
  let raw = fromPoly(G(0));
  for (let e = 1; e <= NEV; e++) { raw = F12.sqr(raw); for (const f of evFactors(e)) raw = F12.mul(raw, fromPoly(f)); }
  raw = F12.mul(raw, fromPoly(VKC.Rconst));
  assert.ok(F12.eql(F12.finalExponentiate(raw), F12.ONE), 'Groth16 equation (FE(f\') = 1)');
  const u = F12.mul(F12.conjugate(raw), F12.inv(raw)), v = F12.pow(u, modInv(LAMBDA, N6R)), c = F12.add(F12.ONE, F12.conjugate(v));
  const Sc = monicRep(c); const ScNeg = pneg(Sc);
  // states and identities
  const states = []; const ids = [];
  let Fcl = F12.mul(fromPoly(ScNeg), fromPoly(G(0)));
  let Pstart = pmul(ScNeg, G(0));
  for (let j = 0; j < NCHUNK; j++) {
    let P = Pstart;
    for (const e of chunkEvents(j)) {
      Fcl = F12.sqr(Fcl); P = pmul(P, P);
      for (const f of evFactors(e)) { Fcl = F12.mul(Fcl, fromPoly(f)); P = pmul(P, f); }
      if (isAdd(e)) { Fcl = F12.mul(Fcl, fromPoly(ScNeg)); P = pmul(P, ScNeg); }
    }
    if (j < NCHUNK - 1) { const S = monicRep(Fcl); states.push(S); ids.push({P, W: S}); Pstart = S; }
    else { P = pmul(P, VKC.Rconst); ids.push({P, W: frob1Monic(Sc)}); }
  }
  for (const id of ids) {
    const Nn = pmul(id.P, pneg(id.W)); const D = psub(Nn, pneg(Nn)); const {q, r: rem} = pdivM(D);
    assert.ok(rem.every((x) => x === 0n), 'identity divisible by M'); assert.ok(q.every((x, i) => i % 2 === 1 || x === 0n), 'odd quotient');
    id.Q = q; id.degP = id.P.length - 1;
  }
  return {st, ns, es, N, Sc, states, slopes: bw.slopes, ids, c};
}

// ---------------- transcript and quotient ----------------
export const TAG = Buffer.from('BLS-SIGLS-NATIVE/1');
// commit region (the exact bytes hashed into h0): statement, nibbles, s^c, states, B slopes (affine events)
export function commitBytes(w) {
  const {st, ns, N, Sc, states, slopes} = w;
  return Buffer.concat([
    ...[st.xA, st.yA, st.xB.c0, st.xB.c1, st.yB.c0, st.yB.c1, st.xC, st.yC].map((x) => le(x)), ...ns.map((n) => le(n, 32)),
    Buffer.from(N[0]), Buffer.from(N[1]), ...Sc.slice(0, 6).map((x) => le(x)), ...states.flatMap((s) => s.slice(0, 6).map((x) => le(x))),
    ...slopes.flatMap((l) => [le(l.c0), le(l.c1)])]);
}
// multi-input commit regions: input 0 (head) holds the statement, nibbles and s^c; every input holds the states that
// end its chunks (not the terminal one) and the B slopes of its affine events. owners[i] = [j0, j1) chunk range of input i.
export const stmtBytes = (w) => { const {st, ns, N, Sc} = w; return Buffer.concat([...[st.xA, st.yA, st.xB.c0, st.xB.c1, st.yB.c0, st.yB.c1, st.xC, st.yC].map((x) => le(x)), ...ns.map((n) => le(n, 32)), Buffer.from(N[0]), Buffer.from(N[1]), ...Sc.slice(0, 6).map((x) => le(x))]); };
export function regionsFor(w, owners, affOf = () => true) {
  // slope index at each event
  const slopeStart = {}; let si = 0; for (let e = 1; e <= NEV; e++) { slopeStart[e] = si; if (affOf(e)) si += isAdd(e) ? 2 : 1; }
  return owners.map(([j0, j1], i) => {
    const parts = i === 0 ? [stmtBytes(w)] : [];
    for (let j = j0; j < Math.min(j1, NCHUNK - 1); j++) parts.push(...w.states[j].slice(0, 6).map((x) => le(x)));
    for (let j = j0; j < j1; j++) for (const e of chunkEvents(j)) if (affOf(e)) { const n = isAdd(e) ? 2 : 1; for (let q = 0; q < n; q++) { const l = w.slopes[slopeStart[e] + q]; parts.push(le(l.c0), le(l.c1)); } }
    return Buffer.concat(parts);
  });
}
export const h0Of = (regions) => sha(TAG, ...regions.map((g) => sha(g))); // fixed-arity tree of fixed-size regions
export function finish(w, affOf = () => true, owners = null) {
  const WS = commitBytes(w); const h0 = owners ? h0Of(regionsFor(w, owners, affOf)) : sha(TAG, WS), rhoRaw = sha(h0, Buffer.from('rho')); const rho = toFp(rhoRaw);
  const bitsOf = (g) => [0, 1].reduce((s, k) => s + [0, 1, 2, 3].filter((i) => (w.N[k][g] >> i) & 1).length, 0);
  const nq = nqOf(bitsOf, affOf);
  const Qagg = Array(2 * nq).fill(0n);
  w.ids.forEach((id, k) => { const wgt = mod(rho ** BigInt(NCHUNK - 1 - k)); id.Q.forEach((x, i) => { if (x) { assert.ok(i < 2 * nq, 'Q exceeds structural bound'); Qagg[i] = mod(Qagg[i] + wgt * x); } }); });
  const qOdd = Qagg.filter((_, i) => i % 2 === 1); while (qOdd.length > 1 && qOdd.at(-1) === 0n) qOdd.pop();
  const WQ = Buffer.concat(qOdd.slice().reverse().map((x) => le(x)));
  const z = toFp(sha(h0, rhoRaw, WQ)); assert.notEqual(z, 0n);
  return {WS, WQ, nq: qOdd.length, nqBound: nq, rho, z, h0, rhoRaw, regions: owners ? regionsFor(w, owners, affOf) : null};
}

// ---------------- value-level reference verifier, split by input ranges of chunks ----------------
// ranges: array of [j0, j1) chunk ranges, one per Miller input. Returns the per-input partial sums and the final check.
export function verifySplit(w, fin, ranges, affOf = () => true) {
  const {st, N, Sc, states} = w; const {rho, z} = fin; const zm = mod(-z);
  const ScNeg = pneg(Sc);
  const bw = bWalk(st, affOf); if (!bw.endpoint) return {ok: false, why: 'endpoint'};
  const dl = deltaLines(st.xC, st.yC);
  const G = (g) => pmul(tbl(0, N[0][g]), tbl(1, N[1][g]));
  const parts = [];
  for (const [j0, j1] of ranges) {
    let R = 0n;
    for (let j = j0; j < j1; j++) {
      const start = j === 0 ? pmul(ScNeg, G(0)) : states[j - 1];
      let Fp_ = peval(start, z), Fm_ = peval(start, zm);
      for (const e of chunkEvents(j)) {
        Fp_ = mod(Fp_ * Fp_); Fm_ = mod(Fm_ * Fm_);
        for (const f of [...bw.lines[e], ...dl[e], G(e)]) { Fp_ = mod(Fp_ * peval(f, z)); Fm_ = mod(Fm_ * peval(f, zm)); }
        if (isAdd(e)) { Fp_ = mod(Fp_ * peval(ScNeg, z)); Fm_ = mod(Fm_ * peval(ScNeg, zm)); }
      }
      let Wn; if (j < NCHUNK - 1) Wn = states[j]; else { Fp_ = mod(Fp_ * peval(VKC.Rconst, z)); Fm_ = mod(Fm_ * peval(VKC.Rconst, zm)); Wn = frob1Monic(Sc); }
      R = mod(R * rho + Fp_ * peval(Wn, zm) - Fm_ * peval(Wn, z));
    }
    parts.push({range: [j0, j1], R});
  }
  // head: combine R = sum_i rho^(NCHUNK - j1_i) R_i, Horner over Q, binding
  let R = 0n; for (const {range: [, j1], R: Ri} of parts) R = mod(R + Ri * rho ** BigInt(NCHUNK - j1));
  const qw = []; for (let i = 0; i < fin.WQ.length; i += 48) qw.push(rdle(fin.WQ.subarray(i, i + 48)));
  let acc = 0n; const z2 = mod(z * z); for (const q of qw) acc = mod(acc * z2 + q);
  const okFinal = R === mod(z * acc * peval(M, z));
  const binding = [0, 1].every((k) => { let a = 0n; for (let g = 0; g < GLS_BITS; g++) { a = 2n * a; for (let i = 0; i < 4; i++) if ((N[k][g] >> i) & 1) a += PI[i]; } return (a - PI_SUM_OFFSET - w.ns[k]) % r === 0n; });
  return {ok: okFinal && binding, okFinal, binding, parts};
}

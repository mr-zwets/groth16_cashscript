// BLS12-381 SI-GLS protocol mirror (design prototype): VK constants, the event schedule as polynomials, the honest
// prover (states, residue root, quotient), the adversarial degree bound for a chunking, and a value-level reference
// verifier. The multi-input split (split.mjs) runs exactly this computation, partitioned by input.
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {bls12_381} from '@noble/curves/bls12-381.js';
import {p, r, mod, F2, F12, f2, G1, G2, X_ABS, NE, BITS, ADD_EVENTS, LAMBDA, N6R, minv, glsDigits, GLS_BITS, XPOW,
  B_TWIST, projDbl, projAdd, psi, linePoly, ETA, frob1Monic, fromPoly, toPoly, monicRep, sameClass, pmul, psub, pneg, psubst, peval, pdivM, M, deg} from './blsmath.mjs';

// ---------------- VK (the bench's synthetic BLS12-381 key: alpha=3, beta=5, gamma=7, delta=11, IC=[2,4,6]) ----------------
const R_ = r; const modr = (x) => mod(x, R_);
export const VKS = {alpha: 3n, beta: 5n, gamma: 7n, delta: 11n, ic: [2n, 4n, 6n]};
export const VK = {alpha: G1.BASE.multiply(VKS.alpha), beta: G2.BASE.multiply(VKS.beta), gamma: G2.BASE.multiply(VKS.gamma), delta: G2.BASE.multiply(VKS.delta), ic: VKS.ic.map((k) => G1.BASE.multiply(k))};
// a valid proof for public inputs ns with B = b G2, C = c G1 (A solved in the exponent; the fixture key publishes its setup)
export const mintProof = (ns, b = 1n, c = 13n) => {
  const vx = modr(VKS.ic[0] + ns[0] * VKS.ic[1] + ns[1] * VKS.ic[2]);
  const a = modr((VKS.alpha * VKS.beta + vx * VKS.gamma + c * VKS.delta) * minv(b, R_));
  return {A: G1.BASE.multiply(a), B: G2.BASE.multiply(b), C: G1.BASE.multiply(c), ns};
};
export const randProof = (seed) => { const h = (t) => BigInt('0x' + createHash('sha256').update(`bls-native-d2/${seed}/${t}`).digest('hex'));
  return mintProof([modr(h('n0')), modr(h('n1'))], modr(h('b')) || 1n, modr(h('c')) || 1n); };

// f_{|x|,Q}(P) (not conjugated): noble's millerLoop conjugates for x < 0
const millerAbs = (P, Q) => F12.conjugate(bls12_381.pairing(P, Q, false));
export const VKC = (() => {
  // delta lines (affine, normalized c2 = 1): (c0, c1, c2) = (lam x_T - y_T, -lam, 1); slopes lam_j, j = 0..67
  const d = VK.delta.toAffine(); let T = VK.delta; const lams = [];
  const slopeDbl = (Ta) => F2.div(F2.mul(f2(3n, 0n), F2.sqr(Ta.x)), F2.add(Ta.y, Ta.y));
  const slopeAdd = (Ta, Qa) => { assert.ok(!F2.eql(Ta.x, Qa.x)); return F2.div(F2.sub(Qa.y, Ta.y), F2.sub(Qa.x, Ta.x)); };
  const lines = []; // {lam, c} per delta line, in event order
  for (let e = 1; e <= NE; e++) {
    let Ta = T.toAffine(); let lam = slopeDbl(Ta); lines.push({lam, c: F2.sub(F2.mul(lam, Ta.x), Ta.y), e, add: false}); T = T.double();
    if (BITS[e]) { Ta = T.toAffine(); lam = slopeAdd(Ta, d); lines.push({lam, c: F2.sub(F2.mul(lam, Ta.x), Ta.y), e, add: true}); T = T.add(VK.delta); }
  }
  assert.equal(lines.length, NE + ADD_EVENTS.length); // 68
  assert.ok(T.equals(VK.delta.multiply(X_ABS)), 'delta walk ends at [|x|]delta');
  // the on-chain delta recursion: state (x_j, c_{j-1}, lam_{j-1}); c_j = (lam_{j-1} + lam_j) x_j - c_{j-1}; x_{j+1} = lam_j^2 - x_j - s
  { let x = d.x, c = d.y, l = F2.ZERO; for (const [j, ln] of lines.entries()) { const cj = F2.sub(F2.mul(F2.add(l, ln.lam), x), c); assert.ok(F2.eql(cj, ln.c), 'delta c_j recursion ' + j); c = cj; l = ln.lam; x = F2.sub(F2.sub(F2.sqr(ln.lam), x), ln.add ? d.x : x); } }
  const mIC = VK.ic.map((P) => millerAbs(P, VK.gamma));
  const mConst = F12.mul(millerAbs(VK.alpha, VK.beta), mIC[0]);
  const sF = (m) => F12.conjugate(F12.frobeniusMap(m, 1)); // sigma o Frob: ^(-p) = ^|x| on mu_r
  const R = [1, 2].map((k) => [monicRep(mIC[k]), monicRep(sF(mIC[k]))]);
  R.forEach((Rk, k) => { // R_{k,2} = R_{k,0}(eta X), R_{k,3} = R_{k,1}(eta X) represent (sigma Frob)^2, (sigma Frob)^3
    let m = mIC[k + 1]; const pw = [m]; for (let i = 1; i < 4; i++) { m = sF(m); pw.push(m); }
    [0, 1].forEach((i) => { const sh = psubst(Rk[i], ETA); assert.equal(sh[6], 1n); assert.ok(sameClass(fromPoly(sh), pw[i + 2]), 'R_{k,i+2} via eta X'); });
    // and the GT action: FE((sigma Frob)^i m) = FE(m)^(|x|^i)
  });
  { const g = F12.finalExponentiate(mIC[1]); assert.ok(F12.eql(F12.finalExponentiate(sF(mIC[1])), F12.pow(g, X_ABS)), 'sigma Frob = ^|x| on GT'); }
  const Rconst = monicRep(mConst);
  return {deltaAff: d, lines, mIC, mConst, R, Rconst};
})();
export const glsFactorPoly = (k, i) => { let f = VKC.R[k][i % 2]; if (i >= 2) f = psubst(f, ETA); return f; };
const tbl = (k, n) => { let poly = [1n]; for (let i = 0; i < 4; i++) if ((n >> i) & 1) poly = pmul(poly, glsFactorPoly(k, i)); return poly; };

// ---------------- the event schedule as polynomials ----------------
// event 0: GLS bit 63 only (F starts at c^-1, T = B); event e = 1..63: square, B doubling line, delta line,
// [B addition line, delta line, c^-1 if bit 63-e of |x|], GLS nibbles (bit 63-e of d_{k,0..3}).
export function factorSchedule(st) {
  const {xA, yA, xB, yB, xC, yC, N} = st; const yP = mod(-yA); // B lines at P = -A
  let T = [xB, yB, F2.ONE]; const events = [{fs: [tbl(0, N[0][0]), tbl(1, N[1][0])], add: false, Tafter: T}];
  let j = 0; const dl = () => { const L = VKC.lines[j++]; return linePoly(xC, yC, L.c, F2.neg(L.lam), F2.ONE); };
  for (let e = 1; e <= NE; e++) {
    const fs = []; let o = projDbl(T); fs.push(linePoly(xA, yP, ...o.line)); T = o.T; fs.push(dl());
    if (BITS[e]) { o = projAdd(T, [xB, yB]); fs.push(linePoly(xA, yP, ...o.line)); T = o.T; fs.push(dl()); }
    fs.push(tbl(0, N[0][e]), tbl(1, N[1][e]));
    events.push({fs, add: !!BITS[e], Tafter: T});
  }
  assert.equal(j, VKC.lines.length);
  const [px, py] = psi(xB, yB); const [X, Y, Z] = T; // endpoint: T = [|x|]B == -psi(B) projectively, Z != 0
  const endpoint = !F2.is0(Z) && F2.eql(X, F2.mul(px, Z)) && F2.eql(Y, F2.mul(F2.neg(py), Z));
  return {events, endpoint, Tend: T};
}

// ---------------- chunking and the adversarial degree bound ----------------
// bounds: ascending event indices b (exclusive ends); chunk k = events [bounds[k-1] (or 0), bounds[k]); last bound = 64
export const eventDeg = (e, glsBits) => (e === 0 ? 0 : 18 + (BITS[e] ? 24 : 0)) + 6 * glsBits;
export const chunkDegP = (bounds, k, bitsOf = () => 8) => { let d = 6; for (let e = k ? bounds[k - 1] : 0; e < bounds[k]; e++) d = (e === 0 ? d : 2 * d) + eventDeg(e, bitsOf(e)); return d; };
const nqOfDegD = (dD) => { const dq = (dD % 2 ? dD : dD - 1) - 12; return (dq + 1) / 2; };
export const nqMax = (bounds, bitsOf = () => 8) => Math.max(...bounds.map((_, k) => nqOfDegD(chunkDegP(bounds, k, bitsOf) + 6)), nqOfDegD(12 + 6));
export const uniformBounds = (c = 2) => { const b = []; for (let e = c; e < NE + 1; e += c) b.push(e); if (b.at(-1) !== NE + 1) b.push(NE + 1); return b; };

// ---------------- encodings / transcript ----------------
export const W48 = 48;
export const le = (x, n) => { assert.ok(x >= 0n && x < 1n << BigInt(8 * n)); const b = Buffer.alloc(n); let v = x; for (let i = 0; i < n; i++) { b[i] = Number(v & 255n); v >>= 8n; } return b; };
export const rdle = (b, o = 0, n = W48) => { let v = 0n; for (let i = n - 1; i >= 0; i--) v = v * 256n + BigInt(b[o + i]); return v; };
export const sha = (...parts) => createHash('sha256').update(Buffer.concat(parts)).digest();
export const toFp = (h) => rdle(h, 0, 32); // BIN2NUM(h || 0x00): already in [0, 2^256) subset of [0, p)

// ---------------- prover ----------------
export function prove(pf, {bounds = uniformBounds(2)} = {}) {
  const {A, B, C, ns} = pf; A.assertValidity(); B.assertValidity(); C.assertValidity();
  ns.forEach((n) => assert.ok(n >= 0n && n < r));
  const ds = ns.map(glsDigits);
  const N = ds.map((d) => Array.from({length: NE + 1}, (_, ev) => d.reduce((s, v, i) => s | (Number((v >> BigInt(GLS_BITS - 1 - ev)) & 1n) << i), 0)));
  const Aa = A.toAffine(), Ba = B.toAffine(), Ca = C.toAffine();
  const st = {xA: Aa.x, yA: Aa.y, xB: Ba.x, yB: Ba.y, xC: Ca.x, yC: Ca.y, N};
  const sched = factorSchedule(st); assert.ok(sched.endpoint, 'B endpoint');
  // raw product with the B and delta Miller loops checked against noble
  let raw = F12.ONE, mB = F12.ONE, mD = F12.ONE;
  sched.events.forEach((ev, e) => { if (e) { raw = F12.sqr(raw); mB = F12.sqr(mB); mD = F12.sqr(mD); }
    for (const [i, f] of ev.fs.entries()) { const F = fromPoly(f); raw = F12.mul(raw, F); const kind = ev.add ? ['B', 'D', 'B', 'D', 'G', 'G'][i] : e ? ['B', 'D', 'G', 'G'][i] : 'G'; if (kind === 'B') mB = F12.mul(mB, F); if (kind === 'D') mD = F12.mul(mD, F); } });
  assert.ok(sameClass(mB, millerAbs(A.negate(), B)), 'B Miller loop = f_{|x|,B}(-A) in G');
  assert.ok(sameClass(mD, millerAbs(C, VK.delta)), 'delta Miller loop = f_{|x|,delta}(C) in G');
  const Fprime = F12.mul(raw, VKC.mConst);
  assert.ok(F12.eql(F12.finalExponentiate(Fprime), F12.ONE), 'Groth16 equation fails');
  // residue root: [c]^lambda = [F']
  const u = F12.mul(F12.conjugate(Fprime), F12.inv(Fprime)), v = F12.pow(u, minv(LAMBDA, N6R)), c = F12.add(F12.ONE, F12.conjugate(v));
  const Sc = monicRep(c); const cInv = pneg(Sc); // [S_c(-X)] = [c^-1]
  // classes along the loop; states after each chunk
  let Fc = fromPoly(cInv); const states = []; let k = 0;
  sched.events.forEach((ev, e) => { if (e) Fc = F12.sqr(Fc); for (const f of ev.fs) Fc = F12.mul(Fc, fromPoly(f)); if (ev.add) Fc = F12.mul(Fc, fromPoly(cInv)); if (e + 1 === bounds[k]) { states.push(monicRep(Fc)); k++; } });
  assert.equal(states.length, bounds.length);
  // identities: chunk k: [P_k] = [S_{k+1}]; terminal: [S_K Rconst] = [Frob(c)]
  const Sp = [cInv, ...states]; const ids = [];
  for (let kk = 0; kk < bounds.length; kk++) {
    let P = Sp[kk];
    for (let e = kk ? bounds[kk - 1] : 0; e < bounds[kk]; e++) { if (e) P = pmul(P, P); for (const f of sched.events[e].fs) P = pmul(P, f); if (sched.events[e].add) P = pmul(P, cInv); }
    ids.push({P, W: Sp[kk + 1]});
  }
  ids.push({P: pmul(Sp[bounds.length], VKC.Rconst), W: frob1Monic(Sc)});
  for (const id of ids) {
    const Nn = pmul(id.P, pneg(id.W)); const D = psub(Nn, pneg(Nn)); const {q, r: rem} = pdivM(D);
    assert.ok(rem.every((x) => x === 0n), 'identity not divisible by M'); assert.ok(q.every((x, i) => i % 2 === 1 || x === 0n), 'quotient not odd');
    id.Q = q; id.degD = deg(D);
  }
  return {st, sched, Sc, states, ids, ns, ds, N, c};
}
// transcript + aggregated quotient for a given data encoding (the split decides the byte layout of phase 1)
export function quotient(proved, rho, nq) {
  const K = proved.ids.length; const Qagg = Array(2 * nq).fill(0n);
  proved.ids.forEach((id, k) => { const w = mod(rho ** BigInt(K - 1 - k)); id.Q.forEach((x, i) => { if (x) { assert.ok(i < 2 * nq, 'Q exceeds the structural bound'); Qagg[i] = mod(Qagg[i] + w * x); } }); });
  return Qagg.filter((_, i) => i % 2 === 1); // q_0..q_{nq-1}: coefficient of X^(2j+1)
}

// ---------------- value-level evaluation of one chunk range (shared by the single and split verifiers) ----------------
// st: decoded statement; returns the running values; every function below is what the script computes
export const evalAt = (poly, z) => [peval(poly, z), peval(poly, mod(-z))];
export function runEvents(st, sched, sc, z, {from, to, F, Tin}) { // events [from, to): F = [F+, F-] in, returns F out
  let [Fp_, Fm_] = F; const scm = pneg([...sc, 1n]); const [cp, cm] = evalAt(scm, z);
  for (let e = from; e < to; e++) {
    const ev = sched.events[e]; if (e) { Fp_ = mod(Fp_ * Fp_); Fm_ = mod(Fm_ * Fm_); }
    for (const f of ev.fs) { const [a, b] = evalAt(f, z); Fp_ = mod(Fp_ * a); Fm_ = mod(Fm_ * b); }
    if (ev.add) { Fp_ = mod(Fp_ * cp); Fm_ = mod(Fm_ * cm); }
  }
  return [Fp_, Fm_];
}

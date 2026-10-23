// Off-chain reference of the commit-all protocol (prover + verifier math, no script).
// Variant: Fp6-projective states (class mod Fp6*), rho-batched odd quotient, every line evaluated
// by the verifier at +-z from (a) the affine B walk with witnessed slopes checked exactly,
// (b) the delta walk with baked slopes, and e(vk_x, gamma) replaced by GT factors
// prod_i prod_j phi^j(G_i)^{k_ij} folded into the shared squaring chain (G_i ~ ML(IC_i, gamma)).
// -1 digits of 6x+2: by default (the measured spec) U is multiplied by conj(chat), i.e. chat's values
// at -+z (conj(chat) ~ chat^-1 mod Fp6*). CHAT_NEG=vside reproduces the original design, which moves
// chat^b to the V side of each chunk identity.
// Usage: node reference.mjs [fixtureIndex]   (GT_MODE=bin for binary instead of NAF GT digits)
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {bn254} from '@noble/curves/bn254.js';
import {psiFrobenius} from '@noble/curves/abstract/tower.js';
import {residueWitness} from '../../../../chunked/bn254/densless-recovered/root-witness.mjs';
import {decompose} from './gt-decomp.mjs';
const Fp = bn254.fields.Fp, F2 = bn254.fields.Fp2, F12 = bn254.fields.Fp12, P = Fp.ORDER, R = bn254.fields.Fr.ORDER;
const mod = (x) => ((x % P) + P) % P;
const X_BN = 4965661367192848881n;
const fx = JSON.parse(readFileSync(new URL('../../../../chunked/bn254/densless-recovered/public-fixtures.json', import.meta.url)));
const FIX = Number(process.argv[2] ?? 0);
const SWAP = process.env.CHAT_NEG !== 'vside';
const {vk} = fx, {proof, publicInputs} = fx.fixtures[FIX];
// ---------------- polynomial model of Fp12 = Fp[X]/(X^12 - 18 X^6 + 82) ----------------
const ORDER = [0, 2, 4, 1, 3, 5]; // tower Fp2 slot i -> degree d (w = X, v = X^2, u = X^6 - 9)
const flat = (x) => [x.c0.c0.c0, x.c0.c0.c1, x.c0.c1.c0, x.c0.c1.c1, x.c0.c2.c0, x.c0.c2.c1, x.c1.c0.c0, x.c1.c0.c1, x.c1.c1.c0, x.c1.c1.c1, x.c1.c2.c0, x.c1.c2.c1];
const toPoly = (t) => { const c = flat(t), out = Array(12).fill(0n); ORDER.forEach((d, i) => { out[d] = mod(c[2 * i] - 9n * c[2 * i + 1]); out[d + 6] = mod(c[2 * i + 1]); }); return out; };
const fromPoly = (q) => { const r = reduce(q), c = Array(12).fill(0n); ORDER.forEach((d, i) => { c[2 * i + 1] = r[d + 6]; c[2 * i] = mod(r[d] + 9n * r[d + 6]); });
  const f2 = (i) => F2.fromBigTuple([c[2 * i], c[2 * i + 1]]);
  return F12.create({c0: bn254.fields.Fp6.create({c0: f2(0), c1: f2(1), c2: f2(2)}), c1: bn254.fields.Fp6.create({c0: f2(3), c1: f2(4), c2: f2(5)})}); };
const pmul = (a, b) => { const o = Array(a.length + b.length - 1).fill(0n); for (let i = 0; i < a.length; i++) if (a[i]) for (let j = 0; j < b.length; j++) o[i + j] += a[i] * b[j]; return o.map(mod); };
const padd = (a, b) => Array.from({length: Math.max(a.length, b.length)}, (_, i) => mod((a[i] ?? 0n) + (b[i] ?? 0n)));
const psub = (a, b) => Array.from({length: Math.max(a.length, b.length)}, (_, i) => mod((a[i] ?? 0n) - (b[i] ?? 0n)));
const pneg = (a) => a.map((c, i) => (i % 2 ? mod(-c) : c)); // a(-X)
const pscale = (a, k) => a.map((c) => mod(c * k));
const deg = (a) => { let d = a.length - 1; while (d > 0 && a[d] === 0n) d--; return d; };
function divM(a) { // returns [q, r] with a = q*M + r
  const r = [...a], q = Array(Math.max(1, a.length - 12)).fill(0n);
  for (let i = r.length - 1; i >= 12; i--) { const v = r[i]; if (!v) continue; q[i - 12] = v; r[i] = 0n; r[i - 6] = mod(r[i - 6] + 18n * v); r[i - 12] = mod(r[i - 12] - 82n * v); }
  return [q, r.slice(0, 12).concat(Array(Math.max(0, 12 - r.length)).fill(0n)).slice(0, 12)];
}
const reduce = (a) => divM(a)[1];
const evalP = (a, z) => a.reduceRight((acc, c) => mod(acc * z + c), 0n);
const MPOLY = (() => { const m = Array(13).fill(0n); m[12] = 1n; m[6] = mod(-18n); m[0] = 82n; return m; })();
// class representative m + X for an element with nonzero odd part (Fp6-projective normalisation)
function normalize(poly) {
  const r = reduce(poly), G = r.map((c, i) => (i % 2 ? 0n : c)), H = r.map((c, i) => (i % 2 ? 0n : r[i + 1] ?? 0n)); // r = G + X*H
  assert(H.some((c) => c), 'odd part zero');
  const m = reduce(toPoly(F12.mul(fromPoly(G), F12.inv(fromPoly(H)))));
  assert(m.every((c, i) => i % 2 === 0 || c === 0n), 'm not even');
  const out = [...m]; out[1] = 1n; return out; // m + X
}
const evenLimbs = (s) => [0, 2, 4, 6, 8, 10].map((i) => s[i]); // the 6 committed limbs of m (X-coefficient is the implicit 1)
// ---------------- Fp2 embedding at z: eps(a) = a0 + a1*(z^6-9) ----------------
const f2poly = (a, d) => { const o = Array(d + 7).fill(0n); o[d] = mod(a.c0 - 9n * a.c1); o[d + 6] = mod(a.c1); return o; };
// line l = cy*yP (slot X^0) + cx*xP (slot X^1) + cb (slot X^3)
const linePoly = (cy, cx, cb, xP, yP) => padd(padd(f2poly(F2.mul(cy, {c0: yP, c1: 0n}), 0), f2poly(F2.mul(cx, {c0: xP, c1: 0n}), 1)), f2poly(cb, 3));
// ---------------- statement ----------------
const g1 = (q) => bn254.G1.Point.fromAffine({x: BigInt(q.x), y: BigInt(q.y)});
const g2 = (q) => bn254.G2.Point.fromAffine({x: {c0: BigInt(q.x.c0), c1: BigInt(q.x.c1)}, y: {c0: BigInt(q.y.c0), c1: BigInt(q.y.c1)}});
const A = g1(proof.a), Bp = g2(proof.b), C = g1(proof.c), n = publicInputs.map(BigInt);
const negA = A.negate().toAffine(), Ca = C.toAffine(), Ba = Bp.toAffine();
const gamma = g2(vk.gamma), delta = g2(vk.delta), alpha = g1(vk.alpha), beta = g2(vk.beta), IC = vk.ic.map(g1);
// NAF digits exactly as densless witness.mjs
const digits = []; for (let k = 6n * X_BN + 2n; k > 1n; k >>= 1n) { if (!(k & 1n)) digits.unshift(0); else if ((k & 3n) === 3n) { digits.unshift(-1); k++; } else digits.unshift(1); }
const NE = digits.length;
const {psi} = psiFrobenius(Fp, F2, F2.NONRESIDUE);
// ---------------- affine walk producing (slope, b = slope*x - y) per line ----------------
function walk(Q) { // returns per event list of {lam, b} and final point; affine formulas
  let T = Q.toAffine(); const ev = [];
  const add = (T, S) => { const lam = F2.div(F2.sub(S.y, T.y), F2.sub(S.x, T.x)); const x = F2.sub(F2.sub(F2.sqr(lam), T.x), S.x); return [{lam, b: F2.sub(F2.mul(lam, T.x), T.y)}, {x, y: F2.sub(F2.mul(lam, F2.sub(T.x, x)), T.y)}]; };
  const dbl = (T) => { const lam = F2.div(F2.mul(F2.sqr(T.x), {c0: 3n, c1: 0n}), F2.add(T.y, T.y)); const x = F2.sub(F2.sqr(lam), F2.add(T.x, T.x)); return [{lam, b: F2.sub(F2.mul(lam, T.x), T.y)}, {x, y: F2.sub(F2.mul(lam, F2.sub(T.x, x)), T.y)}]; };
  const Qa = Q.toAffine(), nQ = {x: Qa.x, y: F2.neg(Qa.y)};
  for (let e = 0; e < NE; e++) {
    const lines = []; let l;
    [l, T] = dbl(T); lines.push(l);
    if (digits[e]) { [l, T] = add(T, digits[e] > 0 ? Qa : nQ); lines.push(l); }
    if (e === NE - 1) { const q1 = psi(Qa.x, Qa.y), q2 = psi(q1[0], q1[1]);
      [l, T] = add(T, {x: q1[0], y: q1[1]}); lines.push(l); [l, T] = add(T, {x: q2[0], y: F2.neg(q2[1])}); lines.push(l); }
    ev.push(lines);
  }
  return {ev, T};
}
const Bwalk = walk(Bp), Dwalk = walk(delta);
{ // tie + subgroup: T_final == -psi^3(B)
  const q1 = psi(Ba.x, Ba.y), q2 = psi(q1[0], q1[1]), q3 = psi(q2[0], q2[1]);
  assert(F2.eql(Bwalk.T.x, q3[0]) && F2.eql(Bwalk.T.y, F2.neg(q3[1])), 'T_final != -psi^3(B)');
}
const unitLine = (l, P) => linePoly(F2.ONE, F2.neg(l.lam), l.b, P.x, P.y);
// ---------------- GT factors ----------------
const mlRaw = (p1, q2) => bn254.pairing(p1, q2, false);
const Gi = [1, 2].map((i) => normalize(toPoly(mlRaw(IC[i], gamma))));
const Kconst = normalize(pmul(toPoly(mlRaw(alpha, beta)), toPoly(mlRaw(IC[0], gamma))));
const frobP = (poly, j) => toPoly(F12.frobeniusMap(fromPoly(poly), j));
const ks = n.map((ni) => decompose(ni)); // ks[i][j], |k| < 2^64 (bit b used at event NE-1-b)
// signed digit of scalar k at bit position b: binary-of-|k| with sign (GT_MODE=bin) or NAF (default)
const nafDigits = (k) => { const out = []; let a = k < 0n ? -k : k; const s = k < 0n ? -1 : 1; while (a > 0n) { if (a & 1n) { const d = (a & 3n) === 3n ? -1 : 1; out.push(d * s); a -= BigInt(d); } else out.push(0); a >>= 1n; } return out; };
const binDigits = (k) => { const out = []; let a = k < 0n ? -k : k; const s = k < 0n ? -1 : 1; while (a > 0n) { out.push(a & 1n ? s : 0); a >>= 1n; } return out; };
const DIG = ks.map((row) => row.map((k) => (process.env.GT_MODE === 'bin' ? binDigits(k) : nafDigits(k))));
DIG.flat().forEach((d) => assert(d.length <= NE));
const gtDigit = (i, j, e) => DIG[i][j][NE - 1 - e] ?? 0;
const factorPoly = (i, j, d) => { const f = frobP(Gi[i], j); return d < 0 ? pneg(f) : f; }; // conj = inverse up to Fp6
const gtFactors = (e) => { const out = []; for (let i = 0; i < 2; i++) for (let j = 0; j < 4; j++) { const d = gtDigit(i, j, e); if (d) out.push(factorPoly(i, j, d)); } return out; };
// ---------------- prover: raw chain f (no chat) and residue ----------------
const eventFactors = (e) => [...Bwalk.ev[e].map((l) => unitLine(l, negA)), ...Dwalk.ev[e].map((l) => unitLine(l, Ca)), ...gtFactors(e)];
let f = [1n];
for (let e = 0; e < NE; e++) { f = reduce(pmul(f, f)); for (const g of eventFactors(e)) f = reduce(pmul(f, g)); }
const fTot = reduce(pmul(f, Kconst));
assert(F12.eql(F12.finalExponentiate(fromPoly(fTot)), F12.ONE), 'pairing product != 1');
const {c} = residueWitness(fromPoly(fTot));
const chat = normalize(toPoly(F12.inv(c)));  // chat ~ c^-1, committed as 6 limbs
// ---------------- prover: chunking, states, quotient ----------------
const chunkU = (Sprev, i, j) => { // unreduced U and the chat exponent b moved to V
  let U = Sprev, b = 0;
  for (let e = i; e < j; e++) {
    U = pmul(U, U); for (const g of eventFactors(e)) U = pmul(U, g);
    if (digits[e] === 1) U = pmul(U, chat);
    if (digits[e] === -1 && SWAP) U = pmul(U, pneg(chat));
    b = 2 * b + (digits[e] === -1 && !SWAP ? 1 : 0);
  }
  return {U, b};
};
const ppow = (a, k) => { let o = [1n]; for (let i = 0; i < k; i++) o = pmul(o, a); return o; };
// greedy chunking for a degree target (the model's DP picks the target; here: fixed target)
const gCount = (e) => { let c = 0; for (let i = 0; i < 2; i++) for (let j = 0; j < 4; j++) if (gtDigit(i, j, e)) c++; return c; };
const nLines = (e) => (2 + 2 * (digits[e] ? 1 : 0) + (e === NE - 1 ? 4 : 0));
const fW = (i, j) => { let dU = 10, b = 0; for (let e = i; e < j; e++) { dU = 2 * dU + 9 * nLines(e) + (digits[e] === 1 || (digits[e] === -1 && SWAP) ? 10 : 0) + 10 * gCount(e); b = 2 * b + (digits[e] === -1 && !SWAP ? 1 : 0); } if (j === NE) dU += 30; return dU + 10 + 10 * b; };
let TARGET = Number(process.env.WMAX ?? 0);
if (!TARGET) { // DP over degree caps: minimise 192*states + 32*oddQ
  const caps = new Set(); for (let i = 0; i < NE; i++) for (let j = i + 1; j <= Math.min(NE, i + 6); j++) caps.add(fW(i, j));
  let best = null;
  for (const cap of caps) { let i = 0, cnt = 0, ok = true; while (i < NE) { let j = i; while (j < NE && fW(i, j + 1) <= cap) j++; if (j === i) { ok = false; break; } i = j; cnt++; }
    if (!ok) continue; const cost = 192 * (cnt - 1) + 32 * (Math.floor((cap - 12) / 2) + 1); if (!best || cost < best.cost) best = {cap, cost}; }
  TARGET = best.cap;
}
const bounds = [0]; const states = []; const Ws = [];
let S = chat, i0 = 0;
const phi = [1, 2, 3].map((j) => frobP(chat, j));
while (i0 < NE) {
  let j = i0 + 1, best = null;
  for (; j <= NE; j++) {
    const {U, b} = chunkU(S, i0, j); const last = j === NE;
    const Ut = last ? pmul(pmul(pmul(U, phi[0]), phi[2]), Kconst) : U;
    const Snext = last ? null : normalize(U.length > 12 ? (b ? pmul(U, pneg(ppow(chat, b))) : U) : U); // S ~ U / chat^b ; dividing by chat^b ~ multiplying by conj(chat)^b
    const V = last ? pmul(phi[1], ppow(chat, b)) : pmul(Snext, ppow(chat, b));
    const W = psub(pmul(Ut, pneg(V)), pmul(pneg(Ut), V));
    if (best && deg(W) > TARGET) break;
    best = {j, W, Snext};
    if (last) break;
  }
  Ws.push(best.W); if (best.Snext) states.push(best.Snext); S = best.Snext; i0 = best.j; bounds.push(i0);
}
// every per-chunk identity holds mod M (W odd, divisible by M)
Ws.forEach((W, k) => { assert(divM(W)[1].every((c) => c === 0n), 'chunk ' + k + ' identity fails'); assert(W.every((c, i) => i % 2 === 1 || c === 0n), 'W not odd'); });
// ---------------- transcript ----------------
const be32 = (x) => Buffer.from(mod(x).toString(16).padStart(64, '0'), 'hex');
const H = (...parts) => createHash('sha256').update(Buffer.concat(parts)).digest();
const toF = (h) => mod(BigInt('0x' + h.toString('hex')));
const bitsBlob = Buffer.from(Array.from({length: NE}, (_, e) => { let w = 0; for (let t = 0; t < 8; t++) { const d = gtDigit(t >> 2, t & 3, e); w |= (d === 1 ? 1 : d === -1 ? 2 : 0) << (2 * t); } return [w & 255, w >> 8]; }).flat());
const signByte = Buffer.alloc(0);
const boundaryMask = Buffer.from(bounds.slice(1, -1).map((b) => b)); // chunk ends
const tau0 = H(Buffer.from('commit-all/v1'), ...[negA.x, A.toAffine().y, Ba.x.c0, Ba.x.c1, Ba.y.c0, Ba.y.c1, Ca.x, Ca.y, ...n].map(be32));
const tau1 = H(tau0, bitsBlob, signByte, boundaryMask, ...evenLimbs(chat).map(be32), ...states.flatMap((s) => evenLimbs(s).map(be32)));
const rho = toF(tau1);
let Agg = [0n]; Ws.forEach((W, k) => (Agg = padd(Agg, pscale(W, mod(rho ** BigInt(k))))));
const [Q, rem] = divM(Agg); assert(rem.every((c) => c === 0n));
assert(Q.every((c, i) => i % 2 === 1 || c === 0n), 'Q not odd');
const Qodd = Q.slice(0, deg(Q) + 1).filter((_, i) => i % 2 === 1); // q_1, q_3, ..., q_degQ (no trailing zero padding)
// spec caps the verifier enforces (README, Soundness): L_MAX = 4 events per chunk, at most 160 odd Q coefficients
const L_MAX = 4, QODD_MAX = 160;
bounds.slice(1).forEach((b, k) => assert(b - bounds[k] <= L_MAX, 'chunk ' + k + ' exceeds L_MAX = ' + L_MAX + ' events'));
assert(Qodd.length <= QODD_MAX, 'Q has ' + Qodd.length + ' odd coefficients, cap ' + QODD_MAX);
const tau2 = H(tau1, ...Qodd.map(be32));
const z = toF(tau2);
// ---------------- verifier (value level, at +-z) ----------------
function verify() {
  assert(z !== 0n);
  const u = mod(z ** 6n - 9n), eps = (a) => mod(a.c0 + a.c1 * u);
  const z3 = mod(z ** 3n);
  const evalEven6 = (limbs) => evalP([limbs[0], 0n, limbs[1], 0n, limbs[2], 0n, limbs[3], 0n, limbs[4], 0n, limbs[5]], z); // m(z)
  const evalPM = (poly) => [evalP(poly, z), evalP(poly, mod(-z))];
  // lines at +-z from (lam, b) and P: l(+-z) = yP +- T, T = -eps(lam)*xP*z + eps(b)*z^3
  const lineAt = (l, Pt) => { const T = mod(-eps(l.lam) * Pt.x * z + eps(l.b) * z3); return [mod(Pt.y + T), mod(Pt.y - T)]; };
  // B walk recomputed with exact slope checks (the verifier's view; slopes are the witness)
  let T = {x: Ba.x, y: Ba.y}; const Bl = [];
  const chkDbl = (lam) => assert(F2.eql(F2.mul(lam, F2.add(T.y, T.y)), F2.mul(F2.sqr(T.x), {c0: 3n, c1: 0n})));
  const chkAdd = (lam, S) => { assert(!F2.eql(S.x, T.x)); assert(F2.eql(F2.mul(lam, F2.sub(S.x, T.x)), F2.sub(S.y, T.y))); };
  const step = (lam, S) => { const x = S ? F2.sub(F2.sub(F2.sqr(lam), T.x), S.x) : F2.sub(F2.sqr(lam), F2.add(T.x, T.x)); const b = F2.sub(F2.mul(lam, T.x), T.y); T = {x, y: F2.sub(b, F2.mul(lam, x))}; return {lam, b}; };
  const Qa = Ba, nQ = {x: Ba.x, y: F2.neg(Ba.y)}, q1 = psi(Ba.x, Ba.y), q2 = psi(q1[0], q1[1]), q3 = psi(q2[0], q2[1]);
  for (let e = 0; e < NE; e++) {
    const wl = Bwalk.ev[e]; const out = []; let k = 0;
    chkDbl(wl[k].lam); out.push(step(wl[k++].lam));
    if (digits[e]) { const S = digits[e] > 0 ? Qa : nQ; chkAdd(wl[k].lam, S); out.push(step(wl[k++].lam, S)); }
    if (e === NE - 1) { for (const S of [{x: q1[0], y: q1[1]}, {x: q2[0], y: F2.neg(q2[1])}]) { chkAdd(wl[k].lam, S); out.push(step(wl[k++].lam, S)); } }
    Bl.push(out);
  }
  assert(F2.eql(T.x, q3[0]) && F2.eql(T.y, F2.neg(q3[1])), 'subgroup/tie check');
  // GT factor values at +-z (signs swap the pair)
  const gtv = [0, 1].map((i) => [0, 1, 2, 3].map((j) => evalPM(frobP(Gi[i], j))));
  const chatv = [mod(evalEven6(evenLimbs(chat)) + z), mod(evalEven6(evenLimbs(chat)) - z)];
  const powv = (v, k) => [mod(v[0] ** BigInt(k)), mod(v[1] ** BigInt(k))];
  let acc = 0n, rp = 1n, Sv = chatv;
  for (let ch = 0; ch < bounds.length - 1; ch++) {
    let U = [...Sv], b = 0;
    for (let e = bounds[ch]; e < bounds[ch + 1]; e++) {
      U = [mod(U[0] * U[0]), mod(U[1] * U[1])];
      const mulv = (v) => { U = [mod(U[0] * v[0]), mod(U[1] * v[1])]; };
      Bl[e].forEach((l) => mulv(lineAt(l, negA)));
      Dwalk.ev[e].forEach((l) => mulv(lineAt(l, Ca)));            // delta: (lam, b) from baked slopes
      for (let i = 0; i < 2; i++) for (let j = 0; j < 4; j++) { const d = gtDigit(i, j, e); if (d) mulv(d > 0 ? gtv[i][j] : [gtv[i][j][1], gtv[i][j][0]]); }
      if (digits[e] === 1) mulv(chatv);
      if (digits[e] === -1 && SWAP) mulv([chatv[1], chatv[0]]); // conj(chat)(+-z) = chat(-+z)
      b = 2 * b + (digits[e] === -1 && !SWAP ? 1 : 0);
    }
    const last = ch === bounds.length - 2;
    let V;
    if (!last) { const m = evalEven6(evenLimbs(states[ch])); Sv = [mod(m + z), mod(m - z)]; V = Sv; }
    else { const [p1, p2, p3] = phi.map(evalPM); const Kv = evalPM(Kconst); U = [mod(U[0] * p1[0] * p3[0] * Kv[0]), mod(U[1] * p1[1] * p3[1] * Kv[1])]; V = p2; }
    const cb = powv(chatv, b); V = [mod(V[0] * cb[0]), mod(V[1] * cb[1])];
    acc = mod(acc + rp * (U[0] * V[1] - U[1] * V[0])); rp = mod(rp * rho);
  }
  const Qz = mod(z * Qodd.reduceRight((a, q) => mod(a * mod(z * z) + q), 0n));
  const Mz = evalP(MPOLY, z);
  return acc === mod(Qz * Mz);
}
assert(verify(), 'verifier rejected honest proof');
const maxW = Math.max(...Ws.map(deg));
console.log(JSON.stringify({fixture: FIX, chatNeg: SWAP ? 'swap' : 'vside', chunks: bounds.length - 1, bounds, committedStates: states.length, maxW, degQ: deg(Q), oddQcoeffs: Qodd.length,
  bytes: {chat: 192, states: 192 * states.length, quotient: 32 * Qodd.length, gtBits: bitsBlob.length + 1, mask: boundaryMask.length, slopesB: 64 * Bwalk.ev.flat().length},
  kMaxBits: Math.max(...ks.flat().map((k) => (k < 0n ? -k : k).toString(2).length)), verifier: 'ACCEPT'}));
// negative control: perturb one committed state limb -> the batched identity must fail
{
  const saved = states[3][0]; states[3][0] = mod(saved + 1n);
  let ok; try { ok = verify(); } catch { ok = false; }
  states[3][0] = saved;
  console.log('perturbed state (z/rho kept fixed) rejected:', !ok);
}

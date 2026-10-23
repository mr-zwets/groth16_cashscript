// Single-identity BN254 Groth16 verifier: executable protocol reference (honest prover + verifier).
//   node proto.mjs [--gls] [--rep=6|10] [--chunks=dp|<s>|a,b,c] [--fix=N] [--json]
// --gls : no vk_x MSM, no gamma Miller loop; e(vk_x,gamma) via 8 GT-GLS factors on the shared chain.
// --rep : class representative of states/c/constants: 6 = monic degree-6 (X^6 + s5 X^5 + ... + s0), 10 = g(X^2)+X.
// Verifies: Groth16 FE == 1, torus residue, every chunk identity exactly divisible by M, the batched
// check sum_k rho^(K-1-k) D_k(z) == Q(z) M(z) with on-chain-style evaluation (chains at +z and -z).
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFileSync, writeFileSync} from 'node:fs';
import {bn254} from '@noble/curves/bn254.js';
import {psiFrobenius} from '@noble/curves/abstract/tower.js';
const args = Object.fromEntries(process.argv.slice(2).map((a) => { const [k, v] = a.replace(/^--/, '').split('='); return [k, v ?? true]; }));
const GLS = !!args.gls, REP = Number(args.rep ?? 6), FIX = Number(args.fix ?? 0), CH = args.chunks ?? 'dp';
const {Fp, Fp2: F, Fp6, Fp12: T} = bn254.fields;
const p = Fp.ORDER, r = bn254.fields.Fr.ORDER, BN_X = 4965661367192848881n;
const mod = (x, m = p) => ((x % m) + m) % m;
const fx = JSON.parse(readFileSync(new URL('../../../../chunked/bn254/densless-recovered/public-fixtures.json', import.meta.url)));
const {vk} = fx; const {proof, publicInputs} = fx.fixtures[FIX];
const g1 = (x) => bn254.G1.Point.fromAffine({x: BigInt(x.x), y: BigInt(x.y)});
const g2 = (x) => bn254.G2.Point.fromAffine({x: {c0: BigInt(x.x.c0), c1: BigInt(x.x.c1)}, y: {c0: BigInt(x.y.c0), c1: BigInt(x.y.c1)}});

// ---------------- polynomials over Fp, Fp12 = Fp[X]/M, M = X^12 - 18 X^6 + 82, X = w, u = X^6 - 9 ----------------
const trim = (a) => { a = a.slice(); while (a.length > 1 && a.at(-1) === 0n) a.pop(); return a; };
const flat = (x) => [x.c0.c0.c0, x.c0.c0.c1, x.c0.c1.c0, x.c0.c1.c1, x.c0.c2.c0, x.c0.c2.c1, x.c1.c0.c0, x.c1.c0.c1, x.c1.c1.c0, x.c1.c1.c1, x.c1.c2.c0, x.c1.c2.c1];
const poly = (x) => { const c = flat(x), out = Array(12).fill(0n); for (const [i, d] of [0, 2, 4, 1, 3, 5].entries()) { out[d] = mod(c[2 * i] - 9n * c[2 * i + 1]); out[d + 6] = c[2 * i + 1]; } return trim(out); };
const pmul = (a, b) => { const o = Array(a.length + b.length - 1).fill(0n); for (let i = 0; i < a.length; i++) if (a[i]) for (let j = 0; j < b.length; j++) o[i + j] += a[i] * b[j]; return o.map((x) => mod(x)); };
const psub = (a, b) => trim(Array.from({length: Math.max(a.length, b.length)}, (_, i) => mod((a[i] ?? 0n) - (b[i] ?? 0n))));
const pneg = (a) => a.map((c, i) => (i % 2 ? mod(-c) : c)); // a(-X) = conjugation (w -> -w)
const pdivM = (a) => { const rem = a.slice(), q = Array(Math.max(1, a.length - 12)).fill(0n); for (let i = rem.length - 1; i >= 12; i--) { const v = rem[i]; q[i - 12] = v; rem[i] = 0n; rem[i - 6] = mod(rem[i - 6] + 18n * v); rem[i - 12] = mod(rem[i - 12] - 82n * v); } return {q: trim(q), r: trim(rem.slice(0, 12))}; };
const peval = (a, x) => { let acc = 0n; for (let i = a.length - 1; i >= 0; i--) acc = mod(acc * x + a[i]); return acc; };
const pmodM = (a) => { const r0 = pdivM(a).r; return [...r0, ...Array(12 - r0.length).fill(0n)]; };
const solveMod = (A, b) => { // Gaussian elimination mod p
  const n = A.length, Mx = A.map((row, i) => [...row, b[i]].map((x) => mod(x)));
  for (let c = 0; c < n; c++) { let piv = c; while (piv < n && Mx[piv][c] === 0n) piv++; if (piv === n) throw new Error('singular'); [Mx[c], Mx[piv]] = [Mx[piv], Mx[c]];
    const iv = Fp.inv(Mx[c][c]); Mx[c] = Mx[c].map((x) => mod(x * iv));
    for (let i = 0; i < n; i++) if (i !== c && Mx[i][c]) { const m = Mx[i][c]; Mx[i] = Mx[i].map((x, k) => mod(x - m * Mx[c][k])); } }
  return Mx.map((row) => row[n]);
};
// class representative of f in Fp12*/Fp6*
const repPoly = (f) => {
  if (REP === 10) return poly(T.create({c0: Fp6.mul(f.c0, Fp6.inv(f.c1)), c1: Fp6.ONE}));
  const fp = poly(f), cols = [0, 2, 4, 6, 8, 10].map((d) => pmodM(pmul(Array.from({length: d + 1}, (_, i) => (i === d ? 1n : 0n)), fp)));
  // find s (6 coords on X^0,X^2,..,X^10) with (s f)[7..11] = 0 and (s f)[6] = 1
  const s = solveMod([6, 7, 8, 9, 10, 11].map((row) => cols.map((c) => c[row])), [1n, 0n, 0n, 0n, 0n, 0n]);
  const out = Array(12).fill(0n); cols.forEach((c, j) => c.forEach((x, i) => (out[i] = mod(out[i] + s[j] * x))));
  assert.ok(out.slice(7).every((x) => x === 0n) && out[6] === 1n); return trim(out);
};
const repDeg = REP === 6 ? 6 : 10;

// ---------------- statement and Miller data ----------------
const A = g1(proof.a), B = g2(proof.b), C = g1(proof.c), gam = g2(vk.gamma), del = g2(vk.delta);
[A, C].forEach((x) => x.assertValidity()); B.assertValidity();
const ns = publicInputs.map(BigInt);
const IC = vk.ic.map(g1);
const mAB = bn254.pairing(g1(vk.alpha), g2(vk.beta), false);
let Ps, Qs, mConst, glsFactors = [], decomposition = null;
if (!GLS) {
  let vkx = IC[0]; ns.forEach((k, i) => { if (k) vkx = vkx.add(IC[i + 1].multiply(k)); });
  Ps = [A.negate(), vkx, C].map((x) => x.toAffine()); Qs = [B, gam, del]; mConst = mAB;
} else {
  // GLS lattice for Frobenius on GT (eigenvalue p mod r)
  const x = BN_X, pr = [1n, p % r, (p * p) % r, (p ** 3n) % r];
  // LLL-reduced basis of {v : sum v_i p^i = 0 mod r}, written in x (verified below: every row is in
  // the lattice and |det| = r)
  const lat = [[2n * x + 1n, 0n, 2n * x, 1n], [2n * x, x + 1n, -x, x], [x + 1n, x, x, -2n * x], [2n * x + 1n, -x, -(x + 1n), -x]];
  lat.forEach((b) => assert.equal(mod(b.reduce((s, v, i) => s + v * pr[i], 0n), r), 0n));
  const det = (m) => m.length === 1 ? m[0][0] : m[0].reduce((s, v, j) => s + (j % 2 ? -1n : 1n) * v * det(m.slice(1).map((row) => row.filter((_, k) => k !== j))), 0n);
  const D = det(lat); assert.equal(D < 0n ? -D : D, r);
  // Babai: c = round(n * adj(L)^T[.,0] / det)
  const decompose = (n) => {
    const cof = (i, j) => (((i + j) % 2) ? -1n : 1n) * det(lat.filter((_, a) => a !== i).map((row) => row.filter((_, b) => b !== j)));
    // solve sum_j c_j lat[j] = (n,0,0,0): c_j = n * cof(j,0) / D
    const c = [0, 1, 2, 3].map((j) => { const num = n * cof(j, 0); const q = num / D, rem = num % D; return 2n * (rem < 0n ? -rem : rem) >= (D < 0n ? -D : D) ? q + ((num < 0n) !== (D < 0n) ? -1n : 1n) : q; });
    const e = [n, 0n, 0n, 0n].map((v, i) => v - c.reduce((s, cj, j) => s + cj * lat[j][i], 0n));
    assert.equal(mod(e.reduce((s, v, i) => s + v * pr[i], 0n), r), mod(n, r)); return e;
  };
  const es = ns.map(decompose); decomposition = es.map((e) => e.map(String));
  const mIC = IC.map((P) => bn254.pairing(P, gam, false));
  mConst = T.mul(mAB, mIC[0]);
  es.forEach((e, k) => e.forEach((ei, i) => { let el = T.frobeniusMap(mIC[k + 1], i); if (ei < 0n) el = T.conjugate(el); glsFactors.push({k, i, e: ei < 0n ? -ei : ei, el, sign: ei < 0n ? -1 : 1}); }));
  assert.ok(glsFactors.every((f) => f.e < 1n << 65n), 'sub-scalar exceeds 65 bits');
  Ps = [A.negate(), C].map((x) => x.toAffine()); Qs = [B, del];
}
const NP = Qs.length;
const digits = []; for (let n = 6n * BN_X + 2n; n > 1n; n >>= 1n) { if (!(n & 1n)) digits.unshift(0); else if ((n & 3n) === 3n) { digits.unshift(-1); n++; } else digits.unshift(1); }
const NE = digits.length; assert.equal(NE, 65);
// unit-free affine line (what the script computes): yP + (-lam xP) w + (lam xT - yT) w^3
const lineAt = (P, lam, Ta) => T.create({c0: Fp6.create({c0: {c0: P.y, c1: 0n}, c1: F.ZERO, c2: F.ZERO}),
  c1: Fp6.create({c0: F.mul(F.neg(lam), {c0: P.x, c1: 0n}), c1: F.sub(F.mul(lam, Ta.x), Ta.y), c2: F.ZERO})});
const {psi} = psiFrobenius(Fp, F, F.NONRESIDUE);
const running = Qs.slice(); const slopesB = [];
const dbl = (i) => { const a = running[i].toAffine(); const lam = F.div(F.mul(F.sqr(a.x), {c0: 3n, c1: 0n}), F.add(a.y, a.y)); if (i === 0) slopesB.push(lam); running[i] = running[i].double(); return lineAt(Ps[i], lam, a); };
const addL = (i, q) => { const a = running[i].toAffine(), b = q.toAffine(); assert.ok(!F.eql(a.x, b.x)); const lam = F.div(F.sub(b.y, a.y), F.sub(b.x, a.x)); if (i === 0) slopesB.push(lam); running[i] = running[i].add(q); return lineAt(Ps[i], lam, a); };
const bitAt = (e, b) => Number((e >> BigInt(b)) & 1n);
const eventLines = [], eventMuls = [];
for (let e = 0; e < NE; e++) {
  const fs = [...Array(NP).keys()].map(dbl);
  if (digits[e]) fs.push(...[...Array(NP).keys()].map((i) => addL(i, digits[e] < 0 ? Qs[i].negate() : Qs[i])));
  eventLines.push(fs); eventMuls.push(glsFactors.filter((f) => bitAt(f.e, 64 - e)).map((f) => f.el));
}
const finalLines = [];
for (let i = 0; i < NP; i++) { const q = Qs[i].toAffine(), q1 = psi(q.x, q.y), q2 = psi(q1[0], q1[1]);
  finalLines.push(addL(i, bn254.G2.Point.fromAffine({x: q1[0], y: q1[1]}))); finalLines.push(addL(i, bn254.G2.Point.fromAffine({x: q2[0], y: F.neg(q2[1])}))); }
const endpointOK = (() => { const q = B.toAffine(), q1 = psi(q.x, q.y), q2 = psi(q1[0], q1[1]), q3 = psi(q2[0], q2[1]); const R = running[0].toAffine(); return F.eql(R.x, q3[0]) && F.eql(R.y, F.neg(q3[1])); })();
assert.ok(endpointOK, 'B endpoint');
let raw = T.ONE;
for (let e = 0; e < NE; e++) { raw = T.sqr(raw); eventLines[e].forEach((l) => (raw = T.mul(raw, l))); eventMuls[e].forEach((m) => (raw = T.mul(raw, m))); }
finalLines.forEach((l) => (raw = T.mul(raw, l))); raw = T.mul(raw, mConst);
assert.ok(T.eql(T.finalExponentiate(raw), T.ONE), 'Groth16 equation');
// torus residue root: [c]^lambda = [raw]
const LAMBDA = 6n * BN_X + 2n + p - p ** 2n + p ** 3n, N6r = (p ** 6n + 1n) / r;
const minv = (a, m) => { let [x, y] = [mod(a, m), m], [s0, s1] = [1n, 0n]; while (y) { const q = x / y; [x, y] = [y, x - q * y]; [s0, s1] = [s1, s0 - q * s1]; } assert.equal(x, 1n); return mod(s0, m); };
const uu = T.mul(T.conjugate(raw), T.inv(raw)), vv = T.pow(uu, minv(LAMBDA, N6r)), c = T.add(T.ONE, T.conjugate(vv));
const sameClass = (a, b) => Fp6.eql(Fp6.mul(a.c0, Fp6.inv(a.c1)), Fp6.mul(b.c0, Fp6.inv(b.c1)));
assert.ok(sameClass(T.pow(c, LAMBDA), raw), 'torus residue');

// ---------------- chunk boundaries ----------------
const evDeg = (e) => 9 * NP + (digits[e] ? 9 * NP + repDeg : 0) + repDeg * eventMuls[e].length;
const evDegWorst = (e) => 9 * NP + (digits[e] ? 9 * NP + repDeg : 0) + repDeg * glsFactors.length;
const degChunk = (a, b, f = evDeg) => { let d = repDeg; for (let e = a; e < b; e++) d = 2 * d + f(e); return d; };
const U_STATE = Number(args.ustate ?? 226), U_Q = Number(args.uq ?? 38); // cost units (bytes + op/800) from model.mjs
const dp = (f) => { let best = null;
  for (let Dmax = 30; Dmax <= 1200; Dmax++) { const bs = []; let a = 0, ok = true;
    while (a < NE) { let b = a + 1; if (degChunk(a, b, f) > Dmax) { ok = false; break; } while (b < NE && degChunk(a, b + 1, f) <= Dmax) b++; bs.push(b); a = b; }
    if (!ok) continue; const real = Math.max(...bs.map((b, i) => degChunk(i ? bs[i - 1] : 0, b, f)));
    const cost = bs.length * U_STATE + Math.ceil((real + repDeg - 12) / 2) * U_Q;
    if (!best || cost < best.cost) best = {cost, bounds: bs}; }
  return best.bounds; };
let bounds = CH === 'dp' ? dp(evDeg) : CH === 'dpworst' ? dp(evDegWorst) : CH.includes(',') ? CH.split(',').map(Number) : (() => { const s = Number(CH), b = []; for (let e = s; e < NE; e += s) b.push(e); return [...b, NE]; })();
if (bounds.at(-1) !== NE) bounds.push(NE);
bounds = [0, ...bounds];

// ---------------- honest prover ----------------
const cRep = repPoly(c), cInvRep = pneg(cRep); // [c^-1] = [conj c]
const factorRep = new Map(); const fRep = (m) => { if (!factorRep.has(m)) factorRep.set(m, repPoly(m)); return factorRep.get(m); };
let Fc = T.create({c0: Fp6.ONE, c1: Fp6.ZERO}); // track exact elements; class reps taken at boundaries
const cInv = T.inv(c); Fc = cInv; const cls = [Fc];
for (let e = 0; e < NE; e++) { Fc = T.sqr(Fc); eventLines[e].forEach((l) => (Fc = T.mul(Fc, l))); eventMuls[e].forEach((m) => (Fc = T.mul(Fc, m))); if (digits[e]) Fc = T.mul(Fc, digits[e] < 0 ? c : cInv); cls.push(Fc); }
const states = bounds.slice(1).map((b) => repPoly(cls[b]));
const Sp = [cInvRep, ...states];
const ids = [];
for (let k = 0; k + 1 < bounds.length; k++) {
  let Pk = Sp[k];
  for (let e = bounds[k]; e < bounds[k + 1]; e++) { Pk = pmul(Pk, Pk); eventLines[e].forEach((l) => (Pk = pmul(Pk, poly(l)))); eventMuls[e].forEach((m) => (Pk = pmul(Pk, fRep(m)))); if (digits[e]) Pk = pmul(Pk, digits[e] < 0 ? cRep : cInvRep); }
  ids.push({name: `${bounds[k]}..${bounds[k + 1]}`, P: Pk, W: Sp[k + 1]});
}
// terminal: [S_K * frob lines * T_const * c^(p^2)] = [c^p * c^(p^3)]; Frobenius images as polynomials (any rep)
const frobPoly = (j) => poly((() => { // Frob^j of the element whose poly is cRep
  // element with polynomial cRep: tower coefficients a_j = (c_j + 9 c_{j+6}) + c_{j+6} u
  const cc = [...cRep, ...Array(12 - cRep.length).fill(0n)], a = [0, 1, 2, 3, 4, 5].map((d) => ({c0: mod(cc[d] + 9n * cc[d + 6]), c1: cc[d + 6]}));
  const el = T.create({c0: Fp6.create({c0: a[0], c1: a[2], c2: a[4]}), c1: Fp6.create({c0: a[1], c1: a[3], c2: a[5]})});
  assert.deepEqual(trim(poly(el)), trim(cRep)); return T.frobeniusMap(el, j); })());
let Pfin = Sp.at(-1); finalLines.forEach((l) => (Pfin = pmul(Pfin, poly(l)))); Pfin = pmul(pmul(Pfin, fRep(mConst)), frobPoly(2));
ids.push({name: 'terminal', P: Pfin, W: pmul(frobPoly(1), frobPoly(3))});
for (const id of ids) { const N = pmul(id.P, pneg(id.W)); const D = psub(N, pneg(N)); const {q, r: rem} = pdivM(D);
  assert.ok(rem.length === 1 && rem[0] === 0n, 'identity not divisible: ' + id.name); assert.ok(q.every((x, i) => i % 2 === 1 || x === 0n)); id.degP = id.P.length - 1; id.degQ = q.length - 1; id.Q = q; }

// ---------------- transcript + verifier ----------------
const H = (...parts) => createHash('sha256').update(Buffer.concat(parts.map((x) => (Buffer.isBuffer(x) ? x : Buffer.from(x))))).digest();
const be = (x) => Buffer.from(mod(x).toString(16).padStart(64, '0'), 'hex');
const stateWords = (s) => (REP === 6 ? s.slice(0, 6) : [0, 2, 4, 6, 8, 10].map((i) => s[i] ?? 0n));
const h0 = H('BN254-SI/v1', ...[Ps[0].x, Ps[0].y, ...[proof.b.x.c0, proof.b.x.c1, proof.b.y.c0, proof.b.y.c1].map(BigInt), BigInt(proof.c.x), BigInt(proof.c.y), ...ns].map(be),
  ...(GLS ? glsFactors.map((f) => be(BigInt(f.sign) * f.e)) : []), ...stateWords(cRep).map(be), ...states.flatMap(stateWords).map(be));
const rho = mod(BigInt('0x' + H(h0, 'rho').toString('hex')));
const K = ids.length, maxQ = Math.max(...ids.map((i) => i.degQ));
const Qagg = Array(maxQ + 1).fill(0n);
ids.forEach((id, k) => { const w = mod(rho ** BigInt(K - 1 - k)); id.Q.forEach((x, i) => (Qagg[i] = mod(Qagg[i] + w * x))); });
const qOdd = Qagg.filter((_, i) => i % 2 === 1);
const z = mod(BigInt('0x' + H(h0, be(rho), ...qOdd.map(be)).toString('hex')));
// verifier: run chains at +z and -z exactly as the script does (values only, no polynomials of degree > 12)
const ev = (pl, x) => peval(pl, x);
const verify = (Sp) => { let Racc = 0n;
{
  let fp = ev(Sp[0], z), fm = ev(Sp[0], mod(-z)), k = 0;
  for (let e = 0; e < NE; e++) {
    fp = mod(fp * fp); fm = mod(fm * fm);
    for (const l of eventLines[e]) { const lp = poly(l); fp = mod(fp * ev(lp, z)); fm = mod(fm * ev(lp, mod(-z))); }
    for (const m of eventMuls[e]) { fp = mod(fp * ev(fRep(m), z)); fm = mod(fm * ev(fRep(m), mod(-z))); }
    if (digits[e]) { const cc = digits[e] < 0 ? cRep : cInvRep; fp = mod(fp * ev(cc, z)); fm = mod(fm * ev(cc, mod(-z))); }
    if (e + 1 === bounds[k + 1]) { const W = Sp[k + 1]; Racc = mod(Racc * rho + fp * ev(W, mod(-z)) - fm * ev(W, z)); k++; fp = ev(W, z); fm = ev(W, mod(-z)); }
  }
  for (const l of finalLines) { const lp = poly(l); fp = mod(fp * ev(lp, z)); fm = mod(fm * ev(lp, mod(-z))); }
  for (const t of [fRep(mConst), frobPoly(2)]) { fp = mod(fp * ev(t, z)); fm = mod(fm * ev(t, mod(-z))); }
  const Wt = pmul(frobPoly(1), frobPoly(3)); Racc = mod(Racc * rho + fp * ev(Wt, mod(-z)) - fm * ev(Wt, z));
} return Racc; };
const Racc = verify(Sp);
const Mz = peval([82n, 0n, 0n, 0n, 0n, 0n, mod(-18n), 0n, 0n, 0n, 0n, 0n, 1n], z);
const Qz = mod(z * qOdd.reduceRight((acc, x) => mod(acc * z * z + x), 0n));
assert.equal(Racc, mod(Qz * Mz), 'batched check');
// negative control: perturb one state coefficient (same rho, Q, z) -> batched check must fail
{ const bad = Sp.map((x) => x.slice()); bad[5][0] = mod(bad[5][0] + 1n); assert.notEqual(verify(bad), mod(Qz * Mz), 'tampered state accepted'); }
// worst-case degrees over all witnesses for these fixed boundaries: every GLS bit set in every event.
// D_k = P_k(X)S'(-X) - P_k(-X)S'(X) is odd, so deg D_k <= the largest odd number <= deg P_k + repDeg.
const worstChunks = bounds.slice(1).map((b, i) => degChunk(bounds[i], b, evDegWorst));
const worstDegP = Math.max(...worstChunks), worstDegD = (worstDegP + repDeg) % 2 ? worstDegP + repDeg : worstDegP + repDeg - 1;
const worstQWords = (worstDegD - 12 + 1) / 2; // odd coefficients q_1..q_{deg D - 12}
const out = {fixture: FIX, gls: GLS, rep: REP, pairs: NP, chunks: bounds.length - 1, states: states.length, bounds: bounds.slice(1),
  degP: ids.map((i) => i.degP), maxDegQ: maxQ, quotientWords: qOdd.length,
  worst: {degP: worstDegP, degD: worstDegD, qWords: worstQWords, chunksAtMax: worstChunks.flatMap((d, i) => (d === worstDegP ? [bounds[i]] : []))}, bSlopes: slopesB.length,
  glsBits: glsFactors.map((f) => f.e.toString(2).length), glsMulsTotal: eventMuls.reduce((s, m) => s + m.length, 0), decomposition,
  witnessWords: 10 + 6 + 6 * states.length + 2 * slopesB.length + qOdd.length, ok: true};
if (args.json) writeFileSync(new URL(`./proto-${GLS ? 'gls' : 'base'}-rep${REP}-${CH}-f${FIX}.json`, import.meta.url), JSON.stringify(out, null, 1));
console.log(JSON.stringify({...out, degP: out.degP.join(' '), bounds: out.bounds.join(',')}));

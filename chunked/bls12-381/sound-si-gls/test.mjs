// Protocol self-test (merged from the second design's test.mjs) and a cross-check of math.mjs against the second
// design's independently written math module (research/sound-si-gls-bls12381-d2/math.mjs).
//   node test.mjs
// 1. cross-check: eta, gamma1, the twist, psi, 3b', the residue exponent, the 68 delta slopes, the GT-GLS digits and
//    factors (by final exponentiation: the two modules use different Miller normalizations, so classes may differ but
//    FE must agree), the Frobenius formula, and the line / projective formulas;
// 2. honest proofs for several statements are accepted by the value-level reference verifier (protocol.mjs), and
//    one-bit tampering of WS or WQ is rejected;
// 3. the identity fixtures have no encoding, and a false statement has no honest witness (the prover's own Groth16
//    assertion fires).
import assert from 'node:assert/strict';
import * as A from './math.mjs';
import {prove, verifyValues, projDbl, projAdd, WS_SIZE, NQ_MAX, E_A} from './protocol.mjs';
const B = await import('../../../research/sound-si-gls-bls12381-d2/math.mjs');

// ---------------- 1. cross-check against the second design's math ----------------
assert.equal(A.p, B.p); assert.equal(A.r, B.r); assert.equal(A.AX, B.T);
assert.equal(A.ETA, B.ETA, 'eta'); assert.ok(A.F2.eql(A.GAMMA1, B.GAMMA1), 'gamma1');
assert.ok(A.F2.eql(A.B_TWIST, B.B_TWIST) && A.F2.eql(A.B3, B.B3), "b', 3b'");
assert.equal(A.LAMBDA, B.LAMBDA); assert.equal(A.N6R, B.N6R);
assert.deepEqual(A.BITS, B.BITS); assert.deepEqual(A.ADD_EVENTS, B.ADD_EVENTS);
{ const Q = A.G2.BASE.multiply(4242n).toAffine(); const [x1, y1] = A.psiAff(Q.x, Q.y), [x2, y2] = B.psiAff(Q.x, Q.y); assert.ok(A.F2.eql(x1, x2) && A.F2.eql(y1, y2), 'psi'); }
assert.equal(A.VKC.lams.length, B.VKC.lams.length); A.VKC.lams.forEach((l, j) => assert.ok(A.F2.eql(l, B.VKC.lams[j]), 'delta slope ' + j));
for (const n of [0n, 1n, A.r - 1n, 123456789n ** 5n % A.r]) assert.deepEqual(A.glsDigits(n), B.glsDigits(n), 'GLS digits');
for (const k of [0, 1]) for (let i = 0; i < 4; i++) assert.ok(A.F12.eql(A.FE(A.fromPoly(A.glsFactor(k, i))), B.F12.finalExponentiate(B.fromPoly(B.glsFactorPoly(k, i)))), `FE of GLS factor ${k},${i}`);
{ const s = [3n, 5n, 7n, 11n, 13n, 17n].map((x) => A.mod(x ** 77n)); assert.equal(A.pmodM(A.frob1Monic(s)).join(), B.pmodM(B.frob1Monic(s)).join(), 'Frob(S)'); }
{ const P = A.G1.BASE.multiply(99n).toAffine(), T = A.G2.BASE.multiply(1234n).toAffine(), Bq = A.G2.BASE.multiply(777n).toAffine(); const Z = A.f2(5n, 9n);
  const lam = A.slopeDbl(T); const c = A.F2.sub(A.F2.mul(lam, T.x), T.y);
  assert.equal(A.trim(A.lineAffPoly(P.x, P.y, lam, c)).join(), B.linePoly(P.x, P.y, c, A.F2.neg(lam), A.F2.ONE).join(), 'affine line');
  const pt = [A.F2.mul(T.x, Z), A.F2.mul(T.y, Z), Z]; const d1 = projDbl(pt), d2 = B.projDbl(pt); [0, 1, 2].forEach((i) => assert.ok(A.F2.eql(d1.T[i], d2.T[i]) && A.F2.eql(d1.line[i], d2.line[i]), 'projective doubling'));
  const a1 = projAdd(pt, [Bq.x, Bq.y]), a2 = B.projAdd(pt, [Bq.x, Bq.y]); [0, 1, 2].forEach((i) => assert.ok(A.F2.eql(a1.T[i], a2.T[i]) && A.F2.eql(a1.line[i], a2.line[i]), 'projective addition'));
  assert.equal(A.trim(A.lineGenPoly(P.x, P.y, ...d1.line)).join(), B.linePoly(P.x, P.y, ...d2.line).join(), 'projective line'); }
console.log('math cross-check against the second design: ok');

// ---------------- 2. honest proofs accepted, tampering rejected (value level) ----------------
console.log('E_A', E_A, 'WS', WS_SIZE, 'NQ_MAX', NQ_MAX);
const T = A.AX;
const cases = [[123n, 456n], [0n, 0n], [A.r - 1n, 1n], [2n ** 200n + 12345n, A.r - 2n], [(T - 1n) * (1n + T + T * T), (T - 1n) * (1n + T + T * T) + 7n], [A.r - 1n, A.r - 1n]];
for (const ns of cases) {
  const fx = A.mint(ns); assert.ok(A.groth16Holds(fx));
  const t0 = Date.now(); const w = prove(fx); const v = verifyValues(w.WS, w.WQ);
  console.log(ns.map(String).map((s) => s.slice(0, 12)).join(','), 'nq', w.nq, v.ok ? 'ACCEPT' : 'REJECT ' + v.why, (Date.now() - t0) + 'ms');
  assert.ok(v.ok);
  const bad = Buffer.from(w.WS); bad[WS_SIZE - 7] ^= 1; assert.equal(verifyValues(bad, w.WQ).ok, false);
  const badq = Buffer.from(w.WQ); badq[5] ^= 1; assert.equal(verifyValues(w.WS, badq).ok, false);
}
for (const n of A.FIXTURE_NAMES) { const w = prove(A.FIXTURES[n]); assert.ok(verifyValues(w.WS, w.WQ).ok, n); }
// ---------------- 3. identity fixtures and false statements ----------------
for (const n of A.IDENTITY_FIXTURES) assert.throws(() => prove(A.FIXTURES[n]), /infinity|is0|ZERO|zero/i, n);
{ const fx = A.mint([123n, 456n]); assert.throws(() => prove({inputs: [124n, 456n], proof: fx.proof}), /Groth16/); }
console.log('ok');

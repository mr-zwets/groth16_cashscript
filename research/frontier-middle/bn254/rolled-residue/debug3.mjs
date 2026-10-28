// debug: terminal stages vs a field mirror (committed proof, or the tampered statement with FORGE=1)
import {buildPartial} from './script.mjs';
import {bare} from './vm.mjs';
import {vmNumberToBigInt} from '@bitauth/libauth';
import {VEC, mod, F2, F12, NE, DIGITS, VKC, ETA, projDbl, projAdd, linePoly, fromPoly, toPoly, pneg, psubst, pmul, pmodM, frob1Monic, psiK, g1, g2} from './math.mjs';
import {prove} from './protocol.mjs';
const forge = !!process.env.FORGE; const pi = forge ? VEC.invalid.publicInputs : VEC.publicInputs;
const w = prove({proof: VEC.proof, publicInputs: pi}, {forge});
const Aa = g1(VEC.proof.a).toAffine(), Ba = g2(VEC.proof.b).toAffine(), Ca = g1(VEC.proof.c).toAffine();
const Q = {B: [Ba.x, Ba.y], G: [VKC.gamma.x, VKC.gamma.y], D: [VKC.delta.x, VKC.delta.y]};
const P = {B: [Aa.x, mod(-Aa.y)], G: [w.V.x, w.V.y], D: [Ca.x, Ca.y]};
const T = Object.fromEntries(Object.entries(Q).map(([k, [x, y]]) => [k, [x, y, F2.ONE]]));
const Sc = w.Sc; let f = fromPoly(pneg(Sc)); const mulL = (k, o) => { f = F12.mul(f, fromPoly(linePoly(P[k][0], P[k][1], ...o.line))); T[k] = o.T; };
for (let e = 0; e < NE; e++) { f = F12.sqr(f); for (const k of ['B', 'G', 'D']) mulL(k, projDbl(T[k]));
  if (DIGITS[e]) { for (const k of ['B', 'G', 'D']) mulL(k, projAdd(T[k], [Q[k][0], DIGITS[e] < 0 ? F2.neg(Q[k][1]) : Q[k][1]])); f = F12.mul(f, fromPoly(DIGITS[e] > 0 ? pneg(Sc) : Sc)); } }
for (const k of ['B', 'G', 'D']) { const [x, y] = Q[k]; const [p1x, p1y] = psiK(1, x, y), [p2x, p2y] = psiK(2, x, y); mulL(k, projAdd(T[k], [p1x, p1y])); mulL(k, projAdd(T[k], [p2x, F2.neg(p2y)])); }
const Pt = f; f = F12.mul(F12.mul(f, fromPoly(VKC.MAB)), fromPoly(psubst(Sc, ETA))); const Pfin = f;
const W = pmodM(pmul(frob1Monic(Sc.slice(0, 6)), psubst(frob1Monic(Sc.slice(0, 6)), ETA)));
const P1 = F12.mul(Pfin, fromPoly(pneg(frob1Monic(Sc.slice(0, 6))))); const P2 = F12.mul(Pfin, fromPoly(pneg(W)));
console.log('mirror: P2 odd zero?', toPoly(P2).every((x, i) => i % 2 === 0 || x === 0n));
for (const label of ['termlines', 'pfin', 'p1']) {
  const {code, names} = buildPartial(label); const res = bare(code, [w.W]); const val = (n) => mod(vmNumberToBigInt(res.stack[names.lastIndexOf(n)], {requireMinimalEncoding: false}));
  const ref = {termlines: Pt, pfin: Pfin, p1: P1}[label]; console.log(label, 'op', res.opCost, toPoly(ref).map((x, i) => (x === val('F' + i) ? 1 : 0)).join(''));
}

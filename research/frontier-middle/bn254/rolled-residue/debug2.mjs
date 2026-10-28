// debug: compare the on-chain F after the loop (and walk states) with a field-level mirror
import {buildPartial} from './script.mjs';
import {bare} from './vm.mjs';
import {vmNumberToBigInt} from '@bitauth/libauth';
import {VEC, mod, F2, F12, NE, DIGITS, VKC, projDbl, projAdd, linePoly, fromPoly, toPoly, pneg, g1, g2} from './math.mjs';
import {prove} from './protocol.mjs';
const w = prove({proof: VEC.proof, publicInputs: VEC.publicInputs});
const {code, names} = buildPartial(process.argv[2] ?? 'postloop'); const res = bare(code, [w.W]);
const val = (n) => mod(vmNumberToBigInt(res.stack[names.lastIndexOf(n)], {requireMinimalEncoding: false}));
const Aa = g1(VEC.proof.a).toAffine(), Ba = g2(VEC.proof.b).toAffine(), Ca = g1(VEC.proof.c).toAffine();
const Q = {B: [Ba.x, Ba.y], G: [VKC.gamma.x, VKC.gamma.y], D: [VKC.delta.x, VKC.delta.y]};
const P = {B: [Aa.x, mod(-Aa.y)], G: [w.V.x, w.V.y], D: [Ca.x, Ca.y]};
const T = Object.fromEntries(Object.entries(Q).map(([k, [x, y]]) => [k, [x, y, F2.ONE]]));
const Sc = w.Sc; let f = fromPoly(pneg(Sc)); const mulL = (k, o) => { f = F12.mul(f, fromPoly(linePoly(P[k][0], P[k][1], ...o.line))); T[k] = o.T; };
const nev = Number(process.argv[3] ?? NE);
for (let e = 0; e < nev; e++) { f = F12.sqr(f); for (const k of ['B', 'G', 'D']) mulL(k, projDbl(T[k]));
  if (DIGITS[e]) { for (const k of ['B', 'G', 'D']) mulL(k, projAdd(T[k], [Q[k][0], DIGITS[e] < 0 ? F2.neg(Q[k][1]) : Q[k][1]])); f = F12.mul(f, fromPoly(DIGITS[e] > 0 ? pneg(Sc) : Sc)); } }
const fp = toPoly(f); console.log('error', res.error, 'op', res.opCost);
console.log('F match', fp.map((x, i) => x === val('F' + i)).join(''));
for (const k of ['B', 'G', 'D']) console.log(k, 'X0 match', val(k + 'X0') === T[k][0].c0, val(k + 'Z1') === T[k][2].c1);
if (process.argv[2] === 'endpoint') {
  const {psiK} = await import('./math.mjs'); const [x, y] = Q.B; const [p1x, p1y] = psiK(1, x, y), [p2x, p2y] = psiK(2, x, y);
  let o = projAdd(T.B, [p1x, p1y]); T.B = o.T; o = projAdd(T.B, [p2x, F2.neg(p2y)]); T.B = o.T;
  console.log('after terminal adds B match', val('BX0') === T.B[0].c0, val('BY1') === T.B[1].c1, val('BZ0') === T.B[2].c0, 'px0', val('px0') === p1x.c0, val('py1') === p1y.c1);
}
if (process.argv[2] === 'endpoint') { const {PSI, psiK, GAMMA1} = await import('./math.mjs'); const [x, y] = Q.B;
  console.log('g20', val('g20') === PSI[0].x.c0, 'g31', val('g31') === PSI[0].y.c1, 'xB0', val('xB0') === x.c0, 'om', val('om'));
  const ps = psiK(1, x, y); console.log('px', val('px0').toString(16).slice(0,12), val('px1').toString(16).slice(0,12), ps[0].c0.toString(16).slice(0,12), ps[0].c1.toString(16).slice(0,12)); console.log(names.slice(-30).join(' ')); }
if (process.argv[2] === 'endpoint') { const {PSI, F2: FF, GAMMA1} = await import('./math.mjs'); const g2 = FF.sqr(GAMMA1);
  for (const n of ['g20','g21','g30','g31','al1','be1','eta']) console.log(n, val(n).toString(16).slice(0, 16)); console.log('exp g2', g2.c0.toString(16).slice(0,16), g2.c1.toString(16).slice(0,16), 'gamma1', GAMMA1.c0.toString(16).slice(0,16)); }

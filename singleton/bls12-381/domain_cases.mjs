// Out-of-domain proof inputs for the BLS12-381 singleton verifier (groth16.cash), shared by
// domain_checks_test.mjs and the vector builders (which ship them to the bench as extra
// rejection runs). Every case reuses the committed instance (bls_instance.mjs) and changes
// only the proof points; each must be REJECTED by the domain checks:
//   - coordinates outside [0, p) (the same point under a non-canonical encoding);
//   - A, C off E(Fp): y^2 = x^3 + 4, and B off the twist E'(Fp2): y^2 = x^3 + 4(1+u), including
//     (0,0), which is how a point at infinity would have to be encoded;
//   - B on the twist but outside G2: B + T13 and T13 itself (T13 of exact order 13, 13^2 | h2,
//     the case that collapses the homogeneous Miller walk to Z = 0), and B + [r]Q (a generic
//     cofactor component).
import { bls12_381 } from '@noble/curves/bls12-381.js';
import { bigIntToVmNumber, encodeDataPush } from '@bitauth/libauth';
import { proof, PUBLIC_INPUTS } from './bls_instance.mjs';

const P = bls12_381.fields.Fp.ORDER;
const R = bls12_381.fields.Fr.ORDER;
const Fp2 = bls12_381.fields.Fp2;
const G2 = bls12_381.G2.Point;
const H2 = 0x5d543a95414e7f1091d50792876a202cd91de4547085abaa68a205b2e5a7ddfa628f1cb4d9e82ef21537e293a6691ae1616ec6e786f0c70cf1c38e31c7238e5n;

const pushInt = (n) => encodeDataPush(bigIntToVmNumber(n));
export const unlockingFor = (args) => Uint8Array.from(args.slice().reverse().flatMap((a) => [...pushInt(a)]));

// ---- twist E'(Fp2): y^2 = x^3 + 4(1+u), affine arithmetic (null = O), for building non-G2 points ----
const B4 = Fp2.create({ c0: 4n, c1: 4n });
const onTwist = (Q) => Fp2.eql(Fp2.sqr(Q.y), Fp2.add(Fp2.mul(Fp2.sqr(Q.x), Q.x), B4));
const tAdd = (S, T) => {
  if (S === null) return T; if (T === null) return S;
  let l;
  if (Fp2.eql(S.x, T.x)) {
    if (!Fp2.eql(S.y, T.y) || Fp2.is0(S.y)) return null;
    l = Fp2.div(Fp2.mul(Fp2.sqr(S.x), Fp2.create({ c0: 3n, c1: 0n })), Fp2.add(S.y, S.y));
  } else {
    l = Fp2.div(Fp2.sub(T.y, S.y), Fp2.sub(T.x, S.x));
  }
  const x = Fp2.sub(Fp2.sub(Fp2.sqr(l), S.x), T.x);
  return { x, y: Fp2.sub(Fp2.mul(l, Fp2.sub(S.x, x)), S.y) };
};
const tMul = (Q, k) => { let acc = null, add = Q; for (; k > 0n; k >>= 1n) { if (k & 1n) acc = tAdd(acc, add); add = tAdd(add, add); } return acc; };
// a point of exact order 13 (13^2 | h2): strip every 13 from #E'(Fp2) = h2*r, take the
// 13-primary part of a twist point, then multiply by 13 until the next step would hit O
function order13Point() {
  if (H2 % 169n !== 0n) throw new Error('13^2 does not divide h2');
  let k = H2 * R; while (k % 13n === 0n) k /= 13n;
  for (let i = 1n; ; i++) {
    const x = Fp2.create({ c0: i, c1: 1n });
    const rhs = Fp2.add(Fp2.mul(Fp2.sqr(x), x), B4);
    let y; try { y = Fp2.sqrt(rhs); } catch { continue; }
    const Q = { x, y };
    if (tMul(Q, H2 * R) !== null) throw new Error('#E\'(Fp2) != h2*r');
    let T = tMul(Q, k);
    if (T === null) continue;
    while (tMul(T, 13n) !== null) T = tMul(T, 13n);
    return T;
  }
}

const A = proof.a.toAffine(), Bp = proof.b.toAffine(), C = proof.c.toAffine();
const honest = { Ax: A.x, Ay: A.y, Bxa: Bp.x.c0, Bxb: Bp.x.c1, Bya: Bp.y.c0, Byb: Bp.y.c1, Cx: C.x, Cy: C.y };
// spend(Ax,Ay, Bxa,Bxb,Bya,Byb, Cx,Cy, in0,in1)
export const toArgs = (w, inputs = PUBLIC_INPUTS) => [w.Ax, w.Ay, w.Bxa, w.Bxb, w.Bya, w.Byb, w.Cx, w.Cy, ...inputs];
export const honestArgs = toArgs(honest);
const withB = (Q) => ({ ...honest, Bxa: Q.x.c0, Bxb: Q.x.c1, Bya: Q.y.c0, Byb: Q.y.c1 });

export function domainRejectCases() {
  const T13 = order13Point();
  const Bt = { x: Bp.x, y: Bp.y };
  const BplusT = tAdd(Bt, T13);
  // a generic non-G2 twist point: B + [r]Q for a twist point Q (pure cofactor component)
  const cof = (() => { for (let i = 2n; ; i++) { const x = Fp2.create({ c0: i, c1: 0n }); try { const y = Fp2.sqrt(Fp2.add(Fp2.mul(Fp2.sqr(x), x), B4)); const c = tMul({ x, y }, R); if (c) return c; } catch { /* non-square */ } } })();
  const BplusCof = tAdd(Bt, cof);
  for (const [n, Q] of [['B+T13', BplusT], ['T13', T13], ['B+cofactor', BplusCof]]) {
    if (!onTwist(Q)) throw new Error(`${n} not on the twist`);
    let inG2 = true; try { G2.fromAffine({ x: Q.x, y: Q.y }).assertValidity(); } catch { inG2 = false; }
    if (inG2) throw new Error(`${n} unexpectedly in G2`);
  }
  return [
    ['A off-curve (Ay + 1)', { ...honest, Ay: honest.Ay + 1n }],
    ['C off-curve (Cy + 1)', { ...honest, Cy: honest.Cy + 1n }],
    ['A = (0,0) (no encoding of O)', { ...honest, Ax: 0n, Ay: 0n }],
    ['C = (0,0) (no encoding of O)', { ...honest, Cx: 0n, Cy: 0n }],
    ['B off-twist (Bya + 1)', { ...honest, Bya: honest.Bya + 1n }],
    ['B = (0,0) (no encoding of O)', { ...honest, Bxa: 0n, Bxb: 0n, Bya: 0n, Byb: 0n }],
    ['B on twist, not in G2: B + T13 (order 13)', withB(BplusT)],
    ['B on twist, not in G2: T13 (walk collapses)', withB(T13)],
    ['B on twist, not in G2: B + [r]Q (cofactor)', withB(BplusCof)],
    ['Ax + p (same point, non-canonical)', { ...honest, Ax: honest.Ax + P }],
    ['Cy + p (same point, non-canonical)', { ...honest, Cy: honest.Cy + P }],
    ['Byb + p (same point, non-canonical)', { ...honest, Byb: honest.Byb + P }],
    ['Ay - p (negative, same residue)', { ...honest, Ay: honest.Ay - P }],
  ].map(([label, w]) => ({ label, args: toArgs(w) }));
}

// JS SPEC for the BLS12-381 optimal-ate Miller loop, reproducing noble's
// millerLoopBatch using OUR own orchestration (pointDouble / pointAdd / mul014 /
// NAF) on noble's field primitives — the exact primitives our CashScript
// fp2/fp6/fp12 functions already match bit-for-bit. If this equals noble's
// pairing(.,.,false) and the multi-pair millerLoopBatch, the orchestration is
// correct and this file is the blueprint for the in-script Miller loop.
//
// Differences from the BN254 blueprint (../bn254/miller_ref.mjs):
//   * twist is MULTIPLICATIVE (M-type) -> the line uses mul014, not mul034
//   * G2 b' = 4*(1+u): mulByB(x) = (4 c0 - 4 c1) + (4 c0 + 4 c1) u
//   * the ate loop is the NAF of |x| (x = -0xd201000000010000); there is NO
//     6x+2 and NO Q1/Q2 postPrecompute
//   * x is NEGATIVE -> the Miller result is conjugated at the very end
//
// Run: node singleton/bls12-381/miller_ref.mjs
import { pathToFileURL } from 'node:url';

const NOBLE = pathToFileURL('C:/Users/mathi/Desktop/verifier/node_modules/@noble/curves/bls12-381.js').href;
const { bls12_381 } = await import(NOBLE);
const { Fp, Fp2, Fp6, Fp12 } = bls12_381.fields;

// ---- constants ----
const INV2 = Fp2.div(Fp2.ONE, Fp2.fromBigTuple([2n, 0n])); // 1/2 in Fp2 (== Fp2div2)
// G2 twist b' = 4*(1+u): mulByB(x) = (4 c0 - 4 c1) + (4 c0 + 4 c1) u
const mulByB = (x) => Fp2.fromBigTuple([
  Fp.sub(Fp.mul(x.c0, 4n), Fp.mul(x.c1, 4n)),
  Fp.add(Fp.mul(x.c0, 4n), Fp.mul(x.c1, 4n)),
]);
const scalarFp2 = (x, k) => Fp2.fromBigTuple([Fp.mul(x.c0, k), Fp.mul(x.c1, k)]); // Fp2 * Fp scalar

// ---- ate loop NAF of |x| (BLS_X) ----
const BLS_X = 0xd201000000010000n;
function naf(a) {
  const res = [];
  for (; a > 1n; a >>= 1n) {
    if ((a & 1n) === 0n) res.unshift(0);
    else if ((a & 3n) === 3n) { res.unshift(-1); a += 1n; }
    else res.unshift(1);
  }
  return res;
}
const ATE_NAF = naf(BLS_X);

// ---- line steps (noble pointDouble / pointAdd, identical to BN254) ----
function pointDouble(Rx, Ry, Rz) {
  const t0 = Fp2.sqr(Ry);
  const t1 = Fp2.sqr(Rz);
  const t2 = mulByB(Fp2.mul(t1, 3n));
  const t3 = Fp2.mul(t2, 3n);
  const t4 = Fp2.sub(Fp2.sub(Fp2.sqr(Fp2.add(Ry, Rz)), t1), t0);
  const c0 = Fp2.sub(t2, t0);
  const c1 = Fp2.mul(Fp2.sqr(Rx), 3n);
  const c2 = Fp2.neg(t4);
  const nx = Fp2.mul(Fp2.mul(Fp2.mul(Fp2.sub(t0, t3), Rx), Ry), INV2);
  const ny = Fp2.sub(Fp2.sqr(Fp2.mul(Fp2.add(t0, t3), INV2)), Fp2.mul(Fp2.sqr(t2), 3n));
  const nz = Fp2.mul(t0, t4);
  return { coeffs: [c0, c1, c2], R: { x: nx, y: ny, z: nz } };
}
function pointAdd(Rx, Ry, Rz, Qx, Qy) {
  const t0 = Fp2.sub(Ry, Fp2.mul(Qy, Rz));
  const t1 = Fp2.sub(Rx, Fp2.mul(Qx, Rz));
  const c0 = Fp2.sub(Fp2.mul(t0, Qx), Fp2.mul(t1, Qy));
  const c1 = Fp2.neg(t0);
  const c2 = t1;
  const t2 = Fp2.sqr(t1);
  const t3 = Fp2.mul(t2, t1);
  const t4 = Fp2.mul(t2, Rx);
  const t5 = Fp2.add(Fp2.sub(t3, Fp2.mul(t4, 2n)), Fp2.mul(Fp2.sqr(t0), Rz));
  const nx = Fp2.mul(t1, t5);
  const ny = Fp2.sub(Fp2.mul(Fp2.sub(t4, t5), t0), Fp2.mul(t3, Ry));
  const nz = Fp2.mul(Rz, t3);
  return { coeffs: [c0, c1, c2], R: { x: nx, y: ny, z: nz } };
}

// ---- mul014 sparse Fp12 multiply (noble, M-twist) ----
// Fp6.mul1: (c0,c1,c2) * (b1 v) = (xi*c2*b1, c0*b1, c1*b1)
function fp6Mul1(x, b1) {
  return Fp6.create({
    c0: Fp2.mulByNonresidue(Fp2.mul(x.c2, b1)),
    c1: Fp2.mul(x.c0, b1),
    c2: Fp2.mul(x.c1, b1),
  });
}
function mul014(f, o0, o1, o4) {
  const t0 = Fp6.mul01(f.c0, o0, o1);
  const t1 = fp6Mul1(f.c1, o4);
  return Fp12.create({
    c0: Fp6.add(Fp6.mulByNonresidue(t1), t0),
    c1: Fp6.sub(Fp6.sub(Fp6.mul01(Fp6.add(f.c1, f.c0), o0, Fp2.add(o1, o4)), t0), t1),
  });
}
// M-twist line application: mul014(f, c0, c1*Px, c2*Py)
const lineFn = (f, c0, c1, c2, Px, Py) => mul014(f, c0, scalarFp2(c1, Px), scalarFp2(c2, Py));

// precompute per-step line coefficients for one G2 point (affine Qx,Qy)
function precompute(Qx, Qy) {
  const negQy = Fp2.neg(Qy);
  let R = { x: Qx, y: Qy, z: Fp2.ONE };
  const ell = [];
  for (const bit of ATE_NAF) {
    const cur = [];
    let d = pointDouble(R.x, R.y, R.z); R = d.R; cur.push(d.coeffs);
    if (bit) { let a = pointAdd(R.x, R.y, R.z, Qx, bit === -1 ? negQy : Qy); R = a.R; cur.push(a.coeffs); }
    ell.push(cur);
  }
  return ell; // no postPrecompute for BLS12-381
}

// batch Miller loop over pairs [{ell, Px, Py}]
function millerBatch(pairs) {
  let f = Fp12.ONE;
  const len = pairs[0].ell.length;
  for (let i = 0; i < len; i++) {
    f = Fp12.sqr(f);
    for (const { ell, Px, Py } of pairs) {
      for (const [c0, c1, c2] of ell[i]) f = lineFn(f, c0, c1, c2, Px, Py);
    }
  }
  return Fp12.conjugate(f); // xNegative = true for bls12-381
}

// ---------- validate against noble ----------
const G1 = bls12_381.G1.Point, G2 = bls12_381.G2.Point;

// single-pair check on the generators
{
  const P = G1.BASE, Q = G2.BASE;
  const Pa = P.toAffine(), Qa = Q.toAffine();
  const mine = millerBatch([{ ell: precompute(Qa.x, Qa.y), Px: Pa.x, Py: Pa.y }]);
  const ref = bls12_381.pairing(P, Q, false);
  console.log('single-pair (generators) miller == noble :', Fp12.eql(mine, ref));
}

// 4-pair batch on deterministic non-generator points
{
  const ks1 = [2n, 3n, 5n, 7n], ks2 = [11n, 13n, 17n, 19n];
  const pairs = [], groth = [];
  for (let i = 0; i < 4; i++) {
    const P = G1.BASE.multiply(ks1[i]), Q = G2.BASE.multiply(ks2[i]);
    const Pa = P.toAffine(), Qa = Q.toAffine();
    pairs.push({ ell: precompute(Qa.x, Qa.y), Px: Pa.x, Py: Pa.y });
    groth.push({ g1: P, g2: Q });
  }
  const mine = millerBatch(pairs);
  const ref = bls12_381.pairingBatch(groth, false);
  console.log('4-pair batch miller == noble boundary    :', Fp12.eql(mine, ref));
  console.log('finalExp(mine) == finalExp(noble)        :',
    Fp12.eql(Fp12.finalExponentiate(mine), Fp12.finalExponentiate(ref)));
}

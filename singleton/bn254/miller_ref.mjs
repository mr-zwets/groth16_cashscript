// JS SPEC for the BN254 optimal-ate Miller loop, reproducing noble's
// millerBoundary using OUR own orchestration (pointDouble / pointAdd / mul034 /
// NAF / postPrecompute) on noble's field primitives — the exact primitives our
// CashScript fp2/fp6/fp12 functions already match bit-for-bit. If this equals
// noble's pairing(.,.,false) and the 4-pair millerBoundary, the orchestration is
// correct and this file is the blueprint for the in-script Miller loop.
//
// Run: node singleton/pairing/miller_ref.mjs
import { readFileSync } from 'node:fs';

import { bn254 } from '@noble/curves/bn254.js';
const { Fp, Fp2, Fp6, Fp12 } = bn254.fields;

// ---- constants (extracted from noble) ----
const Fp2B = Fp2.fromBigTuple([
  19485874751759354771024239261021720505790618469301721065564631296452457478373n,
  266929791119991161246907387137283842545076965332900288569378510910307636690n,
]);
const XI = Fp2.NONRESIDUE;                       // (9,1)
const INV2 = Fp2.inv(Fp2.fromBigTuple([2n, 0n])); // 1/2 in Fp2
const PSI_X = Fp2.pow(XI, (Fp.ORDER - 1n) / 3n);
const PSI_Y = Fp2.pow(XI, (Fp.ORDER - 1n) / 2n);

const mulByB = (x) => Fp2.mul(x, Fp2B);
const scalarFp2 = (x, k) => Fp2.fromBigTuple([Fp.mul(x.c0, k), Fp.mul(x.c1, k)]); // Fp2 * Fp scalar

// ---- ate loop NAF of 6x+2 (noble NAfDecomposition) ----
const BN_X = 4965661367192848881n;
const ATE = 6n * BN_X + 2n;
function naf(a) {
  const res = [];
  for (; a > 1n; a >>= 1n) {
    if ((a & 1n) === 0n) res.unshift(0);
    else if ((a & 3n) === 3n) { res.unshift(-1); a += 1n; }
    else res.unshift(1);
  }
  return res;
}
const ATE_NAF = naf(ATE);

// ---- line steps (noble pointDouble / pointAdd, divisive twist) ----
// returns { coeffs: [c0,c1,c2], R: {x,y,z} } in Fp2 projective
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

// ---- mul034 sparse Fp12 multiply (noble) ----
function mul034(f, o0, o3, o4) {
  // A = f.c0 scaled by o0 (each Fp2 coord * o0)
  const A = Fp6.create({ c0: Fp2.mul(f.c0.c0, o0), c1: Fp2.mul(f.c0.c1, o0), c2: Fp2.mul(f.c0.c2, o0) });
  const B = Fp6.mul01(f.c1, o3, o4);
  const E = Fp6.mul01(Fp6.add(f.c0, f.c1), Fp2.add(o0, o3), o4);
  return Fp12.create({
    c0: Fp6.add(Fp6.mulByNonresidue(B), A),
    c1: Fp6.sub(E, Fp6.add(A, B)),
  });
}
// divisive-twist line application
const lineFn = (f, c0, c1, c2, Px, Py) => mul034(f, scalarFp2(c2, Py), scalarFp2(c1, Px), c0);

// psi (untwist-Frobenius-twist) for the Q1/Q2 postPrecompute
const psi = (x, y) => [Fp2.mul(Fp2.frobeniusMap(x, 1), PSI_X), Fp2.mul(Fp2.frobeniusMap(y, 1), PSI_Y)];

// precompute the per-step line coefficients for one G2 point (affine Qx,Qy)
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
  // postPrecompute: Q1 = psi(Q), Q2 = psi(Q1); add Q1, then add -Q2, both into the LAST step
  const q1 = psi(Qx, Qy);
  let a1 = pointAdd(R.x, R.y, R.z, q1[0], q1[1]); R = a1.R; ell[ell.length - 1].push(a1.coeffs);
  const q2 = psi(q1[0], q1[1]);
  let a2 = pointAdd(R.x, R.y, R.z, q2[0], Fp2.neg(q2[1])); ell[ell.length - 1].push(a2.coeffs);
  return ell;
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
  return f; // xNegative=false for bn254, no conjugate
}

// ---------- validate against noble ----------
const g1 = (o) => bn254.G1.Point.fromAffine({ x: BigInt(o.x), y: BigInt(o.y) });
const g2 = (o) => bn254.G2.Point.fromAffine({
  x: Fp2.fromBigTuple([BigInt(o.x.c0), BigInt(o.x.c1)]),
  y: Fp2.fromBigTuple([BigInt(o.y.c0), BigInt(o.y.c1)]),
});

// single-pair check on the generators
{
  const P = bn254.G1.Point.BASE, Q = bn254.G2.Point.BASE;
  const Pa = P.toAffine(), Qa = Q.toAffine();
  const mine = millerBatch([{ ell: precompute(Qa.x, Qa.y), Px: Pa.x, Py: Pa.y }]);
  const ref = bn254.pairing(P, Q, false);
  console.log('single-pair (generators) miller == noble :', Fp12.eql(mine, ref));
}

// 4-pair Groth16 boundary on the committed instance
const vec = JSON.parse(readFileSync('C:/Users/mathi/Desktop/verifier/src/checkpoints/pairing-vectors.json', 'utf8'));
const vk = { alpha: g1(vec.vk.alpha), beta: g2(vec.vk.beta), gamma: g2(vec.vk.gamma), delta: g2(vec.vk.delta), ic: vec.vk.ic.map(g1) };
const proof = { a: g1(vec.proof.a), b: g2(vec.proof.b), c: g1(vec.proof.c) };
const inputs = vec.publicInputs.map(BigInt);
let vkx = vk.ic[0];
for (let i = 0; i < inputs.length; i++) vkx = vkx.add(vk.ic[i + 1].multiply(inputs[i]));

const groth = [
  { g1: proof.a.negate(), g2: proof.b },
  { g1: vk.alpha, g2: vk.beta },
  { g1: vkx, g2: vk.gamma },
  { g1: proof.c, g2: vk.delta },
];
const pairs = groth.map(({ g1: P, g2: Q }) => {
  const Pa = P.toAffine(), Qa = Q.toAffine();
  return { ell: precompute(Qa.x, Qa.y), Px: Pa.x, Py: Pa.y };
});
const mineBoundary = millerBatch(pairs);
const refBoundary = bn254.pairingBatch(groth, false);
const millerHex = Buffer.from(Fp12.toBytes(mineBoundary)).toString('hex');
console.log('4-pair Groth16 miller == noble boundary    :', Fp12.eql(mineBoundary, refBoundary));
console.log('millerHex matches golden                   :', millerHex === vec.golden.millerHex);
console.log('finalExp(mine) == 1 (valid instance)       :', Fp12.eql(Fp12.finalExponentiate(mineBoundary), Fp12.ONE));

// Deterministic VALID BLS12-381 Groth16 instance, shared by miller4 / verify /
// groth16 / build_vectors. Constructed so the verification equation holds exactly:
//   e(-A,B) * e(alpha,beta) * e(vkx,gamma) * e(C,delta) == 1
// Using the standard exponent trick: with all points as scalar multiples of the
// generators (B = 1*G2), the product is e(g1,g2)^(-A + a*b + vx*g + c*d); choosing
// A = a*b + vx*g + c*d (mod r) makes the exponent 0, so the product is ONE and
// finalExp == 1. Tampering any public input changes vx -> verdict != 1.

import { bls12_381 } from '@noble/curves/bls12-381.js';
export { bls12_381 };
export const { Fp, Fp2, Fp12 } = bls12_381.fields;
const G1 = bls12_381.G1.Point, G2 = bls12_381.G2.Point;

// BLS12-381 scalar field order (group order r)
const R = 52435875175126190479447740508185965837690552500527637822603658699938581184513n;
const mod = (x) => ((x % R) + R) % R;

// fixed nonzero scalars + public inputs (deterministic)
const a = 3n, b = 5n, g = 7n, d = 11n, cS = 13n;
const ic = [2n, 4n, 6n];
export const PUBLIC_INPUTS = [123n, 456n];

const vx = mod(ic[0] + PUBLIC_INPUTS[0] * ic[1] + PUBLIC_INPUTS[1] * ic[2]);
const Ascalar = mod(a * b + vx * g + cS * d);

export const vk = {
  alpha: G1.BASE.multiply(a),
  beta: G2.BASE.multiply(b),
  gamma: G2.BASE.multiply(g),
  delta: G2.BASE.multiply(d),
  ic: ic.map((k) => G1.BASE.multiply(k)),
};
export const proof = {
  a: G1.BASE.multiply(Ascalar),
  b: G2.BASE,                 // 1 * G2
  c: G1.BASE.multiply(cS),
};

// vkx = IC0 + s0*IC1 + s1*IC2  (== vx * G1)
export function computeVkx(inputs) {
  let acc = vk.ic[0];
  inputs.forEach((s, i) => { acc = acc.add(vk.ic[i + 1].multiply(s)); });
  return acc;
}
export const vkx = computeVkx(PUBLIC_INPUTS);

// the 4 Groth16 pairs (G1, G2) for given vkx
export function grothPairs(vkxPoint) {
  return [
    { g1: proof.a.negate(), g2: proof.b },
    { g1: vk.alpha, g2: vk.beta },
    { g1: vkxPoint, g2: vk.gamma },
    { g1: proof.c, g2: vk.delta },
  ];
}

// affine arg row for miller4.cash spend: [Qx.c0,Qx.c1, Qy.c0,Qy.c1, Px, Py]
export function pairRow({ g1, g2 }) {
  const Pa = g1.toAffine(), Qa = g2.toAffine();
  return [Qa.x.c0, Qa.x.c1, Qa.y.c0, Qa.y.c1, Pa.x, Pa.y];
}

// noble Fp12 -> 12 limbs in toBytes order
export const f12 = (x) => [
  x.c0.c0.c0, x.c0.c0.c1, x.c0.c1.c0, x.c0.c1.c1, x.c0.c2.c0, x.c0.c2.c1,
  x.c1.c0.c0, x.c1.c0.c1, x.c1.c1.c0, x.c1.c1.c1, x.c1.c2.c0, x.c1.c2.c1,
];

// pre-final-exponentiation boundary (== noble millerLoopBatch(.,false))
export function boundaryFor(pairs) { return bls12_381.pairingBatch(pairs, false); }

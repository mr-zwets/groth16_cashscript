// JS SPEC for BN254 final exponentiation (p^12-1)/r, reproducing noble's
// Fp12.finalExponentiate with OUR orchestration on noble field primitives — the
// blueprint for the in-script final exp (checkpoint #3). Validated against noble
// on random Fp12 AND end-to-end on the committed Groth16 instance.
//
// Run: node singleton/pairing/finalexp_ref.mjs
import { readFileSync } from 'node:fs';

import { bn254 } from '@noble/curves/bn254.js';
const { Fp2, Fp12 } = bn254.fields;

const BN_X = 4965661367192848881n;
const X_LEN = BN_X.toString(2).length; // 63

// ---- cyclotomic squaring (noble _cyclotomicSquare via Fp4Square) ----
const fp4Square = (a, b) => {
  const a2 = Fp2.sqr(a);
  const b2 = Fp2.sqr(b);
  return {
    first: Fp2.add(Fp2.mulByNonresidue(b2), a2),
    second: Fp2.sub(Fp2.sub(Fp2.sqr(Fp2.add(a, b)), a2), b2),
  };
};
function cyclotomicSquare(f) {
  const { c0, c1 } = f;
  const c0c0 = c0.c0, c0c1 = c0.c1, c0c2 = c0.c2;
  const c1c0 = c1.c0, c1c1 = c1.c1, c1c2 = c1.c2;
  const { first: t3, second: t4 } = fp4Square(c0c0, c1c1);
  const { first: t5, second: t6 } = fp4Square(c1c0, c0c2);
  const { first: t7, second: t8 } = fp4Square(c0c1, c1c2);
  const t9 = Fp2.mulByNonresidue(t8);
  return Fp12.create({
    c0: { // 2*(Ti - c0ci) + Ti
      c0: Fp2.add(Fp2.mul(Fp2.sub(t3, c0c0), 2n), t3),
      c1: Fp2.add(Fp2.mul(Fp2.sub(t5, c0c1), 2n), t5),
      c2: Fp2.add(Fp2.mul(Fp2.sub(t7, c0c2), 2n), t7),
    },
    c1: { // 2*(Ti + c1ci) + Ti
      c0: Fp2.add(Fp2.mul(Fp2.add(t9, c1c0), 2n), t9),
      c1: Fp2.add(Fp2.mul(Fp2.add(t4, c1c1), 2n), t4),
      c2: Fp2.add(Fp2.mul(Fp2.add(t6, c1c2), 2n), t6),
    },
  });
}
function cyclotomicExp(num, n) {
  let z = Fp12.ONE;
  for (let i = X_LEN - 1; i >= 0; i--) {
    z = cyclotomicSquare(z);
    if ((n >> BigInt(i)) & 1n) z = Fp12.mul(z, num);
  }
  return z;
}
const powMinusX = (num) => Fp12.conjugate(cyclotomicExp(num, BN_X));

// ---- final exponentiation (noble Fp12finalExponentiate) ----
function finalExp(num) {
  const r0 = Fp12.mul(Fp12.conjugate(num), Fp12.inv(num)); // easy part: ^(p^6-1)
  const r = Fp12.mul(Fp12.frobeniusMap(r0, 2), r0);        // ^(p^2+1)
  const y1 = cyclotomicSquare(powMinusX(r));
  const y2 = Fp12.mul(cyclotomicSquare(y1), y1);
  const y4 = powMinusX(y2);
  const y6 = powMinusX(cyclotomicSquare(y4));
  const y8 = Fp12.mul(Fp12.mul(Fp12.conjugate(y6), y4), Fp12.conjugate(y2));
  const y9 = Fp12.mul(y8, y1);
  return Fp12.mul(
    Fp12.frobeniusMap(Fp12.mul(Fp12.conjugate(r), y9), 3),
    Fp12.mul(
      Fp12.frobeniusMap(y8, 2),
      Fp12.mul(Fp12.frobeniusMap(y9, 1), Fp12.mul(Fp12.mul(y8, y4), r))
    )
  );
}

// ---- validate vs noble on a random Fp12 ----
const a = Fp12.fromBigTwelve(Array.from({ length: 12 }, (_, i) => BigInt(7 + i * 131) % bn254.fields.Fp.ORDER));
console.log('finalExp(random) == noble :', Fp12.eql(finalExp(a), Fp12.finalExponentiate(a)));

// ---- end-to-end on the committed instance: finalExp(miller) == 1 (valid), != 1 (invalid) ----
const vec = JSON.parse(readFileSync('C:/Users/mathi/Desktop/verifier/src/checkpoints/pairing-vectors.json', 'utf8'));
const g1 = (o) => bn254.G1.Point.fromAffine({ x: BigInt(o.x), y: BigInt(o.y) });
const g2 = (o) => bn254.G2.Point.fromAffine({
  x: Fp2.fromBigTuple([BigInt(o.x.c0), BigInt(o.x.c1)]),
  y: Fp2.fromBigTuple([BigInt(o.y.c0), BigInt(o.y.c1)]),
});
const vk = { alpha: g1(vec.vk.alpha), beta: g2(vec.vk.beta), gamma: g2(vec.vk.gamma), delta: g2(vec.vk.delta), ic: vec.vk.ic.map(g1) };
const proof = { a: g1(vec.proof.a), b: g2(vec.proof.b), c: g1(vec.proof.c) };
const mk = (inputs) => {
  let vkx = vk.ic[0];
  for (let i = 0; i < inputs.length; i++) vkx = vkx.add(vk.ic[i + 1].multiply(inputs[i]));
  return bn254.pairingBatch([
    { g1: proof.a.negate(), g2: proof.b }, { g1: vk.alpha, g2: vk.beta },
    { g1: vkx, g2: vk.gamma }, { g1: proof.c, g2: vk.delta },
  ], false);
};
const validBoundary = mk(vec.publicInputs.map(BigInt));
const invalidBoundary = mk(vec.invalid.publicInputs.map(BigInt));
console.log('finalExp(valid miller)   == 1 :', Fp12.eql(finalExp(validBoundary), Fp12.ONE), '(golden', vec.golden.verified + ')');
console.log('finalExp(invalid miller) != 1 :', !Fp12.eql(finalExp(invalidBoundary), Fp12.ONE), '(golden', vec.golden.invalidVerified + ')');

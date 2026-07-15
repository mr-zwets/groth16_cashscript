import { bls12_381 } from '@noble/curves/bls12-381.js';

import {
  Fp, Fp2, Fp6, Fp12, millerBatchOps, pairsFor,
} from './_pairingmath.mjs';
import {
  A_COFACTOR, BLS_X, LAMBDA, ROOT27, fp12limbsOf,
  millerFusedOps, millerFusedTorusOps, residueTorusWitness,
} from './_residuemath.mjs';
import { LINKED_HIGH_COST_INPUTS } from './_residue_linked_plan.mjs';
import { PUBLIC_INPUTS, proof } from '../../singleton/bls12-381/bls_instance.mjs';

const r = bls12_381.fields.Fr.ORDER;
const p = Fp.ORDER;
const quotientOrder = p ** 6n + 1n;
const finalExponent = (p ** 12n - 1n) / r;
const gcd = (a, b) => {
  while (b !== 0n) [a, b] = [b, a % b];
  return a;
};
const assert = (condition, message) => {
  if (!condition) throw new Error(message);
};
const projective = (x, y) => Fp12.create({ c0: x, c1: y });
const torus = (u) => projective(Fp6.ONE, u);
const scale = (value, scalar) => projective(
  Fp6.mul(value.c0, scalar),
  Fp6.mul(value.c1, scalar),
);
const isZero6 = (value) => Fp6.eql(value, Fp6.ZERO);
const classEqual = (a, b) => Fp6.eql(
  Fp6.mul(a.c0, b.c1),
  Fp6.mul(a.c1, b.c0),
);
const projectiveSquare = (value) => projective(
  Fp6.add(Fp6.sqr(value.c0), Fp6.mulByNonresidue(Fp6.sqr(value.c1))),
  Fp6.mul(Fp6.mul(value.c0, value.c1), 2n),
);
const projectiveTorusMul = (value, u) => projective(
  Fp6.add(value.c0, Fp6.mulByNonresidue(Fp6.mul(value.c1, u))),
  Fp6.add(value.c1, Fp6.mul(value.c0, u)),
);

// Q=Fp12*/Fp6* is cyclic of order p^6+1. The lambda-power image and final-exponent kernel
// both have order (p^6+1)/r, so they are the same subgroup. The larger full-field gcd is harmless:
// its extra factor and the residue correction are contained in Fp6 and disappear in Q.
assert(LAMBDA === p + BLS_X, 'BLS12-381 residue exponent changed');
assert(quotientOrder % r === 0n, 'r does not divide the quotient-torus order');
assert(gcd(r, p ** 6n - 1n) === 1n, 'r unexpectedly intersects Fp6*');
assert(gcd(LAMBDA, quotientOrder) === r, 'lambda does not have the required quotient gcd');
assert(gcd(finalExponent, quotientOrder) === quotientOrder / r, 'final-exponent kernel has wrong size');
assert(gcd(LAMBDA, p ** 12n - 1n) === 3n * r * A_COFACTOR, 'full-field residue gcd changed');
assert(isZero6(ROOT27.c1), 'the residue correction is not discarded by Fp6 quotienting');

// A fixed nontrivial r-th root supplies a complete finite-chart fallback.
const kernelShift = bls12_381.pairing(
  bls12_381.G1.Point.BASE,
  bls12_381.G2.Point.BASE,
);
assert(Fp12.eql(Fp12.pow(kernelShift, r), Fp12.ONE), 'kernel shift is not r-torsion');
assert(Fp12.eql(Fp12.pow(kernelShift, LAMBDA), Fp12.ONE), 'kernel shift changes the lambda power');
assert(!isZero6(kernelShift.c1), 'kernel shift cannot leave the infinity chart');
const infinity = projective(Fp6.ZERO, Fp6.ONE);
assert(!isZero6(Fp12.mul(infinity, kernelShift).c0), 'kernel shift did not move infinity to a finite chart');

const frobeniusK1 = Fp2.fromBigTuple([
  0n,
  4002409555221667392624310435006688643935503118305586438271171395842971157480381377015405980053539358417135540939436n,
]);
const frobeniusK2 = Fp2.fromBigTuple([
  4002409555221667392624310435006688643935503118305586438271171395842971157480381377015405980053539358417135540939437n,
  0n,
]);
const frobeniusW = Fp2.fromBigTuple([
  3850754370037169011952147076051364057158807420970682438676050522613628423219637725072182697113062777891589506424760n,
  151655185184498381465642749684540099398075398968325446656007613510403227271200139370504932015952886146304766135027n,
]);
const conjugate2 = (value) => Fp2.create({ c0: value.c0, c1: Fp.neg(value.c1) });
const torusFrob1 = (value) => Fp6.create({
  c0: Fp2.mul(conjugate2(value.c0), frobeniusW),
  c1: Fp2.mul(Fp2.mul(conjugate2(value.c1), frobeniusK1), frobeniusW),
  c2: Fp2.mul(Fp2.mul(conjugate2(value.c2), frobeniusK2), frobeniusW),
});

let seed = 0x626c733132333831n;
const next = () => {
  seed = BigInt.asUintN(64, seed + 0x9e3779b97f4a7c15n);
  let z = seed;
  z = BigInt.asUintN(64, (z ^ (z >> 30n)) * 0xbf58476d1ce4e5b9n);
  z = BigInt.asUintN(64, (z ^ (z >> 27n)) * 0x94d049bb133111ebn);
  return z ^ (z >> 31n);
};
const randomFp = () => {
  let value = 0n;
  for (let i = 0; i < 6; i++) value = (value << 64n) | next();
  return value % p;
};
const random6 = () => Fp6.fromBigSix(Array.from({ length: 6 }, randomFp));

for (let i = 0; i < 6; i++) {
  const basis = Fp6.fromBigSix(Array.from({ length: 6 }, (_, j) => i === j ? 1n : 0n));
  assert(
    Fp6.eql(torusFrob1(basis), Fp12.frobeniusMap(torus(basis), 1).c1),
    `specialized q Frobenius basis mismatch ${i}`,
  );
}

for (let i = 0; i < 128; i++) {
  const value = Fp12.fromBigTwelve(Array.from({ length: 12 }, randomFp));
  let scalar = random6();
  if (isZero6(scalar)) scalar = Fp6.ONE;
  const u = random6();
  assert(classEqual(value, scale(value, scalar)), `Fp6 scaling changed class ${i}`);
  assert(classEqual(projectiveSquare(value), Fp12.sqr(value)), `projective square mismatch ${i}`);
  assert(classEqual(projectiveTorusMul(value, u), Fp12.mul(value, torus(u))), `finite fold mismatch ${i}`);
  assert(
    classEqual(projectiveTorusMul(value, Fp6.neg(u)), Fp12.mul(value, Fp12.inv(torus(u)))),
    `inverse fold mismatch ${i}`,
  );
  assert(
    Fp12.eql(Fp12.finalExponentiate(value), Fp12.finalExponentiate(scale(value, scalar))),
    `final exponent changed under Fp6 scale ${i}`,
  );
  assert(
    Fp6.eql(torusFrob1(u), Fp12.frobeniusMap(torus(u), 1).c1),
    `specialized q Frobenius mismatch ${i}`,
  );
}

assert(classEqual(projectiveSquare(infinity), Fp12.ONE), 'infinity square is not the identity class');
assert(classEqual(projectiveTorusMul(infinity, Fp6.ZERO), infinity), 'identity fold changed infinity');
let exceptionalU = random6();
while (isZero6(exceptionalU)) exceptionalU = random6();
const exceptionalT = Fp6.neg(Fp6.inv(Fp6.mulByNonresidue(exceptionalU)));
const exceptionalProduct = projectiveTorusMul(torus(exceptionalT), exceptionalU);
assert(
  isZero6(exceptionalProduct.c0) && !isZero6(exceptionalProduct.c1),
  'zero affine denominator did not map to infinity',
);

const G1 = bls12_381.G1.Point;
const modR = (value) => ((value % r) + r) % r;
const makeInstance = (inputs) => {
  const [input0, input1] = inputs.map(BigInt);
  const vkxScalar = modR(2n + input0 * 4n + input1 * 6n);
  const aScalar = modR(3n * 5n + vkxScalar * 7n + 13n * 11n);
  return { inputs, proof: { a: G1.BASE.multiply(aScalar), b: proof.b, c: proof.c } };
};
const instances = [
  { label: 'committed', inputs: PUBLIC_INPUTS, proof },
  { label: 'alternate', ...makeInstance([135208n, 67633n]) },
  { label: 'dense', ...makeInstance(LINKED_HIGH_COST_INPUTS) },
];

for (const instance of instances) {
  const pairs = pairsFor(instance.inputs, instance.proof);
  const rawBoundary = millerBatchOps(pairs).boundary;
  const root = residueTorusWitness(rawBoundary);
  assert(!isZero6(root.c.c0), `${instance.label}: residue root is outside the finite chart`);
  assert(
    fp12limbsOf(root.w).slice(6).every((limb) => limb === 0n),
    `${instance.label}: residue correction survives quotienting`,
  );

  const exact = millerFusedOps(pairs, root.c, root.cInv);
  const quotient = millerFusedTorusOps(pairs, root.c, root.cInv, root.u);
  assert(exact.ops.length === quotient.ops.length, `${instance.label}: trace length changed`);
  for (let i = 0; i < quotient.states.length; i++) {
    assert(
      classEqual(quotient.states[i].f, exact.states[i].f),
      `${instance.label}: quotient trace class mismatch at state ${i}`,
    );
  }

  const expected = Fp12.frobeniusMap(torus(root.u), 1);
  assert(classEqual(quotient.boundary, expected), `${instance.label}: quotient terminal rejected valid trace`);
  assert(
    !classEqual(Fp12.mul(quotient.boundary, kernelShift), expected),
    `${instance.label}: quotient terminal accepted a non-Fp6 class mutation`,
  );
  let tailScale = random6();
  if (isZero6(tailScale)) tailScale = Fp6.ONE;
  assert(classEqual(scale(quotient.boundary, tailScale), expected), `${instance.label}: Fp6 scale changed verdict`);
}

console.log('BLS12-381 quotient-torus proof: PASS');
console.log(`  gcd(lambda, p^6+1) = r (${r})`);
console.log(`  full-field gcd = 3*r*A (${3n * r * A_COFACTOR})`);
console.log(`  exact fused traces checked: ${instances.length} x 277 ops`);
console.log('  projective/random/exceptional transitions checked: 128 + infinity + zero-denominator');
console.log('  specialized Frobenius checked: 6 basis vectors + 128 deterministic random vectors');

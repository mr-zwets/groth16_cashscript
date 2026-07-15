import { bn254 } from '@noble/curves/bn254.js';

import {
  BN_X, Fp, Fp2, Fp6, Fp12, pairsFor, vec,
} from './_millermath.mjs';
import {
  ROOT27, fp12limbsOf, millerFusedAffineOps, residueWitness,
} from './_residuemath.mjs';

const r = bn254.fields.Fr.ORDER;
const p = Fp.ORDER;
const quotientOrder = p ** 6n + 1n;
const lambda = 6n * BN_X + 2n + p - p ** 2n + p ** 3n;
const finalExponent = (p ** 12n - 1n) / r;
const gcd = (a, b) => {
  while (b !== 0n) [a, b] = [b, a % b];
  return a;
};
const projective = (x, y) => Fp12.create({ c0: x, c1: y });
const torus = (u) => projective(Fp6.ONE, u);
const scale = (value, scalar) => projective(
  Fp6.mul(value.c0, scalar), Fp6.mul(value.c1, scalar),
);
const isZero6 = (value) => Fp6.eql(value, Fp6.ZERO);
const classEqual = (a, b) => Fp6.eql(
  Fp6.mul(a.c0, b.c1), Fp6.mul(a.c1, b.c0),
);
const projectiveSquare = (value) => projective(
  Fp6.add(Fp6.sqr(value.c0), Fp6.mulByNonresidue(Fp6.sqr(value.c1))),
  Fp6.mul(Fp6.mul(value.c0, value.c1), 2n),
);
const projectiveTorusMul = (value, u) => projective(
  Fp6.add(value.c0, Fp6.mulByNonresidue(Fp6.mul(value.c1, u))),
  Fp6.add(value.c1, Fp6.mul(value.c0, u)),
);
const assert = (condition, message) => {
  if (!condition) throw new Error(message);
};

// Q = Fp12*/Fp6* is cyclic of order p^6+1. The final-exponent kernel and the
// lambda-power image both have order (p^6+1)/r, so they are the same subgroup.
assert(quotientOrder % r === 0n, 'r does not divide the quotient-torus order');
assert(gcd(r, p ** 6n - 1n) === 1n, 'r unexpectedly intersects Fp6*');
assert(gcd(lambda, quotientOrder) === r, 'lambda does not have the required quotient gcd');
assert(gcd(finalExponent, quotientOrder) === quotientOrder / r, 'final-exponent kernel has wrong size');
assert(gcd(lambda, p ** 12n - 1n) === 3n * r, 'full-field residue gcd changed');
// W denotes the Fp12/Fp6 tower basis. The old residue-coset correction w is ROOT27;
// it lies in Fp6 and therefore vanishes after quotienting by Fp6*.
assert(isZero6(ROOT27.c1), 'the residue correction w is not discarded by Fp6 quotienting');

// A fixed nontrivial r-th root supplies a deterministic finite-chart fallback.
// If a valid root c is the unique infinity point, c*k has the same lambda power
// and finite c0 because k.c1 != 0.
const kernelShift = bn254.pairing(bn254.G1.Point.BASE, bn254.G2.Point.BASE);
assert(Fp12.eql(Fp12.pow(kernelShift, r), Fp12.ONE), 'kernel shift is not r-torsion');
assert(Fp12.eql(Fp12.pow(kernelShift, lambda), Fp12.ONE), 'kernel shift changes the lambda power');
assert(!isZero6(kernelShift.c1), 'kernel shift cannot leave the infinity chart');
const infinity = projective(Fp6.ZERO, Fp6.ONE);
assert(!isZero6(Fp12.mul(infinity, kernelShift).c0), 'kernel shift did not move infinity to a finite chart');

let seed = 0x746f727573n;
const next = () => {
  seed = BigInt.asUintN(64, seed + 0x9e3779b97f4a7c15n);
  let z = seed;
  z = BigInt.asUintN(64, (z ^ (z >> 30n)) * 0xbf58476d1ce4e5b9n);
  z = BigInt.asUintN(64, (z ^ (z >> 27n)) * 0x94d049bb133111ebn);
  return z ^ (z >> 31n);
};
const randomFp = () => {
  let value = 0n;
  for (let i = 0; i < 4; i++) value = (value << 64n) | next();
  return value % p;
};
const random6 = () => Fp6.fromBigSix(Array.from({ length: 6 }, randomFp));
const mod = (value) => (value % p + p) % p;
const mul2 = ([a0, a1], [b0, b1]) => [
  mod(a0 * b0 - a1 * b1),
  mod(a0 * b1 + a1 * b0),
];
const torusFrob1 = (value) => {
  const limbs = fp12limbsOf(projective(Fp6.ZERO, value)).slice(6);
  const conjugate = (offset) => [limbs[offset], mod(-limbs[offset + 1])];
  const k1 = [
    21575463638280843010398324269430826099269044274347216827212613867836435027261n,
    10307601595873709700152284273816112264069230130616436755625194854815875713954n,
  ];
  const k2 = [
    2581911344467009335267311115468803099551665605076196740867805258568234346338n,
    19937756971775647987995932169929341994314640652964949448313374472400716661030n,
  ];
  const w = [
    8376118865763821496583973867626364092589906065868298776909617916018768340080n,
    16469823323077808223889137241176536799009286646108169935659301613961712198316n,
  ];
  return Fp6.fromBigSix([
    ...mul2(conjugate(0), w),
    ...mul2(mul2(conjugate(2), k1), w),
    ...mul2(mul2(conjugate(4), k2), w),
  ]);
};
const torusFrob2 = (value) => {
  const limbs = fp12limbsOf(projective(Fp6.ZERO, value)).slice(6);
  const c0 = 21888242871839275220042445260109153167277707414472061641714758635765020556617n;
  const c2 = 2203960485148121921418603742825762020974279258880205651967n;
  return Fp6.fromBigSix([
    mod(limbs[0] * c0), mod(limbs[1] * c0),
    mod(-limbs[2]), mod(-limbs[3]),
    mod(limbs[4] * c2), mod(limbs[5] * c2),
  ]);
};
const frob2Neg = 2203960485148121921418603742825762020974279258880205651966n;
const frob2Pos = 2203960485148121921418603742825762020974279258880205651967n;
const signedMod = (value) => value % p;
const shortSignedFrob2 = (limbs) => [
  -signedMod(limbs[0] * frob2Neg),
  -signedMod(limbs[1] * frob2Neg),
  -limbs[2],
  -limbs[3],
  signedMod(limbs[4] * frob2Pos),
  signedMod(limbs[5] * frob2Pos),
];
const genericFrob2 = (limbs) => [
  signedMod(limbs[0] * (p - frob2Neg)),
  signedMod(limbs[1] * (p - frob2Neg)),
  signedMod(64n * p - limbs[2]),
  signedMod(64n * p - limbs[3]),
  signedMod(limbs[4] * frob2Pos),
  signedMod(limbs[5] * frob2Pos),
];

for (let i = 0; i < 6; i++) {
  const basis = Fp6.fromBigSix(Array.from({ length: 6 }, (_, j) => i === j ? 1n : 0n));
  const direct1 = Fp12.frobeniusMap(torus(basis), 1).c1;
  const direct2 = Fp12.frobeniusMap(torus(basis), 2).c1;
  const direct3 = Fp12.frobeniusMap(torus(basis), 3).c1;
  const cash1 = torusFrob1(basis);
  assert(Fp6.eql(cash1, direct1), `specialized q Frobenius basis mismatch ${i}`);
  assert(Fp6.eql(torusFrob2(basis), direct2), `specialized q^2 Frobenius basis mismatch ${i}`);
  assert(Fp6.eql(torusFrob2(cash1), direct3), `composed q^3 Frobenius basis mismatch ${i}`);
}

for (let i = 0; i < 128; i++) {
  const value = Fp12.fromBigTwelve(Array.from({ length: 12 }, randomFp));
  let scalar = random6();
  if (isZero6(scalar)) scalar = Fp6.ONE;
  const u = random6();
  assert(classEqual(value, scale(value, scalar)), `Fp6 scaling changed class ${i}`);
  assert(classEqual(projectiveSquare(value), Fp12.sqr(value)), `projective square mismatch ${i}`);
  assert(classEqual(projectiveTorusMul(value, u), Fp12.mul(value, torus(u))), `finite fold mismatch ${i}`);
  assert(classEqual(projectiveTorusMul(value, Fp6.neg(u)), Fp12.mul(value, Fp12.inv(torus(u)))), `inverse fold mismatch ${i}`);
  assert(Fp12.eql(Fp12.finalExponentiate(value), Fp12.finalExponentiate(scale(value, scalar))), `final exponent changed under Fp6 scale ${i}`);
  const direct2 = Fp12.frobeniusMap(torus(u), 2).c1;
  const direct1 = Fp12.frobeniusMap(torus(u), 1).c1;
  const direct3 = Fp12.frobeniusMap(torus(u), 3).c1;
  const cash1 = torusFrob1(u);
  assert(Fp6.eql(cash1, direct1), `specialized q Frobenius mismatch ${i}`);
  assert(Fp6.eql(torusFrob2(u), direct2), `specialized q^2 Frobenius mismatch ${i}`);
  assert(Fp6.eql(torusFrob2(cash1), direct3), `composed q^3 Frobenius mismatch ${i}`);
}

for (let i = 0; i < 256; i++) {
  const limbs = Array.from({ length: 6 }, () => randomFp() - randomFp());
  const short = shortSignedFrob2(limbs);
  const generic = genericFrob2(limbs);
  for (let limb = 0; limb < 6; limb++) {
    assert(mod(short[limb]) === mod(generic[limb]), `short signed q^2 mismatch ${i}:${limb}`);
    assert(short[limb] > -p && short[limb] < p, `short signed q^2 output bound failed ${i}:${limb}`);
    if (limb < 2 || limb > 3) {
      const coefficient = limb < 2 ? frob2Neg : frob2Pos;
      const product = limbs[limb] * coefficient;
      assert(product > -(p ** 2n) && product < p ** 2n, `short signed q^2 product bound failed ${i}:${limb}`);
    }
  }
}

assert(classEqual(projectiveSquare(infinity), Fp12.ONE), 'infinity square is not the identity class');
assert(classEqual(projectiveTorusMul(infinity, Fp6.ZERO), infinity), 'identity fold changed infinity');
let exceptionalU = random6();
while (isZero6(exceptionalU)) exceptionalU = random6();
const vU = Fp6.mulByNonresidue(exceptionalU);
const exceptionalT = Fp6.neg(Fp6.inv(vU));
const exceptionalProduct = projectiveTorusMul(torus(exceptionalT), exceptionalU);
assert(isZero6(exceptionalProduct.c0) && !isZero6(exceptionalProduct.c1), 'zero affine denominator did not map to infinity');

// Trace the committed generic verifier algebra. Every candidate state may differ
// from the exact trace by an arbitrary nonzero Fp6 scale, but no other difference.
const pairs = pairsFor(vec.publicInputs);
const unfused = millerFusedAffineOps(pairs, Fp12.ONE, Fp12.ONE, { unitLines: true });
const { c } = residueWitness(unfused.boundary);
const finiteC = isZero6(c.c0) ? Fp12.mul(c, kernelShift) : c;
if (isZero6(finiteC.c0)) throw new Error('quotient point is in the infinity chart');
const u = Fp6.mul(finiteC.c1, Fp6.inv(finiteC.c0));
const exact = millerFusedAffineOps(pairs, finiteC, Fp12.inv(finiteC), { unitLines: true });
let candidate = torus(Fp6.neg(u));
assert(classEqual(candidate, exact.states[0].f), 'genesis cInv class mismatch');
for (let i = 0; i < exact.ops.length; i++) {
  const op = exact.ops[i];
  if (op.t === 'sqr') candidate = projectiveSquare(candidate);
  else if (op.t === 'cf') candidate = projectiveTorusMul(candidate, op.neg ? u : Fp6.neg(u));
  else if (op.t === 'cmul1') candidate = Fp12.mul(candidate, exact.fAB);
  else {
    const factor = Fp12.mul(exact.states[i + 1].f, Fp12.inv(exact.states[i].f));
    candidate = Fp12.mul(candidate, factor);
  }
  assert(classEqual(candidate, exact.states[i + 1].f), `trace class mismatch after op ${i} (${op.t})`);
}

const cRep = torus(u);
const lhs = Fp12.mul(candidate, Fp12.frobeniusMap(cRep, 2));
const rhs = Fp12.mul(Fp12.frobeniusMap(cRep, 1), Fp12.frobeniusMap(cRep, 3));
assert(classEqual(lhs, rhs), 'quotient residue tail rejected the valid trace');
assert(!classEqual(Fp12.mul(lhs, kernelShift), rhs), 'quotient residue tail accepted a non-Fp6 class mutation');
const tailScale = random6();
assert(!isZero6(tailScale), 'deterministic tail scale was zero');
assert(classEqual(scale(lhs, tailScale), rhs), 'quotient residue tail rejected an Fp6 scale');

console.log('BN254 quotient-torus proof: PASS');
console.log(`  gcd(lambda, p^6+1) = r (${r})`);
console.log(`  exact fused trace checked: ${exact.ops.length} ops (${exact.ops.filter((op) => op.t === 'cf').length} c-folds)`);
console.log(`  projective/random/exceptional transitions checked: 128 + infinity + zero-denominator`);
console.log('  specialized Frobenius checked: 6 basis vectors + 128 deterministic random vectors');
console.log('  short signed q^2 coefficients checked: 256 deterministic signed vectors');
console.log(`  finite residue coordinate limbs: ${fp12limbsOf(cRep).slice(6).length}`);

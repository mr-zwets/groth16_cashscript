// Executable equivalence/completeness checks for Py-normalized o0=1 Miller lines.
//
// Runtime G1 state stores u=-Px/Py and v=-1/Py. For a line (c0,c1,c2), fixed lines are
// normalized offline by -1/c2, while affine runtime-B lines already have c2=-1. Therefore
//   (1, c1' * u, c0' * v) = (c2*Py, c1*Px, c0) / (c2*Py).
// Every scale is in Fp2*. Products and Miller squarings keep the aggregate scale in Fp2*, and
// p^2-1 divides (p^12-1)/r, so the scale vanishes in final exponentiation.

import {
  bn254, Fp, Fp2, Fp12, BN_X, PT_CFG, pairsFor, proof, vec,
} from './_millermath.mjs';
import {
  eq12, millerFusedOps, millerFusedAffineOps,
} from './_residuemath.mjs';

const P = Fp.ORDER;
const R = bn254.fields.Fr.ORDER;
if (((P ** 12n - 1n) / R) % (P ** 2n - 1n) !== 0n) {
  throw new Error('Fp2 unit-line scales do not vanish in final exponentiation');
}

const committedPairs = pairsFor(vec.publicInputs, proof);
const raw = millerFusedOps(committedPairs, Fp12.ONE, Fp12.ONE);
let fixedLines = 0;
for (const op of raw.ops) {
  if (op.j !== 2 && op.j !== 3) continue;
  const triples = op.t === 'pp' ? op.coeffs : [op.coeffs];
  for (const coeffs of triples) {
    if (Fp2.eql(coeffs[2], Fp2.ZERO)) throw new Error('fixed Miller line has zero c2');
    fixedLines += 1;
  }
}
if (fixedLines !== 176) throw new Error(`expected 176 fixed lines, got ${fixedLines}`);

const wrapX = P - 1n;
const wrapPoint = bn254.G1.Point.fromAffine({ x: wrapX, y: Fp.sqrt(2n) });
wrapPoint.assertValidity();
const cases = [
  { label: 'committed', inputs: vec.publicInputs, proof },
  ...[2n, 7n, BN_X].map((scalar) => ({
    label: `scaled-${scalar}`,
    inputs: vec.publicInputs,
    proof: {
      a: proof.a.multiply(bn254.fields.Fr.inv(scalar)),
      b: proof.b.multiply(scalar),
      c: proof.c,
    },
  })),
  { label: 'wrap-a', inputs: vec.publicInputs, proof: { a: wrapPoint.negate(), b: proof.b, c: proof.c } },
  { label: 'wrap-c', inputs: vec.publicInputs, proof: { a: proof.a, b: proof.b, c: wrapPoint } },
  { label: 'dense-inputs', inputs: [R - 1n, R - 2n], proof },
];

for (const testCase of cases) {
  const pairs = pairsFor(testCase.inputs, testCase.proof);
  for (let j = 0; j < pairs.length; j++) {
    if (!PT_CFG[j].P) continue;
    const point = pairs[j].P.toAffine();
    if (point.y === 0n) throw new Error(`${testCase.label} has a zero runtime Py`);
    const invY = Fp.inv(point.y);
    const u = Fp.neg(Fp.mul(point.x, invY));
    const v = Fp.neg(invY);
    if (Fp.add(Fp.mul(u, point.y), point.x) !== 0n || Fp.add(Fp.mul(v, point.y), 1n) !== 0n) {
      throw new Error(`${testCase.label} signed P normalization failed`);
    }
  }
  const affine = millerFusedAffineOps(pairs, Fp12.ONE, Fp12.ONE).boundary;
  const unitTrace = millerFusedAffineOps(
    pairs,
    Fp12.ONE,
    Fp12.ONE,
    { unitLines: true },
  );
  const quotient = Fp12.mul(unitTrace.boundary, Fp12.inv(affine));
  if (!eq12(Fp12.frobeniusMap(quotient, 2), quotient)) {
    throw new Error(`${testCase.label} unit/affine quotient is not in Fp2`);
  }
  for (const op of unitTrace.ops) {
    if (op.j !== 2 && op.j !== 3) continue;
    const triples = op.t === 'pp' ? op.coeffs : [op.coeffs];
    if (triples.some((coeffs) => !Fp2.eql(coeffs[2], Fp2.ONE))) {
      throw new Error(`${testCase.label} fixed line was not normalized to c2=1`);
    }
  }
}

console.log('Miller unit-line proof passed');
console.log('176 fixed c2 values are nonzero; all runtime Py values are invertible');
console.log(`${cases.length} affine/unit traces differ only by Fp2*; p^2-1 divides the final exponent`);

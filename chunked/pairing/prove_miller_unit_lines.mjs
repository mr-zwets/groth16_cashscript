// Executable equivalence/completeness checks for Py-normalized o0=1 Miller lines.
//
// Runtime G1 state stores u=-Px/Py and v=-1/Py. For a line (c0,c1,c2), fixed lines are
// normalized offline by -1/c2, while affine runtime-B lines already have c2=-1. Therefore
//   (1, c1' * u, c0' * v) = (c2*Py, c1*Px, c0) / (c2*Py).
// Every scale is in Fp2*. Products and Miller squarings keep the aggregate scale in Fp2*, and
// p^2-1 divides (p^12-1)/r, so the scale vanishes in final exponentiation.

import {
  bn254, Fp, Fp2, Fp12, BN_X, PT_CFG, lineUnitFn, pairsFor, proof, vec,
} from './_millermath.mjs';
import {
  eq12, millerFusedOps, millerFusedAffineOps,
} from './_residuemath.mjs';

const P = Fp.ORDER;
const R = bn254.fields.Fr.ORDER;
const G1_CURVE = bn254.G1.Point.CURVE();
if (G1_CURVE.h !== 1n || G1_CURVE.n !== R || (R & 1n) === 0n) {
  throw new Error('normalized G1 proof requires a cofactor-one odd-order group');
}
if (((P ** 12n - 1n) / R) % (P ** 2n - 1n) !== 0n) {
  throw new Error('Fp2 unit-line scales do not vanish in final exponentiation');
}

// Over Fp, every finite G1 point has y!=0 because G1 has odd order and hence no
// nontrivial 2-torsion. Its canonical encoding u=-x/y,v=-1/y satisfies
// v=u^3+3v^3. Conversely, v!=0 recovers the unique x=u/v,y=-1/v; if v=0,
// the relation forces u^3=0 and therefore u=0. Thus (0,0) is the only remaining
// solution and represents the identity.
const assertNormalizedRoundTrip = (point, label) => {
  if (point.equals(bn254.G1.Point.ZERO)) {
    const u = 0n, v = 0n;
    if (Fp.sub(v, Fp.add(Fp.mul(Fp.sqr(u), u), Fp.mul(3n, Fp.mul(Fp.sqr(v), v)))) !== 0n) {
      throw new Error(`${label} normalized identity does not satisfy the curve relation`);
    }
    return;
  }
  const affine = point.toAffine();
  if (affine.y === 0n) throw new Error(`${label} has a finite zero-Y G1 point`);
  const yInv = Fp.inv(affine.y);
  const u = Fp.neg(Fp.mul(affine.x, yInv));
  const v = Fp.neg(yInv);
  const u3 = Fp.mul(Fp.sqr(u), u);
  const v3 = Fp.mul(Fp.sqr(v), v);
  if (Fp.sub(v, Fp.add(u3, Fp.mul(3n, v3))) !== 0n) {
    throw new Error(`${label} normalized coordinates fail v=u^3+3v^3`);
  }
  const vInv = Fp.inv(v);
  if (Fp.mul(u, vInv) !== affine.x || Fp.neg(vInv) !== affine.y) {
    throw new Error(`${label} normalized coordinates do not uniquely recover the point`);
  }
};
assertNormalizedRoundTrip(bn254.G1.Point.ZERO, 'identity');
for (let scalar = 1n; scalar <= 128n; scalar += 1n) {
  assertNormalizedRoundTrip(bn254.G1.Point.BASE.multiplyUnsafe(scalar), `G1 scalar ${scalar}`);
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
let zeroUnitLineChecks = 0;

for (const testCase of cases) {
  const pairs = pairsFor(testCase.inputs, testCase.proof);
  for (let j = 0; j < pairs.length; j++) {
    if (!PT_CFG[j].P) continue;
    assertNormalizedRoundTrip(pairs[j].P, `${testCase.label} pair ${j}`);
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
    if (op.j === undefined || !PT_CFG[op.j].P) continue;
    const triples = op.t === 'pp' ? op.coeffs : [op.coeffs];
    if (op.j !== 0 && triples.some((coeffs) => !Fp2.eql(coeffs[2], Fp2.ONE))) {
      throw new Error(`${testCase.label} runtime G1 line was not normalized to c2=1`);
    }
    for (const coeffs of triples) {
      for (const state of [Fp12.ONE, raw.boundary, unitTrace.boundary]) {
        if (!Fp12.eql(lineUnitFn(state, coeffs[0], coeffs[1], 0n, 0n), state)) {
          throw new Error(`${testCase.label} zero-unit line changed the Miller accumulator`);
        }
        zeroUnitLineChecks += 1;
      }
    }
  }
}

console.log('Miller unit-line proof passed');
console.log('176 fixed c2 values are nonzero; all runtime Py values are invertible');
console.log(`normalized G1 identity plus 128 scalar points round-trip; ${zeroUnitLineChecks} zero-unit line applications are exact identities`);
console.log(`${cases.length} affine/unit traces differ only by Fp2*; p^2-1 divides the final exponent`);

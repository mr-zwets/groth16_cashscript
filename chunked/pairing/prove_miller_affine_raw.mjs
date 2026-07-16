// Differential and interval certificate for Bn254Lazy.cash::pointDoubleAffineRaw and
// pointAddAffineRaw. It replays the exact unreduced integer formulas across four complete
// runtime-G2 Miller traces, then proves every possible canonical input remains below
// 8p^2 and therefore within 64 BCH VM-number bytes.

import {
  bn254, Fp, Fp2, BN_X, pairsFor, proof, psi, vec,
} from './_millermath.mjs';
import { millerFusedAffineOps } from './_residuemath.mjs';

const P = Fp.ORDER;
const modP = (value) => ((value % P) + P) % P;
const eq2 = (a, b) => Fp2.eql(a, b);
const canonical2 = (a) => Fp2.fromBigTuple([modP(a.c0), modP(a.c1)]);

let concreteMaxAbs = 0n;
const recordConcrete = (...values) => {
  for (const value of values) {
    const absolute = value < 0n ? -value : value;
    if (absolute > concreteMaxAbs) concreteMaxAbs = absolute;
  }
};
const fp2RawMul = (a, b, record) => {
  const v0 = a.c0 * b.c0;
  const v1 = a.c1 * b.c1;
  const aSum = a.c0 + a.c1;
  const bSum = b.c0 + b.c1;
  const cross = aSum * bSum;
  record(v0, v1, aSum, bSum, cross, cross - v0, v0 - v1, cross - v0 - v1);
  return { c0: v0 - v1, c1: cross - v0 - v1 };
};
const fp2RawSqr = (a, record) => {
  const sum = a.c0 + a.c1;
  const difference = a.c0 - a.c1;
  const twice = a.c0 + a.c0;
  const c0 = sum * difference;
  const c1 = twice * a.c1;
  record(sum, difference, twice, c0, c1);
  return { c0, c1 };
};

const rawAffineDouble = (point, slope) => {
  const twoY = { c0: point.y.c0 + point.y.c0, c1: point.y.c1 + point.y.c1 };
  recordConcrete(twoY.c0, twoY.c1);
  const slopeLhs = fp2RawMul(slope, twoY, recordConcrete);
  const x2 = fp2RawSqr(point.x, recordConcrete);
  const slopeRhs = { c0: 3n * x2.c0, c1: 3n * x2.c1 };
  recordConcrete(slopeRhs.c0, slopeRhs.c1,
    slopeLhs.c0 - slopeRhs.c0, slopeLhs.c1 - slopeRhs.c1);
  if (modP(slopeLhs.c0 - slopeRhs.c0) !== 0n || modP(slopeLhs.c1 - slopeRhs.c1) !== 0n) {
    throw new Error('raw affine double slope equation failed');
  }
  const m2 = fp2RawSqr(slope, recordConcrete);
  const twoX = { c0: point.x.c0 + point.x.c0, c1: point.x.c1 + point.x.c1 };
  const nextXRaw = { c0: m2.c0 - twoX.c0, c1: m2.c1 - twoX.c1 };
  recordConcrete(twoX.c0, twoX.c1, nextXRaw.c0, nextXRaw.c1);
  const nextX = canonical2(nextXRaw);
  const xDifference = { c0: point.x.c0 - nextX.c0, c1: point.x.c1 - nextX.c1 };
  recordConcrete(xDifference.c0, xDifference.c1);
  const slopeTimesDifference = fp2RawMul(slope, xDifference, recordConcrete);
  const nextYRaw = {
    c0: slopeTimesDifference.c0 - point.y.c0,
    c1: slopeTimesDifference.c1 - point.y.c1,
  };
  recordConcrete(nextYRaw.c0, nextYRaw.c1);
  const slopeTimesX = fp2RawMul(slope, point.x, recordConcrete);
  const c0Raw = { c0: point.y.c0 - slopeTimesX.c0, c1: point.y.c1 - slopeTimesX.c1 };
  recordConcrete(c0Raw.c0, c0Raw.c1);
  return {
    R: { x: nextX, y: canonical2(nextYRaw) },
    c0: canonical2(c0Raw),
  };
};

const rawAffineAdd = (point, addend, slope) => {
  const xDifference = {
    c0: addend.x.c0 - point.x.c0,
    c1: addend.x.c1 - point.x.c1,
  };
  const yDifference = {
    c0: addend.y.c0 - point.y.c0,
    c1: addend.y.c1 - point.y.c1,
  };
  recordConcrete(xDifference.c0, xDifference.c1, yDifference.c0, yDifference.c1);
  const slopeLhs = fp2RawMul(slope, xDifference, recordConcrete);
  recordConcrete(slopeLhs.c0 - yDifference.c0, slopeLhs.c1 - yDifference.c1);
  if (modP(slopeLhs.c0 - yDifference.c0) !== 0n ||
      modP(slopeLhs.c1 - yDifference.c1) !== 0n) {
    throw new Error('raw affine add slope equation failed');
  }
  const m2 = fp2RawSqr(slope, recordConcrete);
  const nextXRaw = {
    c0: m2.c0 - point.x.c0 - addend.x.c0,
    c1: m2.c1 - point.x.c1 - addend.x.c1,
  };
  recordConcrete(nextXRaw.c0, nextXRaw.c1);
  const nextX = canonical2(nextXRaw);
  const runningXDifference = {
    c0: point.x.c0 - nextX.c0,
    c1: point.x.c1 - nextX.c1,
  };
  recordConcrete(runningXDifference.c0, runningXDifference.c1);
  const slopeTimesDifference = fp2RawMul(slope, runningXDifference, recordConcrete);
  const nextYRaw = {
    c0: slopeTimesDifference.c0 - point.y.c0,
    c1: slopeTimesDifference.c1 - point.y.c1,
  };
  recordConcrete(nextYRaw.c0, nextYRaw.c1);
  const slopeTimesX = fp2RawMul(slope, point.x, recordConcrete);
  const c0Raw = { c0: point.y.c0 - slopeTimesX.c0, c1: point.y.c1 - slopeTimesX.c1 };
  recordConcrete(c0Raw.c0, c0Raw.c1);
  return {
    R: { x: nextX, y: canonical2(nextYRaw) },
    c0: canonical2(c0Raw),
  };
};

const boundedNeg = (value) => ({ c0: 64n * P - value.c0, c1: 64n * P - value.c1 });
const expectedC0 = (point, slope) => Fp2.sub(point.y, Fp2.mul(slope, point.x));

let rawDoubles = 0;
let rawAdds = 0;
for (const scalar of [1n, 2n, 7n, BN_X]) {
  const scaledProof = scalar === 1n ? proof : {
    a: proof.a.multiply(bn254.fields.Fr.inv(scalar)),
    b: proof.b.multiply(scalar),
    c: proof.c,
  };
  const pairs = pairsFor(vec.publicInputs, scaledProof);
  const trace = millerFusedAffineOps(pairs, bn254.fields.Fp12.ONE, bn254.fields.Fp12.ONE);
  const runtimeQ = pairs[0].Q.toAffine();
  let replayR = { x: runtimeQ.x, y: runtimeQ.y };
  for (let index = 0; index < trace.ops.length; index++) {
    const op = trace.ops[index];
    if (op.j !== 0) continue;
    const before = trace.states[index].Rs[0];
    if (!eq2(replayR.x, before.x) || !eq2(replayR.y, before.y)) {
      throw new Error(`raw affine replay entered the wrong state at operation ${index}`);
    }
    if (op.t === 'dl') {
      const result = rawAffineDouble(replayR, op.affineSlopes[0]);
      if (!eq2(result.c0, expectedC0(replayR, op.affineSlopes[0]))) {
        throw new Error(`raw affine double emitted the wrong line at operation ${index}`);
      }
      replayR = result.R;
      rawDoubles += 1;
    } else if (op.t === 'al') {
      const addend = { x: runtimeQ.x, y: op.neg ? boundedNeg(runtimeQ.y) : runtimeQ.y };
      const result = rawAffineAdd(replayR, addend, op.affineSlopes[0]);
      if (!eq2(result.c0, expectedC0(replayR, op.affineSlopes[0]))) {
        throw new Error(`raw affine add emitted the wrong line at operation ${index}`);
      }
      replayR = result.R;
      rawAdds += 1;
    } else if (op.t === 'pp') {
      const [q1x, q1y] = psi(runtimeQ.x, runtimeQ.y);
      const first = rawAffineAdd(replayR, { x: q1x, y: q1y }, op.affineSlopes[0]);
      if (!eq2(first.c0, expectedC0(replayR, op.affineSlopes[0]))) {
        throw new Error(`raw first post-processing add emitted the wrong line at operation ${index}`);
      }
      replayR = first.R;
      const [q2x, q2y] = psi(q1x, q1y);
      const second = rawAffineAdd(replayR, { x: q2x, y: boundedNeg(q2y) }, op.affineSlopes[1]);
      if (!eq2(second.c0, expectedC0(replayR, op.affineSlopes[1]))) {
        throw new Error(`raw second post-processing add emitted the wrong line at operation ${index}`);
      }
      replayR = second.R;
      rawAdds += 2;
    }
    const after = trace.states[index + 1].Rs[0];
    if (!eq2(replayR.x, after.x) || !eq2(replayR.y, after.y)) {
      throw new Error(`raw affine replay emitted the wrong state at operation ${index}`);
    }
  }
}
if (rawDoubles !== 260 || rawAdds !== 92) {
  throw new Error(`unexpected raw affine coverage: ${rawDoubles} doubles, ${rawAdds} additions`);
}

const interval = (lo, hi) => {
  if (lo > hi) throw new Error('invalid interval');
  return { lo, hi };
};
const add = (a, b) => interval(a.lo + b.lo, a.hi + b.hi);
const sub = (a, b) => interval(a.lo - b.hi, a.hi - b.lo);
const mul = (a, b) => {
  const products = [a.lo * b.lo, a.lo * b.hi, a.hi * b.lo, a.hi * b.hi];
  return interval(products.reduce((minimum, value) => value < minimum ? value : minimum),
    products.reduce((maximum, value) => value > maximum ? value : maximum));
};
const scale = (a, scalar) => scalar >= 0n
  ? interval(a.lo * scalar, a.hi * scalar)
  : interval(a.hi * scalar, a.lo * scalar);
let intervalMaxAbs = 0n;
const recordInterval = (...values) => {
  for (const value of values) {
    const absolute = (-value.lo) > value.hi ? -value.lo : value.hi;
    if (absolute > intervalMaxAbs) intervalMaxAbs = absolute;
  }
};
const rawMul = (a, b) => {
  const v0 = mul(a.c0, b.c0);
  const v1 = mul(a.c1, b.c1);
  const aSum = add(a.c0, a.c1);
  const bSum = add(b.c0, b.c1);
  const cross = mul(aSum, bSum);
  const crossMinusV0 = sub(cross, v0);
  const c0 = sub(v0, v1);
  // cross-v0-v1 is exactly a0*b1+a1*b0. Preserve that dependency for its
  // final interval while separately bounding the left-associated intermediate.
  const c1 = add(mul(a.c0, b.c1), mul(a.c1, b.c0));
  recordInterval(v0, v1, aSum, bSum, cross, crossMinusV0, c0, c1);
  return { c0, c1 };
};
const rawSqr = (a) => {
  const sum = add(a.c0, a.c1);
  const difference = sub(a.c0, a.c1);
  const twice = scale(a.c0, 2n);
  const c0 = mul(sum, difference);
  const c1 = mul(twice, a.c1);
  recordInterval(sum, difference, twice, c0, c1);
  return { c0, c1 };
};

const canonical = { c0: interval(0n, P - 1n), c1: interval(0n, P - 1n) };
const twoY = { c0: scale(canonical.c0, 2n), c1: scale(canonical.c1, 2n) };
recordInterval(twoY.c0, twoY.c1);
const doubleLhs = rawMul(canonical, twoY);
const x2 = rawSqr(canonical);
const doubleRhs = { c0: scale(x2.c0, 3n), c1: scale(x2.c1, 3n) };
recordInterval(doubleRhs.c0, doubleRhs.c1,
  sub(doubleLhs.c0, doubleRhs.c0), sub(doubleLhs.c1, doubleRhs.c1));
const doubleM2 = rawSqr(canonical);
const twoX = { c0: scale(canonical.c0, 2n), c1: scale(canonical.c1, 2n) };
recordInterval(twoX.c0, twoX.c1,
  sub(doubleM2.c0, twoX.c0), sub(doubleM2.c1, twoX.c1));
const signedCanonical = interval(-(P - 1n), P - 1n);
const runningDifference = { c0: signedCanonical, c1: signedCanonical };
recordInterval(runningDifference.c0, runningDifference.c1);
const doubleMxdn = rawMul(canonical, runningDifference);
recordInterval(sub(doubleMxdn.c0, canonical.c0), sub(doubleMxdn.c1, canonical.c1));
const doubleMx = rawMul(canonical, canonical);
recordInterval(sub(canonical.c0, doubleMx.c0), sub(canonical.c1, doubleMx.c1));

const boundedY = interval(0n, 64n * P);
const addDy = { c0: sub(boundedY, canonical.c0), c1: sub(boundedY, canonical.c1) };
recordInterval(signedCanonical, addDy.c0, addDy.c1);
const addLhs = rawMul(canonical, runningDifference);
recordInterval(sub(addLhs.c0, addDy.c0), sub(addLhs.c1, addDy.c1));
const addM2 = rawSqr(canonical);
recordInterval(
  sub(sub(addM2.c0, canonical.c0), canonical.c0),
  sub(sub(addM2.c1, canonical.c1), canonical.c1),
);
const addMxdn = rawMul(canonical, runningDifference);
recordInterval(sub(addMxdn.c0, canonical.c0), sub(addMxdn.c1, canonical.c1));
const addMx = rawMul(canonical, canonical);
recordInterval(sub(canonical.c0, addMx.c0), sub(canonical.c1, addMx.c1));

const vmNumberBytes = (value) => {
  const absolute = value < 0n ? -value : value;
  if (absolute === 0n) return 0;
  const magnitudeBytes = Math.ceil(absolute.toString(2).length / 8);
  return (absolute >> BigInt(8 * magnitudeBytes - 1)) === 0n ? magnitudeBytes : magnitudeBytes + 1;
};
const rawLimit = 8n * P * P;
if (intervalMaxAbs >= rawLimit || vmNumberBytes(intervalMaxAbs) > 64) {
  throw new Error('raw affine interval exceeds the certified 8p^2/64-byte bound');
}
if (concreteMaxAbs >= rawLimit || vmNumberBytes(concreteMaxAbs) > 64) {
  throw new Error('concrete raw affine replay exceeds the certified integer bound');
}

console.log('Raw affine Miller certificate passed');
console.log(`${rawDoubles} doubles and ${rawAdds} additions match the field formulas and Miller states`);
console.log(`all raw affine intermediates are < 8p^2 (${vmNumberBytes(intervalMaxAbs)} VM-number bytes)`);

// Proof and degree audit for complete two-chart quotient-torus
// handoffs over the selected 63-bit binary BLS12-381 Miller trace. This file
// proves algebraic primitives and certificate bounds; it is not a verifier or
// a benchmark-vector generator.
import { createHash } from 'node:crypto';
import {
  QSPLIT_ATE_LOOP_DIGITS as ATE_LOOP_DIGITS,
  Fp,
  Fp6,
  Fp12,
  qsplitMillerBatchOps as millerBatchOps,
  qsplitPairsFor as pairsFor,
} from './_pairingmath.mjs';
import {
  qsplitFixedVkMiller as fixedVkMiller,
  qsplitMillerFusedAffineDirect8Ops as millerFusedAffineDirect8Ops,
  residueTorusWitness,
} from './_residuemath.mjs';
import { le48Exact } from './_vkxmath.mjs';
import {
  PUBLIC_INPUTS,
  proof,
} from '../../singleton/bls12-381/bls_instance.mjs';

const P = Fp.ORDER;
const W = 48;
const mod = (value) => ((value % P) + P) % P;
const assert = (condition, message) => {
  if (!condition) throw new Error(message);
};
const concat = (...parts) => Uint8Array.from(parts.flatMap((part) => [...part]));
const sha256 = (bytes) => Uint8Array.from(createHash('sha256').update(bytes).digest());
const hex = (bytes) => Buffer.from(bytes).toString('hex');

const trim = (polynomial) => {
  const output = polynomial.map(mod);
  while (output.length > 1 && output[output.length - 1] === 0n) output.pop();
  return output;
};
const add = (left, right) => trim(Array.from(
  { length: Math.max(left.length, right.length) },
  (_, index) => (left[index] ?? 0n) + (right[index] ?? 0n),
));
const subtract = (left, right) => trim(Array.from(
  { length: Math.max(left.length, right.length) },
  (_, index) => (left[index] ?? 0n) - (right[index] ?? 0n),
));
const multiply = (left, right) => {
  const output = Array.from({ length: left.length + right.length - 1 }, () => 0n);
  left.forEach((a, leftIndex) => right.forEach((b, rightIndex) => {
    output[leftIndex + rightIndex] = mod(output[leftIndex + rightIndex] + a * b);
  }));
  return trim(output);
};
const shiftY = (polynomial) => [0n, ...polynomial];
const divideFp6 = (polynomial) => {
  const remainder = polynomial.map(mod);
  const quotient = Array.from({ length: Math.max(1, remainder.length - 6) }, () => 0n);
  for (let degree = remainder.length - 1; degree >= 6; degree -= 1) {
    const coefficient = remainder[degree] ?? 0n;
    quotient[degree - 6] = coefficient;
    remainder[degree] = 0n;
    remainder[degree - 3] = mod((remainder[degree - 3] ?? 0n) + 2n * coefficient);
    remainder[degree - 6] = mod((remainder[degree - 6] ?? 0n) - 2n * coefficient);
  }
  return { quotient: trim(quotient), remainder: trim(remainder.slice(0, 6)) };
};
const reduceFp6 = (polynomial) => divideFp6(polynomial).remainder;
const FP6_MODULUS = [2n, 0n, 0n, -2n, 0n, 0n, 1n];
const dividePolynomial = (dividend, divisor) => {
  const denominator = trim(divisor);
  assert(!(denominator.length === 1 && denominator[0] === 0n), 'polynomial division by zero');
  const remainder = trim(dividend);
  const quotient = Array.from(
    { length: Math.max(1, remainder.length - denominator.length + 1) },
    () => 0n,
  );
  const leadingInverse = Fp.inv(denominator.at(-1));
  while (!(remainder.length === 1 && remainder[0] === 0n) &&
    remainder.length >= denominator.length) {
    const offset = remainder.length - denominator.length;
    const coefficient = mod(remainder.at(-1) * leadingInverse);
    quotient[offset] = coefficient;
    denominator.forEach((value, index) => {
      remainder[offset + index] = mod(remainder[offset + index] - coefficient * value);
    });
    while (remainder.length > 1 && remainder.at(-1) === 0n) remainder.pop();
  }
  return { quotient: trim(quotient), remainder: trim(remainder) };
};
const powPolynomialModulo = (base, exponent, modulus) => {
  let result = [1n];
  let power = dividePolynomial(base, modulus).remainder;
  let remaining = exponent;
  while (remaining > 0n) {
    if ((remaining & 1n) === 1n) {
      result = dividePolynomial(multiply(result, power), modulus).remainder;
    }
    power = dividePolynomial(multiply(power, power), modulus).remainder;
    remaining >>= 1n;
  }
  return result;
};
const gcdPolynomial = (left, right) => {
  let a = trim(left);
  let b = trim(right);
  while (!(b.length === 1 && b[0] === 0n)) {
    [a, b] = [b, dividePolynomial(a, b).remainder];
  }
  const leadingInverse = Fp.inv(a.at(-1));
  return trim(a.map((coefficient) => coefficient * leadingInverse));
};

const FLAT_Y = [0n, 1n];
const yPowers = [2n, 3n, 6n].map((power) => ({
  power,
  value: powPolynomialModulo(FLAT_Y, P ** power, FP6_MODULUS),
}));
const yP2 = yPowers.find(({ power }) => power === 2n).value;
const yP3 = yPowers.find(({ power }) => power === 3n).value;
const yP6 = yPowers.find(({ power }) => power === 6n).value;
assert(trim(subtract(yP6, FLAT_Y)).every((coefficient) => coefficient === 0n),
  'Rabin degree-6 Frobenius identity failed');
const rabinDegree3Gcd = gcdPolynomial(subtract(yP3, FLAT_Y), FP6_MODULUS);
const rabinDegree2Gcd = gcdPolynomial(subtract(yP2, FLAT_Y), FP6_MODULUS);
assert(rabinDegree3Gcd.length === 1 && rabinDegree3Gcd[0] === 1n,
  'Rabin degree-3 gcd is not one');
assert(rabinDegree2Gcd.length === 1 && rabinDegree2Gcd[0] === 1n,
  'Rabin degree-2 gcd is not one');
const flatYLegendre = powPolynomialModulo(
  FLAT_Y,
  (P ** 6n - 1n) / 2n,
  FP6_MODULUS,
);
assert(flatYLegendre.length === 1 && flatYLegendre[0] === P - 1n,
  'Y is not certified as a nonsquare in the flat Fp6 field');

const fp6Limbs = (value) => [
  value.c0.c0, value.c0.c1,
  value.c1.c0, value.c1.c1,
  value.c2.c0, value.c2.c1,
];
const fp6ToFlatInteger = (limbs) => [
  limbs[0] - limbs[1], limbs[2] - limbs[3], limbs[4] - limbs[5],
  limbs[1], limbs[3], limbs[5],
];
const flatToFp6Integer = (flat) => [
  flat[0] + flat[3], flat[3],
  flat[1] + flat[4], flat[4],
  flat[2] + flat[5], flat[5],
];
const fp6ToFlat = (value) => fp6ToFlatInteger(fp6Limbs(value)).map(mod);
const flatToFp6 = (flat) => Fp6.fromBigSix(flatToFp6Integer(flat).map(mod));
assert(Fp6.eql(flatToFp6(Array.from({ length: 6 }, (_, index) => flatYLegendre[index] ?? 0n)),
  Fp6.neg(Fp6.ONE)),
  'flat polynomial and tower implementations disagree on the Y Legendre symbol');
const pairFor = (value) => [trim(fp6ToFlat(value.c0)), trim(fp6ToFlat(value.c1))];
const pairSquare = ([c0, c1]) => [
  add(multiply(c0, c0), shiftY(multiply(c1, c1))),
  multiply([2n], multiply(c0, c1)),
];
const pairMultiply = ([a0, a1], [b0, b1]) => [
  add(multiply(a0, b0), shiftY(multiply(a1, b1))),
  add(multiply(a0, b1), multiply(a1, b0)),
];
const sameClass = (left, right) => Fp6.eql(
  Fp6.mul(left.c0, right.c1),
  Fp6.mul(left.c1, right.c0),
);
const chart = (value, preferChart1) => {
  assert(!Fp12.eql(value, Fp12.ZERO), 'zero has no quotient-torus chart');
  const c0IsZero = Fp6.eql(value.c0, Fp6.ZERO);
  const c1IsZero = Fp6.eql(value.c1, Fp6.ZERO);
  const flag = c0IsZero || preferChart1 && !c1IsZero ? 1 : 0;
  const denominator = flag === 0 ? value.c0 : value.c1;
  assert(!Fp6.eql(denominator, Fp6.ZERO), `chart ${flag} selected a zero denominator`);
  const inverse = Fp6.inv(denominator);
  const u = flag === 0
    ? Fp6.mul(value.c1, inverse)
    : Fp6.mul(value.c0, inverse);
  const representative = flag === 0
    ? Fp12.create({ c0: Fp6.ONE, c1: u })
    : Fp12.create({ c0: u, c1: Fp6.ONE });
  assert(sameClass(value, representative), `chart ${flag} reconstruction changed the class`);
  return { flag, u, representative };
};

let seed = 0x243f6a8885a308d3n;
const random = () => {
  seed ^= seed << 13n;
  seed ^= seed >> 7n;
  seed ^= seed << 17n;
  return mod(seed);
};
for (let sample = 0; sample < 128; sample += 1) {
  const integers = Array.from(
    { length: 6 },
    (_, index) => BigInt((sample + 3) * (index + 5) * (index % 2 === 0 ? 1 : -1)),
  );
  assert(
    flatToFp6Integer(fp6ToFlatInteger(integers)).every((value, index) => value === integers[index]),
    `Fp6 integer flat-map round trip failed at sample ${sample}`,
  );
}
for (let sample = 0; sample < 96; sample += 1) {
  const left = Fp6.fromBigSix(Array.from({ length: 6 }, random));
  const right = Fp6.fromBigSix(Array.from({ length: 6 }, random));
  const leftFlat = fp6ToFlat(left);
  assert(Fp6.eql(flatToFp6(leftFlat), left), `Fp6 flat-map inverse failed at sample ${sample}`);
  assert(
    reduceFp6(multiply(leftFlat, fp6ToFlat(right))).every(
      (value, index) => value === fp6ToFlat(Fp6.mul(left, right))[index],
    ),
    `Fp6 multiplication differential failed at sample ${sample}`,
  );
}
for (let sample = 0; sample < 128; sample += 1) {
  const c0 = sample % 17 === 0
    ? Fp6.ZERO
    : Fp6.fromBigSix(Array.from({ length: 6 }, random));
  const c1 = sample % 19 === 0
    ? Fp6.ONE
    : Fp6.fromBigSix(Array.from({ length: 6 }, random));
  const value = Fp12.create({ c0, c1 });
  if (Fp12.eql(value, Fp12.ZERO)) continue;
  if (!Fp6.eql(c0, Fp6.ZERO)) assert(sameClass(value, chart(value, false).representative), 'chart 0 failed');
  if (!Fp6.eql(c1, Fp6.ZERO)) assert(sameClass(value, chart(value, true).representative), 'chart 1 failed');
}

const fullPairs = pairsFor(PUBLIC_INPUTS, proof);
const pairs = pairsFor(PUBLIC_INPUTS, proof, { msmOnly: true });
const fixedMiller = fixedVkMiller(pairs, true);
const selectedBoundary = millerFusedAffineDirect8Ops(
  pairs,
  Fp12.ONE,
  Fp12.ONE,
  { fixedMiller },
).boundary;
assert(
  Fp12.eql(
    Fp12.finalExponentiate(selectedBoundary),
    Fp12.finalExponentiate(millerBatchOps(fullPairs).boundary),
  ),
  'selected IC0-folded direct8 trace changed the four-pair verdict',
);
const residue = residueTorusWitness(selectedBoundary);
const trace = millerFusedAffineDirect8Ops(
  pairs,
  residue.c,
  residue.cInv,
  { torusU: residue.u, fixedMiller },
);
const squareIndices = trace.ops.flatMap((op, index) => op.t === 'sqr' ? [index] : []);
const fixedFoldIndex = trace.ops.findIndex((op) => op.t === 'cmul1');
assert(squareIndices.length === ATE_LOOP_DIGITS.length, 'binary fused trace round count changed');
assert(trace.ops.length === 273, 'binary fused trace operation count changed');
assert(fixedFoldIndex === trace.ops.length - 1, 'fixed Miller fold is not terminal');
assert(trace.ops.filter((op) => op.t === 'dl').length === 189, 'binary doubling count changed');
assert(trace.ops.filter((op) => op.t === 'al').length === 15, 'binary addition count changed');
assert(trace.ops.filter((op) => op.t === 'cf').length === 5, 'binary residue-fold count changed');
assert(trace.ops.every((op) => ['sqr', 'dl', 'al', 'cf', 'cmul1'].includes(op.t)),
  'binary trace contains an unknown operation');

const zero = Fp12.ZERO;
assert(Fp12.eql(Fp12.sqr(zero), zero), 'zero is not absorbing under square');
trace.ops.forEach((op, index) => {
  const before = trace.states[index].f;
  const after = trace.states[index + 1].f;
  assert(!Fp12.eql(before, zero), `genuine trace state ${index} is zero`);
  if (op.t !== 'sqr') {
    const factor = Fp12.mul(after, Fp12.inv(before));
    assert(!Fp12.eql(factor, zero), `genuine transition factor ${index} is zero`);
    assert(Fp12.eql(Fp12.mul(zero, factor), zero), `zero recovered at transition ${index}`);
    const [low, high] = pairFor(factor);
    assert(low.length === 1 && low[0] === 1n, `transition ${index} is not normalized as 1 + W*t`);
    assert(high.length <= 6, `transition ${index} high Fp6 coefficient exceeds degree 5`);
  }
});
assert(!Fp12.eql(trace.boundary, zero), 'accepted fused terminal is zero');

const torusRoot = Fp12.create({ c0: Fp6.ONE, c1: residue.u });
const expectedTerminal = Fp12.frobeniusMap(torusRoot, 1);
assert(sameClass(trace.boundary, expectedTerminal), 'six-limb quotient residue terminal failed');
assert(Fp6.eql(residue.w.c1, Fp6.ZERO), 'residue correction does not vanish in the Fp6 quotient');

const rangesFor = (depth) => Array.from(
  { length: Math.ceil(squareIndices.length / depth) },
  (_, blockIndex) => {
    const roundLo = blockIndex * depth;
    const roundHi = Math.min(squareIndices.length, roundLo + depth);
    return {
      blockIndex,
      roundLo,
      roundHi,
      opLo: squareIndices[roundLo],
      opHi: roundHi === squareIndices.length ? fixedFoldIndex : squareIndices[roundHi],
    };
  },
);
const transitionFactor = (index) => {
  const before = trace.states[index].f;
  const after = trace.states[index + 1].f;
  assert(!Fp12.eql(before, Fp12.ZERO), `transition ${index} begins at zero`);
  const factor = Fp12.mul(after, Fp12.inv(before));
  assert(Fp12.eql(Fp12.mul(before, factor), after), `transition ${index} factor changed`);
  return factor;
};
const relationFor = (components, outputChart) => {
  const output = fp6ToFlat(outputChart.u);
  const selected = outputChart.flag === 0 ? components[0] : components[1];
  const other = outputChart.flag === 0 ? components[1] : components[0];
  const crossResidual = subtract(other, multiply(selected, output));
  const reducedSelected = flatToFp6(reduceFp6(selected));
  assert(!Fp6.eql(reducedSelected, Fp6.ZERO), 'selected projective denominator is zero');
  const selectedInverse = fp6ToFlat(Fp6.inv(reducedSelected));
  const inverseResidual = subtract(multiply(selected, selectedInverse), [1n]);
  const crossDivision = divideFp6(crossResidual);
  const inverseDivision = divideFp6(inverseResidual);
  assert(crossDivision.remainder.every((coefficient) => coefficient === 0n), 'cross remainder is nonzero');
  assert(inverseDivision.remainder.every((coefficient) => coefficient === 0n), 'inverse remainder is nonzero');
  return {
    crossResidual,
    inverseResidual,
    crossQuotient: crossDivision.quotient,
    inverseQuotient: inverseDivision.quotient,
    selectedInverse,
  };
};

const checkDepth = (depth) => {
  const ranges = rangesFor(depth);
  const boundaryCharts = Array.from(
    { length: ranges.length + 1 },
    (_, index) => {
      const stateIndex = index === ranges.length ? fixedFoldIndex : ranges[index].opLo;
      return chart(trace.states[stateIndex].f, index % 2 === 1);
    },
  );
  const diagnostics = ranges.map((range, blockIndex) => {
    let components = pairFor(boundaryCharts[blockIndex].representative);
    for (let index = range.opLo; index < range.opHi; index += 1) {
      components = trace.ops[index].t === 'sqr'
        ? pairSquare(components)
        : pairMultiply(components, pairFor(transitionFactor(index)));
    }
    const relation = relationFor(components, boundaryCharts[blockIndex + 1]);
    return {
      blockIndex,
      inputChart: boundaryCharts[blockIndex].flag,
      outputChart: boundaryCharts[blockIndex + 1].flag,
      componentDegrees: components.map((component) => component.length - 1),
      crossDegree: relation.crossResidual.length - 1,
      inverseDegree: relation.inverseResidual.length - 1,
      crossQuotientCoefficients: relation.crossQuotient.length,
      inverseQuotientCoefficients: relation.inverseQuotient.length,
    };
  });

  let universalMaximumRelationDegree = -1;
  let universalWitness = null;
  ranges.forEach((range) => {
    [0, 1].forEach((inputChart) => {
      let degrees = inputChart === 0 ? [0, 5] : [5, 0];
      for (let index = range.opLo; index < range.opHi; index += 1) {
        if (trace.ops[index].t === 'sqr') {
          degrees = [
            Math.max(2 * degrees[0], 2 * degrees[1] + 1),
            degrees[0] + degrees[1],
          ];
        } else {
          degrees = [
            Math.max(degrees[0], degrees[1] + 6),
            Math.max(degrees[0] + 5, degrees[1]),
          ];
        }
      }
      [0, 1].forEach((outputChart) => {
        const selectedDegree = degrees[outputChart];
        const otherDegree = degrees[1 - outputChart];
        const crossDegree = Math.max(otherDegree, selectedDegree + 5);
        const inverseDegree = selectedDegree + 5;
        const relationDegree = Math.max(crossDegree, inverseDegree);
        if (relationDegree > universalMaximumRelationDegree) {
          universalMaximumRelationDegree = relationDegree;
          universalWitness = {
            blockIndex: range.blockIndex,
            inputChart,
            outputChart,
            componentDegrees: degrees,
            crossDegree,
            inverseDegree,
          };
        }
      });
    });
  });

  const degreeSum = (left, right) => left === Number.NEGATIVE_INFINITY ||
    right === Number.NEGATIVE_INFINITY
    ? Number.NEGATIVE_INFINITY
    : left + right;
  let canonicalNoInverseMaximumRelationDegree = -1;
  let canonicalNoInverseWitness = null;
  const includeCanonicalRange = (range, inputChart, initialDegrees, terminal = false) => {
    let degrees = initialDegrees;
    for (let index = range.opLo; index < range.opHi; index += 1) {
      if (trace.ops[index].t === 'sqr') {
        degrees = [
          Math.max(degreeSum(degrees[0], degrees[0]), degreeSum(degrees[1], degrees[1]) + 1),
          degreeSum(degrees[0], degrees[1]),
        ];
      } else {
        degrees = [
          Math.max(degrees[0], degreeSum(degrees[1], 6)),
          Math.max(degreeSum(degrees[0], 5), degrees[1]),
        ];
      }
    }
    [0, 1].forEach((outputChart) => {
      const crossDegree = outputChart === 0
        ? Math.max(degrees[1], degreeSum(degrees[0], 5))
        : degrees[0];
      if (crossDegree > canonicalNoInverseMaximumRelationDegree) {
        canonicalNoInverseMaximumRelationDegree = crossDegree;
        canonicalNoInverseWitness = {
          blockIndex: terminal ? 'terminal' : range.blockIndex,
          inputChart,
          outputChart,
          componentDegrees: degrees,
          crossDegree,
        };
      }
    });
  };
  ranges.forEach((range) => {
    includeCanonicalRange(range, 0, [0, 5]);
    includeCanonicalRange(range, 1, [Number.NEGATIVE_INFINITY, 0]);
  });
  includeCanonicalRange(
    { opLo: fixedFoldIndex, opHi: fixedFoldIndex + 1 },
    0,
    [0, 5],
    true,
  );
  includeCanonicalRange(
    { opLo: fixedFoldIndex, opHi: fixedFoldIndex + 1 },
    1,
    [Number.NEGATIVE_INFINITY, 0],
    true,
  );

  const preTerminalChart = boundaryCharts.at(-1);
  const fixedFactor = transitionFactor(fixedFoldIndex);
  let terminalComponents = pairMultiply(
    pairFor(preTerminalChart.representative),
    pairFor(fixedFactor),
  );
  const terminalChart = chart(expectedTerminal, false);
  const terminalRelation = relationFor(terminalComponents, terminalChart);
  const maximumActualQuotientCoefficients = Math.max(
    ...diagnostics.flatMap((item) => [
      item.crossQuotientCoefficients,
      item.inverseQuotientCoefficients,
    ]),
    terminalRelation.crossQuotient.length,
    terminalRelation.inverseQuotient.length,
  );
  const universalMaximumQuotientCoefficients = universalMaximumRelationDegree - 5;
  const blockCount = ranges.length;
  return {
    depth,
    blockCount,
    relationCount: 2 * blockCount + 2,
    maximumActualQuotientCoefficients,
    universalMaximumRelationDegree,
    universalMaximumQuotientCoefficients,
    universalWitness,
    canonicalNoInverseMaximumRelationDegree,
    canonicalNoInverseMaximumQuotientCoefficients:
      canonicalNoInverseMaximumRelationDegree - 5,
    canonicalNoInverseWitness,
    chartStateBytes: blockCount * (6 * W + 1),
    selectedDenominatorInverseBytes: (blockCount + 1) * 6 * W,
    quotientBytes: universalMaximumQuotientCoefficients * W,
    chartsExercised: [...new Set(boundaryCharts.map((item) => item.flag))].sort(),
    terminalCrossQuotientCoefficients: terminalRelation.crossQuotient.length,
    terminalInverseQuotientCoefficients: terminalRelation.inverseQuotient.length,
    diagnostics,
  };
};

const d3Ranges = rangesFor(3);
const fixedTableBlocks = d3Ranges.map((range) => {
  const coefficients = trace.ops.slice(range.opLo, range.opHi)
    .filter((op) => op.j === 2 || op.j === 3)
    .flatMap((op) => op.coeffs.flatMap((coefficient) => [coefficient.c0, coefficient.c1]));
  return {
    blockIndex: range.blockIndex,
    bytes: coefficients.length * W,
    commitment: hex(sha256(concat(...coefficients.map(le48Exact)))),
  };
});
assert(
  fixedTableBlocks.reduce((total, block) => total + block.bytes, 0) === 136 * 4 * W,
  'prepared fixed-table byte count changed',
);

const models = Array.from({ length: 5 }, (_, index) => checkDepth(index + 1));
assert(models.every((model, index) =>
  model.canonicalNoInverseMaximumQuotientCoefficients === [44, 110, 264, 550, 1122][index]),
'canonical no-inverse quotient-width table changed');
const summaryOnly = process.env.RPA_SUMMARY === '1';
console.log(JSON.stringify({
  scope: 'two-chart fused quotient-torus algebra and universal degree bounds only',
  completeVerifier: false,
  sourceTrace: {
    binaryRounds: squareIndices.length,
    binaryAdditions: ATE_LOOP_DIGITS.filter((digit) => digit !== 0).length,
    fusedOperations: trace.ops.length,
    fixedFoldIndex,
  },
  flatFp6Modulus: 'Y^6 - 2*Y^3 + 2',
  fieldCertificate: {
    rabinIrreducibility: {
      yToP6EqualsY: true,
      gcdYToP3MinusY: '1',
      gcdYToP2MinusY: '1',
      conclusion: 'Y^6 - 2*Y^3 + 2 is irreducible over Fp',
    },
    yLegendreSymbolInFp6: '-1',
    fp12Modulus: 'W^2 - Y',
    fp12Irreducible: true,
  },
  charts: {
    chart0: '1 + u*W',
    chart1: 'W (canonical flag 1 requires u=0)',
    overlappingAuditChart1: 'u + W',
    flagDomain: [0, 1],
    inverseBackedSelectedComponentCheck: 'D*z = 1 modulo Y^6 - 2*Y^3 + 2',
    coverage: 'chart 0 covers c0 != 0; canonical chart 1 is the unique quotient point with c0=0',
  },
  noInverseCertificate: {
    status: 'algebraically certified for the grouped Miller handoff only',
    initialStates: [
      '1 + u*W is nonzero for every u in Fp6',
      'W is nonzero',
    ],
    factors: [
      'every direct8 line factor is 1 + W*t by construction',
      'every residue-root fold is 1 + W*t by construction',
      'the public fixed fAB fold has a checked finite normalization 1 + W*t',
    ],
    induction: 'Fp12 is a field, so squares and products of these nonzero values remain nonzero',
    crossRelation: [
      'chart 0: b=a*u and a+b*W nonzero imply a is nonzero',
      'chart 1: u=0, a=0, and a+b*W nonzero imply b is nonzero',
    ],
    conclusion: 'the canonical cross relation alone excludes the zero projective pair at every grouped handoff',
  },
  differentialChecks: {
    integerFlatMapRoundTrips: 128,
    fp6Multiplications: 96,
    randomChartClasses: 128,
    genuineNonzeroStates: trace.states.length,
    genuineNonzeroFactors: trace.ops.length - squareIndices.length,
  },
  quotientResidue: {
    serializedRootLimbs: 6,
    serializedRootBytes: 6 * W,
    inverseByNegation: true,
    correctionWVanishesInFp6Quotient: true,
    terminalMatchesFrobeniusClass: true,
  },
  preparedFixedTable: {
    source: 'normalized gamma/delta lines derived from the fixed public VK',
    lineCount: 136,
    bytes: 136 * 4 * W,
    blockCommitmentsMustBeHardcoded: true,
    blocks: fixedTableBlocks,
  },
  models: summaryOnly
    ? models.map(({ diagnostics: _diagnostics, ...model }) => model)
    : models,
  omissions: [
    'transaction-wide coordinator integration',
    'compiled per-block alpha evaluation and relation accumulation',
    'compiled Q Horner accumulation',
    'compiled runtime G2 slope equations',
    'compiled fixed-table commitment checks',
    'compiled fixed-fAB and quotient-residue terminal',
    'proof, public-input, G1/G2, and subgroup validation',
  ],
}, null, 2));

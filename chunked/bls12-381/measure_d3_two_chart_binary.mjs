// Compiled measurement and vector source for the depth-3 binary BLS12-381 Miller
// construction. Each Miller block proves one or two complete quotient-torus relations
// modulo Y^6-2Y^3+2, runtime-B affine slope equations, and an authenticated
// public-VK-derived table commitment. A transaction-wide Fiat-Shamir transcript
// combines every relation and checks the combined quotient with a Horner carrier chain.
//
// This source measures one fixture at a time. The strict corpus runner and the
// proof-independent resource certificate compose these measurements into the frozen
// ten-fixture result and resource artifacts.
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import {
  bigIntToVmNumber,
  binToHex,
  createInstructionSetBch2026,
  createVirtualMachine,
  createVirtualMachineBch2026,
  decodeAuthenticationInstructions,
  encodeDataPush,
  encodeLockingBytecodeP2sh32,
  encodeTransactionBch,
  hash256,
  numberToBinUint16LE,
  numberToBinUint32LE,
  OpcodesBCH,
} from '@bitauth/libauth';
import {
  QSPLIT_ATE_LOOP_DIGITS as ATE_LOOP_DIGITS,
  B_IDENTITY_SUBSTITUTE,
  Fp,
  Fp6,
  Fp12,
  qsplitMillerBatchOps as millerBatchOps,
  qsplitPairsFor as pairsFor,
  qsplitR4limbs as r4limbs,
  qsplitSinglePairMiller as singlePairMiller,
  unitG1,
} from './_pairingmath.mjs';
import {
  qsplitFixedVkMiller as fixedVkMiller,
  qsplitMillerFusedAffineDirect8Ops as millerFusedAffineDirect8Ops,
  residueTorusWitness,
} from './_residuemath.mjs';
import {
  OP_BUDGET,
  P,
  compileBytecode,
  le48Exact,
} from './_vkxmath.mjs';
import {
  bls12_381,
  proof as committedProof,
} from '../../singleton/bls12-381/bls_instance.mjs';

const W = 48;
const DEPTH = 3;
const INVERSE_RELATIONS = process.env.RPA_INVERSES !== 'off';
const SKIP_GAMMA = process.env.RPA_SKIP_GAMMA === '1';
const PIC32_RECORDS = SKIP_GAMMA && process.env.RPA_PIC32 === '1';
const REGULAR_DENSITY_PADDING = JSON.parse(process.env.RPA_REGULAR_DENSITY_PADDING ?? '{}');
const COORDINATOR_DENSITY_PADDING = Number(
  process.env.RPA_COORDINATOR_DENSITY_PADDING ?? 0,
);
const PIC_BLOCK4_DENSITY_PADDING = Number(
  process.env.RPA_PIC_BLOCK4_DENSITY_PADDING ?? 0,
);
const PIC_BLOCK2_DENSITY_PADDING = Number(
  process.env.RPA_PIC_BLOCK2_DENSITY_PADDING ?? 0,
);
const TRACE_SKIP_PAIRS = new Set(SKIP_GAMMA ? [1, 2] : [1]);
const SPLIT_RELATION_BLOCKS = INVERSE_RELATIONS ? [] : [0, 15];
const SPLIT_AFTER_OPERATION_COUNT = 6;
const QUOTIENT_COEFFICIENTS = INVERSE_RELATIONS ? 269 : 132;
const QUOTIENT_CARRIERS = INVERSE_RELATIONS ? 3 : 1;
const MAGIC = Uint8Array.from(Buffer.from('BLS12-381-RPA-v2', 'ascii'));
const OP_RETURN = Uint8Array.of(0x6a);
const OUTPUT_SATOSHIS = 1000n;
const SCALAR_ORDER = 52435875175126190479447740508185965837690552500527637822603658699938581184513n;
const consensusVm = createVirtualMachineBch2026(false);
const standardVm = createVirtualMachineBch2026(true);
const createDensityMeasurementVm = (standard) => {
  const instructionSet = createInstructionSetBch2026(standard);
  const initialize = instructionSet.initialize;
  return createVirtualMachine({
    ...instructionSet,
    initialize: (program) => {
      const state = initialize(program);
      return {
        ...state,
        metrics: {
          ...state.metrics,
          maximumOperationCost: Number.MAX_SAFE_INTEGER,
          maximumHashDigestIterations: Number.MAX_SAFE_INTEGER,
        },
      };
    },
  });
};
const measurementConsensusVm = createDensityMeasurementVm(false);
const measurementStandardVm = createDensityMeasurementVm(true);
const mod = (value) => ((value % P) + P) % P;
const assert = (condition, message) => {
  if (!condition) throw new Error(message);
};
assert(!INVERSE_RELATIONS, 'the block-0-and-15 split construction requires RPA_INVERSES=off');
const concat = (...parts) => Uint8Array.from(parts.flatMap((part) => [...part]));
const sha256 = (bytes) => Uint8Array.from(createHash('sha256').update(bytes).digest());
const hex = (bytes) => Buffer.from(bytes).toString('hex');
const u32 = (value) => numberToBinUint32LE(value);
const sum = (items, select) => items.reduce((total, item) => total + select(item), 0);
const equalBytes = (left, right) => left.length === right.length &&
  left.every((byte, index) => byte === right[index]);
assert((1n << 256n) < P, 'SHA-256 digest no longer fits the BLS12-381 base field');

const scalarMod = (value) => ((value % SCALAR_ORDER) + SCALAR_ORDER) % SCALAR_ORDER;
const G1 = bls12_381.G1.Point;
const G2 = bls12_381.G2.Point;
const Fr = bls12_381.fields.Fr;
const syntheticFixture = (inputs, bScalar, cScalar, aScalar) => {
  const normalizedInputs = inputs.map(BigInt);
  const b = BigInt(bScalar);
  const c = BigInt(cScalar);
  const vx = scalarMod(2n + 4n * normalizedInputs[0] + 6n * normalizedInputs[1]);
  const rhs = scalarMod(3n * 5n + vx * 7n + c * 11n);
  const a = aScalar === undefined
    ? Fr.mul(rhs, Fr.inv(b))
    : scalarMod(BigInt(aScalar));
  assert(scalarMod(a * b - rhs) === 0n, 'synthetic Groth16 scalar equation changed');
  return {
    inputs: normalizedInputs,
    scalars: { a, b, c, vx },
    proof: {
      a: a === 0n ? G1.ZERO : G1.BASE.multiply(a),
      b: b === 0n ? G2.ZERO : G2.BASE.multiply(b),
      c: c === 0n ? G1.ZERO : G1.BASE.multiply(c),
    },
  };
};
const deriveZeroRhsC = (inputs) => {
  const [input0, input1] = inputs.map(BigInt);
  const vx = scalarMod(2n + 4n * input0 + 6n * input1);
  return scalarMod(-(15n + 7n * vx) * Fr.inv(11n));
};
const denseWorstInputs = [
  40792793307691160132937706698213704133054528069427933762012433436987942497952n,
  20976222017425405296340351928930328963278634447870202382235661951061637561134n,
];
const identityBalancedInputs = [0n, scalarMod(-29n * Fr.inv(42n))];
const proof1Inputs = [135208n, 67633n];
const bIdentityC = deriveZeroRhsC(proof1Inputs);
const fixtureSpecs = {
  committed: { cacheName: 'committed', ...syntheticFixture([123n, 456n], 1n, 13n) },
  proof1: { cacheName: 'proof1', ...syntheticFixture(proof1Inputs, 17n, 19n) },
  dense: { cacheName: 'dense-worst', ...syntheticFixture(denseWorstInputs, 23n, 29n) },
  zero: { cacheName: 'zero', ...syntheticFixture([0n, 0n], 31n, 37n) },
  max: {
    cacheName: 'max-canonical',
    ...syntheticFixture([SCALAR_ORDER - 1n, SCALAR_ORDER - 1n], 41n, 43n),
  },
  'msm-identity': {
    cacheName: 'msm-identity',
    ...syntheticFixture([3n, SCALAR_ORDER - 2n], 47n, 53n),
  },
  'b-identity': {
    cacheName: 'proof1',
    ...syntheticFixture(proof1Inputs, 0n, bIdentityC, 59n),
  },
  'a-identity': {
    cacheName: 'proof1',
    ...syntheticFixture(proof1Inputs, 17n, bIdentityC, 0n),
  },
  'c-identity': {
    cacheName: 'proof1',
    ...syntheticFixture(proof1Inputs, 17n, 0n),
  },
  'all-identity': {
    cacheName: 'identity-balanced',
    ...syntheticFixture(identityBalancedInputs, 0n, 0n, 0n),
  },
};
assert(fixtureSpecs.committed.proof.a.equals(committedProof.a) &&
  fixtureSpecs.committed.proof.b.equals(committedProof.b) &&
  fixtureSpecs.committed.proof.c.equals(committedProof.c),
'committed synthetic proof changed');
const activeFixtureName = process.env.RPA_PROOF_FIXTURE ?? 'committed';
const activeFixture = fixtureSpecs[activeFixtureName];
assert(activeFixture !== undefined, `unknown RPA_PROOF_FIXTURE: ${activeFixtureName}`);
const activePublicInputs = activeFixture.inputs;
const semanticProof = activeFixture.proof;
const bIdentity = semanticProof.b.is0();
const effectiveProof = bIdentity ? {
  a: G1.ZERO,
  b: B_IDENTITY_SUBSTITUTE,
  c: semanticProof.c,
} : semanticProof;

const picCachePath = PIC32_RECORDS ? (process.env.RPA_GT_CACHE ?? (() => {
    throw new Error('RPA_GT_CACHE is required when RPA_PIC32=1');
  })()) : null;
const picCacheBytes = PIC32_RECORDS ? readFileSync(picCachePath) : null;
const picCache = PIC32_RECORDS ? JSON.parse(picCacheBytes.toString('utf8')) : null;
const picFixtureNames = [activeFixture.cacheName];
const publicInputsFromPicRecords = (records) => [0, 1].map((bytePosition) => records.reduce(
  (value, record, window) => value |
    (BigInt((record.index >> (bytePosition * 8)) & 0xff) << BigInt(window * 8)),
  0n,
));
const picFixtureRecords = picCache?.records?.[activeFixture.cacheName] ?? [];
assert(!PIC32_RECORDS || activePublicInputs.every((value) => value >= 0n && value < SCALAR_ORDER),
  'v4 PIC fixture public scalar is noncanonical');
assert(!PIC32_RECORDS || publicInputsFromPicRecords(picFixtureRecords)
  .every((value, index) => value === activePublicInputs[index]),
`v4 ${activeFixture.cacheName} PIC fixture changed public inputs`);

const framePrefix = (tag, payloadLength) => {
  const tagBytes = Uint8Array.from(Buffer.from(tag, 'ascii'));
  if (tagBytes.length > 255) throw new Error('frame tag is too long');
  return concat(MAGIC, Uint8Array.of(tagBytes.length), tagBytes, u32(payloadLength));
};
const frame = (tag, payload) => concat(framePrefix(tag, payload.length), payload);
const digestToUnsignedLe = (digest) => digest.reduceRight(
  (value, byte) => (value << 8n) + BigInt(byte),
  0n,
);

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
const scale = (polynomial, scalar) => trim(polynomial.map(
  (coefficient) => coefficient * scalar,
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
const evaluate = (polynomial, point) => polynomial.reduceRight(
  (accumulator, coefficient) => mod(accumulator * point + coefficient),
  0n,
);

const fp6Limbs = (value) => [
  value.c0.c0, value.c0.c1,
  value.c1.c0, value.c1.c1,
  value.c2.c0, value.c2.c1,
];
const fp6ToFlat = (value) => {
  const limbs = fp6Limbs(value);
  return [
    limbs[0] - limbs[1], limbs[2] - limbs[3], limbs[4] - limbs[5],
    limbs[1], limbs[3], limbs[5],
  ].map(mod);
};
const flatToFp6 = (flat) => Fp6.fromBigSix([
  mod(flat[0] + flat[3]), mod(flat[3]),
  mod(flat[1] + flat[4]), mod(flat[4]),
  mod(flat[2] + flat[5]), mod(flat[5]),
]);
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

// Canonical complete encoding: chart 0 is used whenever c0 is nonzero; chart 1
// is reserved for the unique infinity class [0:1], encoded with u=0. This
// removes overlap without dropping any quotient class.
const canonicalChart = (value) => {
  assert(!Fp12.eql(value, Fp12.ZERO), 'zero has no quotient-torus chart');
  if (!Fp6.eql(value.c0, Fp6.ZERO)) {
    const u = Fp6.mul(value.c1, Fp6.inv(value.c0));
    const representative = Fp12.create({ c0: Fp6.ONE, c1: u });
    assert(sameClass(value, representative), 'chart-0 reconstruction changed the class');
    return { flag: 0, u, representative };
  }
  assert(!Fp6.eql(value.c1, Fp6.ZERO), 'nonzero class has two zero components');
  const representative = Fp12.create({ c0: Fp6.ZERO, c1: Fp6.ONE });
  assert(sameClass(value, representative), 'chart-1 reconstruction changed the class');
  return { flag: 1, u: Fp6.ZERO, representative };
};

const relationFor = (components, outputChart) => {
  const output = fp6ToFlat(outputChart.u);
  const selected = outputChart.flag === 0 ? components[0] : components[1];
  const other = outputChart.flag === 0 ? components[1] : components[0];
  const crossResidual = subtract(other, multiply(selected, output));
  const reducedSelected = flatToFp6(reduceFp6(selected));
  assert(!Fp6.eql(reducedSelected, Fp6.ZERO), 'selected projective scale is zero');
  const selectedInverse = fp6ToFlat(Fp6.inv(reducedSelected));
  const inverseResidual = subtract(multiply(selected, selectedInverse), [1n]);
  const cross = divideFp6(crossResidual);
  const inverse = divideFp6(inverseResidual);
  assert(cross.remainder.every((coefficient) => coefficient === 0n), 'cross remainder is nonzero');
  assert(inverse.remainder.every((coefficient) => coefficient === 0n), 'inverse remainder is nonzero');
  return {
    crossResidual,
    inverseResidual,
    crossQuotient: cross.quotient,
    inverseQuotient: inverse.quotient,
    selectedInverse,
  };
};

const serializeLimbs = (limbs) => concat(...limbs.map((limb) => le48Exact(mod(limb))));
const serializeUnsignedLe = (value, width) => {
  let remaining = value;
  const output = new Uint8Array(width);
  for (let index = 0; index < width; index += 1) {
    output[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  assert(remaining === 0n, `value does not fit in ${width} bytes`);
  return output;
};
const serializePolynomial = (polynomial, coefficientCount) => concat(...Array.from(
  { length: coefficientCount },
  (_, index) => le48Exact(polynomial[coefficientCount - 1 - index] ?? 0n),
));

const fullPairs = pairsFor(activePublicInputs, effectiveProof);
const pairs = pairsFor(activePublicInputs, effectiveProof, { msmOnly: true });
const fixedMiller = fixedVkMiller(pairs, true);
const selectedBoundary = millerFusedAffineDirect8Ops(
  pairs,
  Fp12.ONE,
  Fp12.ONE,
  { fixedMiller, skipPairs: TRACE_SKIP_PAIRS },
).boundary;
const gammaMsmMiller = Fp12.conjugate(singlePairMiller(pairs[2]).f);
assert(!SKIP_GAMMA || !Fp6.eql(gammaMsmMiller.c0, Fp6.ZERO),
  'aggregate gamma MSM factor has no finite quotient-torus coordinate');
const gammaTorusU = SKIP_GAMMA
  ? Fp6.mul(gammaMsmMiller.c1, Fp6.inv(gammaMsmMiller.c0))
  : Fp6.ZERO;
const gammaTorusFactor = Fp12.create({ c0: Fp6.ONE, c1: gammaTorusU });
assert(!SKIP_GAMMA || sameClass(gammaMsmMiller, gammaTorusFactor),
  'aggregate gamma torus lift changed its projective class');
const regularPicCarrierBlocks = [2, 3, ...Array.from({ length: 10 }, (_, index) => index + 5),
  16, 17, 18, 19];
const regularPicWindowBlocks = regularPicCarrierBlocks.flatMap((blockIndex) => [blockIndex, blockIndex]);
const regularPicRemainingSquares = regularPicWindowBlocks.map((blockIndex) => 3 * (20 - blockIndex));
const PIC_FLAT_RECORDS = PIC32_RECORDS && picCache.version === 4;
assert(!PIC32_RECORDS || (
  (picCache.version === 3 || picCache.version === 4) &&
  picCache.layout === 'uniform-regular' &&
  picCache.merkleDomain === (PIC_FLAT_RECORDS ? 'BLSGTF1' : 'BLSGTR1') &&
  picCache.recordEncoding === (PIC_FLAT_RECORDS
    ? 'canonical-conjugated-flat-fp6'
    : 'canonical-standard-fp6') &&
  picCache.carrierBlocks.join(',') === regularPicCarrierBlocks.join(',') &&
  picCache.windowBlocks.join(',') === regularPicWindowBlocks.join(',') &&
  picCache.windowRemainingSquares.join(',') === regularPicRemainingSquares.join(',')
), 'position-adjusted PIC cache schedule changed');
const picRecords = picFixtureRecords.map((record) => ({
  index: record.index,
  carrierBlock: record.carrierBlock,
  remainingSquares: record.remainingSquares,
  authenticatedLimbs: (PIC_FLAT_RECORDS ? record.factor : record.u).map(BigInt),
  terminalLimbs: (PIC_FLAT_RECORDS ? record.terminalFactor : record.terminalU).map(BigInt),
  path: Uint8Array.from(Buffer.from(record.path, 'hex')),
})) ?? [];
assert(!PIC32_RECORDS || picRecords.length === 32, 'PIC record count changed');
assert(!PIC32_RECORDS || picRecords.every((record, window) =>
  record.authenticatedLimbs.length === 6 && record.path.length === 512 &&
    record.terminalLimbs.length === 6 &&
    record.authenticatedLimbs.every((limb) => limb >= 0n && limb < P) &&
    record.terminalLimbs.every((limb) => limb >= 0n && limb < P) &&
    record.carrierBlock === regularPicWindowBlocks[window] &&
    record.remainingSquares === regularPicRemainingSquares[window]),
'PIC record encoding changed');
picRecords.forEach((record) => {
  if (PIC_FLAT_RECORDS) {
    record.factor = record.authenticatedLimbs;
    record.terminalFactor = flatToFp6(record.terminalLimbs);
  } else {
    record.factor = fp6ToFlat(Fp6.neg(Fp6.fromBigSix(record.authenticatedLimbs)));
    record.terminalFactor = Fp6.neg(Fp6.fromBigSix(record.terminalLimbs));
  }
});
const picTerminalPreconjugateProduct = picRecords.reduce((product, record) => Fp12.mul(
  product,
  Fp12.create({ c0: Fp6.ONE, c1: record.terminalFactor }),
), Fp12.ONE);
assert(!PIC32_RECORDS || Fp12.eql(
  Fp12.finalExponentiate(picTerminalPreconjugateProduct),
  Fp12.finalExponentiate(gammaMsmMiller),
), 'PIC factors do not restore the gamma MSM final-exponent class');
const gammaRestoration = PIC32_RECORDS ? picTerminalPreconjugateProduct : gammaMsmMiller;
const selectedBoundaryWithGamma = SKIP_GAMMA
  ? Fp12.mul(selectedBoundary, gammaRestoration)
  : selectedBoundary;
const fullBoundary = millerBatchOps(fullPairs).boundary;
assert(
  Fp12.eql(
    Fp12.finalExponentiate(selectedBoundaryWithGamma),
    Fp12.finalExponentiate(fullBoundary),
  ),
  'selected IC0-folded direct8 trace changed the four-pair verdict',
);
assert(Fp12.eql(Fp12.finalExponentiate(fullBoundary), Fp12.ONE),
  `${activeFixtureName} synthetic proof does not satisfy the Groth16 pairing equation`);
const residue = residueTorusWitness(selectedBoundaryWithGamma);
const trace = millerFusedAffineDirect8Ops(
  pairs,
  residue.c,
  residue.cInv,
  { torusU: residue.u, fixedMiller, skipPairs: TRACE_SKIP_PAIRS },
);
const squareIndices = trace.ops.flatMap((op, index) => op.t === 'sqr' ? [index] : []);
const fixedFoldIndex = trace.ops.findIndex((op) => op.t === 'cmul1');
assert(squareIndices.length === 63, 'binary round count changed');
assert(ATE_LOOP_DIGITS.filter((digit) => digit !== 0).length === 5, 'binary addition count changed');
assert(trace.ops.length === (SKIP_GAMMA ? 205 : 273), 'fused operation count changed');
assert(fixedFoldIndex === (SKIP_GAMMA ? 204 : 272), 'fixed Miller fold position changed');
assert(trace.ops.filter((op) => op.t === 'dl').length === (SKIP_GAMMA ? 126 : 189),
  'doubling-line count changed');
assert(trace.ops.filter((op) => op.t === 'al').length === (SKIP_GAMMA ? 10 : 15),
  'addition-line count changed');
assert(trace.ops.filter((op) => op.t === 'cf').length === 5, 'residue-fold count changed');

const blockRanges = Array.from(
  { length: Math.ceil(squareIndices.length / DEPTH) },
  (_, blockIndex) => {
    const roundLo = blockIndex * DEPTH;
    const roundHi = Math.min(squareIndices.length, roundLo + DEPTH);
    return {
      blockIndex,
      roundLo,
      roundHi,
      opLo: squareIndices[roundLo],
      opHi: roundHi === squareIndices.length ? fixedFoldIndex : squareIndices[roundHi],
    };
  },
);
assert(blockRanges.length === 21, 'depth-3 block count changed');

const transitionFactor = (index) => {
  const before = trace.states[index].f;
  const after = trace.states[index + 1].f;
  assert(!Fp12.eql(before, Fp12.ZERO), `transition ${index} begins at zero`);
  const factor = Fp12.mul(after, Fp12.inv(before));
  assert(Fp12.eql(Fp12.mul(before, factor), after), `transition ${index} factor changed`);
  return factor;
};
const rawBoundaryCharts = Array.from(
  { length: blockRanges.length + 1 },
  (_, index) => canonicalChart(trace.states[
    index === blockRanges.length ? fixedFoldIndex : blockRanges[index].opLo
  ].f),
);
assert(rawBoundaryCharts.every((item) => item.flag === 0),
  'raw fixture unexpectedly reached chart infinity');

const torusRoot = Fp12.create({ c0: Fp6.ONE, c1: residue.u });
const expectedTerminal = Fp12.frobeniusMap(torusRoot, 1);
const restoredTraceBoundary = SKIP_GAMMA
  ? Fp12.mul(trace.boundary, gammaRestoration)
  : trace.boundary;
assert(sameClass(restoredTraceBoundary, expectedTerminal),
  'six-limb residue terminal changed class');
assert(Fp6.eql(residue.w.c1, Fp6.ZERO), 'residue correction does not vanish in the quotient');
const terminalChart = canonicalChart(expectedTerminal);
assert(terminalChart.flag === 0, 'fixture terminal unexpectedly reached chart infinity');
const fixedFactor = transitionFactor(fixedFoldIndex);
const fixedTorusFlat = fp6ToFlat(Fp6.mul(fixedFactor.c1, Fp6.inv(fixedFactor.c0)));
const flatY = flatToFp6([0n, 1n, 0n, 0n, 0n, 0n]);
assert(
  Fp6.eql(Fp6.pow(flatY, (P ** 6n - 1n) / 2n), Fp6.neg(Fp6.ONE)),
  'Y became a square in Fp6; W^2-Y is not certified irreducible',
);
trace.ops.forEach((op, index) => {
  if (op.t === 'sqr' || op.t === 'cmul1') return;
  const [low] = pairFor(transitionFactor(index));
  assert(low.length === 1 && low[0] === 1n,
    `transition ${index} lost its universal 1+W*t shape`);
});
assert(!Fp6.eql(fixedFactor.c0, Fp6.ZERO), 'fixed fold has no finite 1+W*t representative');
const universalNonzeroFactorCertificate = true;
assert(INVERSE_RELATIONS || universalNonzeroFactorCertificate,
  'inverse-free mode requires the universal nonzero-factor certificate');

const picLayout = process.env.RPA_PIC_LAYOUT ?? 'regular';
assert(['regular', 'low'].includes(picLayout), 'unknown PIC carrier layout');
const lowPicCarrierBlocks = [3, 4, ...Array.from({ length: 10 }, (_, index) => index + 5),
  16, 17, 18, 19];
assert(!PIC32_RECORDS || picLayout === 'regular',
  'the certified position-adjusted cache is bound to the uniform Regular layout');
const picCarrierBlocks = picLayout === 'regular' ? regularPicCarrierBlocks : lowPicCarrierBlocks;
assert(picCarrierBlocks.length === 16 && new Set(picCarrierBlocks).size === 16,
  'PIC carrier allocation changed');
const liftRecordsByBlock = Array.from({ length: blockRanges.length }, () => []);
if (PIC32_RECORDS) {
  picCarrierBlocks.forEach((blockIndex, carrierIndex) => {
    liftRecordsByBlock[blockIndex] = picRecords.slice(carrierIndex * 2, carrierIndex * 2 + 2);
  });
} else if (SKIP_GAMMA) {
  liftRecordsByBlock[blockRanges.length - 1] = [{
    factor: fp6ToFlat(gammaTorusU),
    payload: serializeLimbs(fp6ToFlat(gammaTorusU)),
    path: new Uint8Array(),
  }];
}
picRecords.forEach((record) => {
  record.payload = concat(serializeLimbs(record.authenticatedLimbs), record.path);
});
assert(!PIC32_RECORDS || sum(liftRecordsByBlock, (records) => records.length) === 32,
  'PIC record allocation changed');
assert(!SKIP_GAMMA || PIC32_RECORDS || sum(liftRecordsByBlock, (records) => records.length) === 1,
  'aggregate gamma factor hook count changed');
// Replay the lifted trace itself. A factor inserted after block b is squared by
// every later Miller round, so multiplying raw trace boundaries by a cumulative
// product is not equivalent. Position-adjusted records are certified such that
// these later squarings restore their intended terminal GT values.
const boundaryCharts = [rawBoundaryCharts[0]];
let liftedState = rawBoundaryCharts[0].representative;
blockRanges.forEach((range, blockIndex) => {
  for (let index = range.opLo; index < range.opHi; index += 1) {
    liftedState = trace.ops[index].t === 'sqr'
      ? Fp12.sqr(liftedState)
      : Fp12.mul(liftedState, transitionFactor(index));
  }
  liftRecordsByBlock[blockIndex].forEach((record) => {
    liftedState = Fp12.mul(
      liftedState,
      Fp12.create({ c0: Fp6.ONE, c1: flatToFp6(record.factor) }),
    );
  });
  boundaryCharts.push(canonicalChart(liftedState));
});
assert(boundaryCharts.length === blockRanges.length + 1,
  'lifted boundary count changed');
assert(boundaryCharts.every((item) => item.flag === 0),
  'lifted fixture unexpectedly reached chart infinity');
assert(sameClass(
  boundaryCharts.at(-1).representative,
  Fp12.mul(trace.states[fixedFoldIndex].f, gammaRestoration),
), 'position-adjusted factors did not restore the intended terminal class');
const blockRecords = blockRanges.map((range, blockIndex) => {
  let components = pairFor(boundaryCharts[blockIndex].representative);
  let splitRelation;
  for (let index = range.opLo; index < range.opHi; index += 1) {
    components = trace.ops[index].t === 'sqr'
      ? pairSquare(components)
      : pairMultiply(components, pairFor(transitionFactor(index)));
    if (SPLIT_RELATION_BLOCKS.includes(blockIndex) &&
      index - range.opLo + 1 === SPLIT_AFTER_OPERATION_COUNT) {
      const splitValue = Fp12.create({
        c0: flatToFp6(reduceFp6(components[0])),
        c1: flatToFp6(reduceFp6(components[1])),
      });
      const splitChart = canonicalChart(splitValue);
      splitRelation = {
        operationCount: index - range.opLo + 1,
        chart: splitChart,
        relation: relationFor(components, splitChart),
      };
      components = pairFor(splitChart.representative);
    }
  }
  assert(!SPLIT_RELATION_BLOCKS.includes(blockIndex) || splitRelation !== undefined,
    `block ${blockIndex} split relation was not created`);
  const liftRecords = liftRecordsByBlock[blockIndex];
  liftRecords.forEach((record) => {
    components = pairMultiply(components, [[1n], record.factor]);
  });
  const relation = relationFor(components, boundaryCharts[blockIndex + 1]);
  const operations = trace.ops.slice(range.opLo, range.opHi);
  const runtimeOps = operations.filter((op) => op.t !== 'sqr' && op.j === 0);
  const fixedOps = operations.filter((op) => op.t !== 'sqr' && (op.j === 2 || op.j === 3));
  const runtimeSlopes = runtimeOps.flatMap((op) => [op.coeffs[1].c0, op.coeffs[1].c1]);
  const fixedCoefficients = fixedOps.flatMap((op) => [
    op.coeffs[0].c0, op.coeffs[0].c1,
    op.coeffs[1].c0, op.coeffs[1].c1,
  ]);
  const fixedBlob = serializeLimbs(fixedCoefficients);

  let cursor = 0;
  const layout = { outputU: cursor };
  cursor += 6 * W;
  layout.outputFlag = cursor;
  cursor += 1;
  if (INVERSE_RELATIONS) {
    layout.outputInverse = cursor;
    cursor += 6 * W;
  }
  layout.outputR = cursor;
  cursor += 4 * W;
  layout.runtimeSlopes = cursor;
  cursor += runtimeSlopes.length * W;
  layout.fixedCoefficients = cursor;
  cursor += fixedBlob.length;
  layout.liftRecords = cursor;
  cursor += sum(liftRecords, (record) => record.payload.length);
  if (splitRelation !== undefined) {
    layout.splitU = cursor;
    cursor += 6 * W;
    layout.splitFlag = cursor;
    cursor += 1;
  }

  const parts = [
    serializeLimbs(fp6ToFlat(boundaryCharts[blockIndex + 1].u)),
    Uint8Array.of(boundaryCharts[blockIndex + 1].flag),
  ];
  if (INVERSE_RELATIONS) parts.push(serializeLimbs(relation.selectedInverse));
  parts.push(
    serializeLimbs(r4limbs(trace.states[range.opHi].Rs[0])),
    serializeLimbs(runtimeSlopes),
    fixedBlob,
    ...liftRecords.map((record) => record.payload),
  );
  if (splitRelation !== undefined) {
    parts.push(
      serializeLimbs(fp6ToFlat(splitRelation.chart.u)),
      Uint8Array.of(splitRelation.chart.flag),
    );
  }
  return {
    ...range,
    operations,
    runtimeOps,
    fixedOps,
    runtimeSlopes,
    fixedCoefficients,
    liftRecords,
    fixedCommitment: sha256(fixedBlob),
    layout,
    payloadCursor: cursor,
    payloadParts: parts,
    splitRelation,
    relation,
    componentDegrees: components.map((component) => component.length - 1),
  };
});

const terminalComponents = pairMultiply(
  pairFor(boundaryCharts.at(-1).representative),
  pairFor(fixedFactor),
);
const terminalRelation = relationFor(terminalComponents, terminalChart);
const lastRecord = blockRecords.at(-1);
if (INVERSE_RELATIONS) {
  lastRecord.layout.terminalInverse = lastRecord.payloadCursor;
  lastRecord.payloadCursor += 6 * W;
  lastRecord.payloadParts.push(serializeLimbs(terminalRelation.selectedInverse));
}
lastRecord.terminalRelation = terminalRelation;

const degreeSum = (left, right) => left === Number.NEGATIVE_INFINITY ||
  right === Number.NEGATIVE_INFINITY
  ? Number.NEGATIVE_INFINITY
  : left + right;
const segmentDegreeCeiling = (operations, trailingFactorCount = 0) => {
  let maximumRelationDegree = Number.NEGATIVE_INFINITY;
  [0, 1].forEach((inputChart) => {
    let degrees = inputChart === 0 ? [0, 5] : [Number.NEGATIVE_INFINITY, 0];
    [...operations, ...Array.from({ length: trailingFactorCount }, () => ({ t: 'factor' }))]
      .forEach((operation) => {
        if (operation.t === 'sqr') {
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
      });
    const chart0Degree = Math.max(degrees[1], degreeSum(degrees[0], 5));
    const chart1Degree = degrees[0];
    maximumRelationDegree = Math.max(maximumRelationDegree, chart0Degree, chart1Degree);
  });
  return {
    maximumRelationDegree,
    maximumQuotientCoefficients: maximumRelationDegree - 5,
  };
};
const universalDegreeSegments = blockRecords.flatMap((record) => {
  if (record.splitRelation === undefined) {
    return [{
      blockIndex: record.blockIndex,
      segment: 0,
      ...segmentDegreeCeiling(record.operations, record.liftRecords.length),
    }];
  }
  return [
    {
      blockIndex: record.blockIndex,
      segment: 0,
      ...segmentDegreeCeiling(record.operations.slice(0, record.splitRelation.operationCount)),
    },
    {
      blockIndex: record.blockIndex,
      segment: 1,
      ...segmentDegreeCeiling(
        record.operations.slice(record.splitRelation.operationCount),
        record.liftRecords.length,
      ),
    },
  ];
});
const terminalDegreeCeiling = segmentDegreeCeiling([{ t: 'factor' }]);
const secondSplitBoundaryScan = Array.from(
  { length: blockRecords[15].operations.length - 1 },
  (_, index) => {
    const operationCount = index + 1;
    const prefix = segmentDegreeCeiling(
      blockRecords[15].operations.slice(0, operationCount),
    );
    const suffix = segmentDegreeCeiling(
      blockRecords[15].operations.slice(operationCount),
      blockRecords[15].liftRecords.length,
    );
    const otherMaximum = Math.max(
      terminalDegreeCeiling.maximumRelationDegree,
      ...universalDegreeSegments
        .filter((segment) => segment.blockIndex !== 15)
        .map((segment) => segment.maximumRelationDegree),
    );
    return {
      operationCount,
      operationType: blockRecords[15].operations[index].t,
      prefixMaximumRelationDegree: prefix.maximumRelationDegree,
      suffixMaximumRelationDegree: suffix.maximumRelationDegree,
      universalMaximumRelationDegree: Math.max(
        otherMaximum,
        prefix.maximumRelationDegree,
        suffix.maximumRelationDegree,
      ),
    };
  },
);
const degreeOptimalSecondSplit = secondSplitBoundaryScan.reduce((best, candidate) => {
  const candidateLocalMaximum = Math.max(
    candidate.prefixMaximumRelationDegree,
    candidate.suffixMaximumRelationDegree,
  );
  const bestLocalMaximum = Math.max(
    best.prefixMaximumRelationDegree,
    best.suffixMaximumRelationDegree,
  );
  return candidate.universalMaximumRelationDegree < best.universalMaximumRelationDegree ||
    (candidate.universalMaximumRelationDegree === best.universalMaximumRelationDegree &&
      candidateLocalMaximum < bestLocalMaximum)
    ? candidate
    : best;
});
const universalMaximumRelationDegree = Math.max(
  terminalDegreeCeiling.maximumRelationDegree,
  ...universalDegreeSegments.map((segment) => segment.maximumRelationDegree),
);
const universalMaximumQuotientCoefficients = Math.max(
  terminalDegreeCeiling.maximumQuotientCoefficients,
  ...universalDegreeSegments.map((segment) => segment.maximumQuotientCoefficients),
);
assert(secondSplitBoundaryScan.length === blockRecords[15].operations.length - 1 &&
  secondSplitBoundaryScan.every(({ operationCount }, index) => operationCount === index + 1),
'block-15 split boundary scan is incomplete');
assert(degreeOptimalSecondSplit.operationCount === SPLIT_AFTER_OPERATION_COUNT &&
  degreeOptimalSecondSplit.universalMaximumRelationDegree === 137,
'block-15 split boundary optimum changed');
assert(universalMaximumRelationDegree === 137 &&
  universalMaximumQuotientCoefficients === QUOTIENT_COEFFICIENTS,
'block-0-and-15 split universal quotient ceiling changed');

blockRecords.forEach((record) => {
  record.payload = concat(...record.payloadParts);
  assert(record.payload.length === record.payloadCursor, `block ${record.blockIndex} payload layout changed`);
});
const blockPayloads = blockRecords.map((record) => record.payload);
assert(sum(blockRecords, (record) => record.runtimeOps.length) === 68, 'runtime line count changed');
assert(sum(blockRecords, (record) => record.fixedOps.length) === (SKIP_GAMMA ? 68 : 136),
  'fixed line count changed');
assert(sum(blockRecords, (record) => record.fixedCoefficients.length * W) ===
  (SKIP_GAMMA ? 13_056 : 26_112),
  'fixed table byte count changed');
assert(
  Math.max(...blockRecords.flatMap((record) => [
    ...(record.splitRelation === undefined ? [] : [
      record.splitRelation.relation.crossQuotient.length,
      record.splitRelation.relation.inverseQuotient.length,
    ]),
    record.relation.crossQuotient.length,
    record.relation.inverseQuotient.length,
  ]), terminalRelation.crossQuotient.length, terminalRelation.inverseQuotient.length) <=
    QUOTIENT_COEFFICIENTS,
  'canonical-chart quotient exceeds the structural d3 width',
);

const effectiveProofB = effectiveProof.b.toAffine();
const identitySubstituteB = B_IDENTITY_SUBSTITUTE.toAffine();
const unitPairIndices = SKIP_GAMMA ? [0, 3] : [0, 2, 3];
const units = unitPairIndices.flatMap((index) => {
  const unit = unitG1(pairs[index].P);
  return [unit.u, unit.v];
});
const statementFields = [
  ['Bidentity', bIdentity ? 1n : 0n, 2n, 1],
  ['effectiveBxa', effectiveProofB.x.c0, P, W], ['effectiveBxb', effectiveProofB.x.c1, P, W],
  ['effectiveBya', effectiveProofB.y.c0, P, W], ['effectiveByb', effectiveProofB.y.c1, P, W],
  ['public0', activePublicInputs[0], SCALAR_ORDER, 32],
  ['public1', activePublicInputs[1], SCALAR_ORDER, 32],
  ...fp6ToFlat(residue.u).map((value, index) => [`root${index}`, value, P, W]),
  ['p0u', units[0], P, W], ['p0v', units[1], P, W],
  ...(SKIP_GAMMA ? [
    ['p3u', units[2], P, W], ['p3v', units[3], P, W],
  ] : [
    ['p2u', units[2], P, W], ['p2v', units[3], P, W],
    ['p3u', units[4], P, W], ['p3v', units[5], P, W],
  ]),
];
const statementIndex = Object.fromEntries(statementFields.map(([name], index) => [name, index]));
const statementLimbs = statementFields.map(([, value]) => value);
let statementCursor = 0;
const statementLayout = statementFields.map(([, , , width]) => {
  const offset = statementCursor;
  statementCursor += width;
  return { offset, width };
});
const statementBytes = concat(...statementFields.map(([, value, , width]) =>
  serializeUnsignedLe(value, width)));
assert(statementLimbs.length === (SKIP_GAMMA ? 17 : 19) &&
  statementBytes.length === (SKIP_GAMMA ? 737 : 833), 'statement layout changed');
const unitCurveHolds = (u, v) => mod(v - 4n * u * u * u - 16n * v * v * v) === 0n;
assert(unitCurveHolds(units[0], units[1]), 'proof A unit encoding is off curve');
if (!SKIP_GAMMA) assert(unitCurveHolds(units[2], units[3]), 'MSM unit encoding is off curve');
assert(unitCurveHolds(units.at(-2), units.at(-1)), 'proof C unit encoding is off curve');

const treeFor = (payloads, metadataLengths = payloads.map((payload) => payload.length)) => {
  assert(payloads.length === metadataLengths.length, 'tree metadata length mismatch');
  let nodes = payloads.map((payload, index) => sha256(frame('leaf', concat(
    u32(index), u32(payloads.length), u32(metadataLengths[index]), payload,
  ))));
  let level = 0;
  while (nodes.length > 1) {
    const next = [];
    for (let index = 0; index < nodes.length; index += 2) {
      const left = nodes[index];
      const right = nodes[index + 1] ?? left;
      next.push(sha256(frame('node', concat(u32(level), u32(index / 2), left, right))));
    }
    nodes = next;
    level += 1;
  }
  return nodes[0];
};

const commitmentPayloads = [statementBytes, ...blockPayloads];
const commitmentRoot = treeFor(commitmentPayloads);
const splitCommitmentMutationPayloads = commitmentPayloads.map((payload) => Uint8Array.from(payload));
splitCommitmentMutationPayloads[1][blockRecords[0].layout.splitU] ^= 1;
const splitCommitmentMutationRoot = treeFor(splitCommitmentMutationPayloads);
assert(!equalBytes(commitmentRoot, splitCommitmentMutationRoot),
  'split U is not bound by the pre-beta commitment root');
const betaDigest = sha256(frame('beta', concat(u32(blockPayloads.length), commitmentRoot)));
const splitCommitmentMutationBeta = sha256(frame(
  'beta',
  concat(u32(blockPayloads.length), splitCommitmentMutationRoot),
));
assert(!equalBytes(betaDigest, splitCommitmentMutationBeta),
  'split U commitment mutation did not change beta');
const secondSplitCommitmentMutationPayloads = commitmentPayloads.map(
  (payload) => Uint8Array.from(payload),
);
secondSplitCommitmentMutationPayloads[16][blockRecords[15].layout.splitU] ^= 1;
const secondSplitCommitmentMutationRoot = treeFor(secondSplitCommitmentMutationPayloads);
assert(!equalBytes(commitmentRoot, secondSplitCommitmentMutationRoot),
  'block-15 split U is not bound by the pre-beta commitment root');
const secondSplitCommitmentMutationBeta = sha256(frame(
  'beta',
  concat(u32(blockPayloads.length), secondSplitCommitmentMutationRoot),
));
assert(!equalBytes(betaDigest, secondSplitCommitmentMutationBeta),
  'block-15 split U commitment mutation did not change beta');
const beta = digestToUnsignedLe(betaDigest);
assert(beta > 0n && beta < P, 'beta is outside the nonzero base field');

const relationStartExponent = (blockIndex) => blockIndex +
  SPLIT_RELATION_BLOCKS.filter((splitBlockIndex) => splitBlockIndex < blockIndex).length;
const relationRecords = [];
blockRecords.forEach((record) => {
  if (record.splitRelation !== undefined) {
    relationRecords.push({ blockIndex: record.blockIndex, kind: 'split-cross',
      residual: record.splitRelation.relation.crossResidual,
      quotient: record.splitRelation.relation.crossQuotient });
  }
  relationRecords.push({ blockIndex: record.blockIndex, kind: 'cross',
    residual: record.relation.crossResidual, quotient: record.relation.crossQuotient });
  if (INVERSE_RELATIONS) {
    relationRecords.push({ blockIndex: record.blockIndex, kind: 'inverse',
      residual: record.relation.inverseResidual, quotient: record.relation.inverseQuotient });
  }
  if (record.terminalRelation !== undefined) {
    relationRecords.push({ blockIndex: record.blockIndex, kind: 'terminal-cross',
      residual: record.terminalRelation.crossResidual,
      quotient: record.terminalRelation.crossQuotient });
    if (INVERSE_RELATIONS) {
      relationRecords.push({ blockIndex: record.blockIndex, kind: 'terminal-inverse',
        residual: record.terminalRelation.inverseResidual,
        quotient: record.terminalRelation.inverseQuotient });
    }
  }
});
assert(relationRecords.length === (INVERSE_RELATIONS ? 44 : 22 + SPLIT_RELATION_BLOCKS.length),
  'relation count changed');
let expectedRelationExponent = 0;
blockRecords.forEach((record) => {
  assert(relationStartExponent(record.blockIndex) === expectedRelationExponent,
    `block ${record.blockIndex} relation start exponent changed`);
  expectedRelationExponent += record.splitRelation === undefined ? 1 : 2;
  if (record.terminalRelation !== undefined) expectedRelationExponent += 1;
});
assert(expectedRelationExponent === relationRecords.length,
  'relation exponents are not contiguous');
let relationPower = 1n;
let combinedQuotient = [0n];
relationRecords.forEach((record) => {
  combinedQuotient = add(combinedQuotient, scale(record.quotient, relationPower));
  relationPower = mod(relationPower * beta);
});
assert(combinedQuotient.length <= QUOTIENT_COEFFICIENTS, 'combined quotient exceeds d3 width');
const paddedQuotient = Array.from(
  { length: QUOTIENT_COEFFICIENTS },
  (_, index) => combinedQuotient[index] ?? 0n,
);
const quotientBytes = serializePolynomial(paddedQuotient, QUOTIENT_COEFFICIENTS);
const FUSED_QUOTIENT_TAIL_COEFFICIENTS = Number(
  process.env.RPA_Q_TAIL_COEFFICIENTS ?? 22,
);
assert(Number.isInteger(FUSED_QUOTIENT_TAIL_COEFFICIENTS) &&
  FUSED_QUOTIENT_TAIL_COEFFICIENTS >= 21 && FUSED_QUOTIENT_TAIL_COEFFICIENTS <= 25,
'fused quotient tail coefficient count is outside the audited sweep');
const quotientChunkCounts = Array.from(
  { length: QUOTIENT_CARRIERS },
  (_, index) => Math.floor(QUOTIENT_COEFFICIENTS / QUOTIENT_CARRIERS) +
    (index < QUOTIENT_COEFFICIENTS % QUOTIENT_CARRIERS ? 1 : 0),
);
const quotientPayloads = [];
let quotientByteCursor = 0;
quotientChunkCounts.forEach((count) => {
  quotientPayloads.push(quotientBytes.slice(quotientByteCursor, quotientByteCursor + count * W));
  quotientByteCursor += count * W;
});
assert(quotientByteCursor === quotientBytes.length, 'quotient payload split changed');
const fusedQuotientTailBytes = FUSED_QUOTIENT_TAIL_COEFFICIENTS * W;
const fusedQuotientHeadPayload = quotientBytes.slice(
  0,
  quotientBytes.length - fusedQuotientTailBytes,
);
const fusedQuotientTailPayload = quotientBytes.slice(
  quotientBytes.length - fusedQuotientTailBytes,
);
assert(fusedQuotientHeadPayload.length + fusedQuotientTailPayload.length ===
  quotientBytes.length && equalBytes(
    concat(fusedQuotientHeadPayload, fusedQuotientTailPayload),
    quotientBytes,
  ),
'fused quotient physical chunks changed logical coefficient order');
const quotientRoot = treeFor(
  quotientPayloads,
  quotientPayloads.map(() => quotientBytes.length),
);
const quotientCommitmentMutationPayloads = quotientPayloads.map(
  (payload) => Uint8Array.from(payload),
);
quotientCommitmentMutationPayloads[0][quotientCommitmentMutationPayloads[0].length - 1] ^= 1;
const quotientCommitmentMutationRoot = treeFor(
  quotientCommitmentMutationPayloads,
  quotientCommitmentMutationPayloads.map(() => quotientBytes.length),
);
assert(!equalBytes(quotientRoot, quotientCommitmentMutationRoot),
  'q132 coefficient mutation did not change the quotient root');
const alphaDigest = sha256(frame('alpha', concat(commitmentRoot, quotientRoot)));
const quotientCommitmentMutationAlpha = sha256(frame(
  'alpha',
  concat(commitmentRoot, quotientCommitmentMutationRoot),
));
assert(!equalBytes(alphaDigest, quotientCommitmentMutationAlpha),
  'q132 root mutation did not change alpha');
const alpha = digestToUnsignedLe(alphaDigest);
assert(alpha < P, 'alpha is outside the base field');
const transcriptHeader = concat(commitmentRoot, quotientRoot, betaDigest, alphaDigest);
assert(transcriptHeader.length === 128, 'transcript header length changed');

const terminalInputAtAlpha = pairFor(boundaryCharts.at(-1).representative)
  .map((component) => evaluate(component, alpha));
const fixedAtAlpha = evaluate(fixedTorusFlat, alpha);
const terminalStateAtAlpha = [
  mod(terminalInputAtAlpha[0] + alpha * terminalInputAtAlpha[1] * fixedAtAlpha),
  mod(terminalInputAtAlpha[1] + terminalInputAtAlpha[0] * fixedAtAlpha),
];
const terminalExpectedAtAlpha = evaluate(fp6ToFlat(terminalChart.u), alpha);
assert(
  mod(terminalStateAtAlpha[1] - terminalStateAtAlpha[0] * terminalExpectedAtAlpha) ===
    evaluate(terminalRelation.crossResidual, alpha),
  'compiled-form terminal cross evaluation differs from its polynomial relation',
);
assert(
  mod(terminalStateAtAlpha[0] * evaluate(terminalRelation.selectedInverse, alpha) - 1n) ===
    evaluate(terminalRelation.inverseResidual, alpha),
  'compiled-form terminal inverse evaluation differs from its polynomial relation',
);

let evaluationPower = 1n;
let evaluationSum = 0n;
const blockEvaluationPayloads = [];
blockRecords.forEach((record) => {
  relationRecords.filter((relation) => relation.blockIndex === record.blockIndex).forEach((relation) => {
    evaluationSum = mod(evaluationSum + evaluationPower * evaluate(relation.residual, alpha));
    evaluationPower = mod(evaluationPower * beta);
  });
  blockEvaluationPayloads.push(serializeLimbs([evaluationSum]));
});
assert(evaluationPower === relationPower, 'beta-power recurrence changed');

const quotientCoefficientsHighToLow = [...paddedQuotient].reverse();
let quotientAccumulator = 0n;
const quotientEvaluationPayloads = [];
let quotientCoefficientCursor = 0;
quotientChunkCounts.forEach((count) => {
  quotientCoefficientsHighToLow.slice(
    quotientCoefficientCursor,
    quotientCoefficientCursor + count,
  ).forEach((coefficient) => {
    quotientAccumulator = mod(quotientAccumulator * alpha + coefficient);
  });
  quotientCoefficientCursor += count;
  quotientEvaluationPayloads.push(serializeLimbs([quotientAccumulator]));
});
const alpha3 = mod(alpha * alpha * alpha);
const modulusAtAlpha = mod(alpha3 * alpha3 - 2n * alpha3 + 2n);
assert(mod(quotientAccumulator * modulusAtAlpha) === evaluationSum,
  'combined quotient evaluation does not match the relation sum');

const pushHeaderLength = (payloadLength) => encodeDataPush(new Uint8Array(payloadLength)).length - payloadLength;
const firstPushExpression = (inputIndex, payloadLength) => {
  const headerLength = pushHeaderLength(payloadLength);
  return `tx.inputs[${inputIndex}].unlockingBytecode.split(${payloadLength + headerLength})[0]` +
    `.split(${headerLength})[1]`;
};
const secondPushExpression = (inputIndex, firstLength, secondLength) => {
  const firstTotal = firstLength + pushHeaderLength(firstLength);
  const secondHeader = pushHeaderLength(secondLength);
  return `tx.inputs[${inputIndex}].unlockingBytecode.split(${firstTotal})[1]` +
    `.split(${secondLength + secondHeader})[0].split(${secondHeader})[1]`;
};
const thirdPushExpression = (inputIndex, firstLength, secondLength, thirdLength) => {
  const firstTotal = firstLength + pushHeaderLength(firstLength);
  const secondTotal = secondLength + pushHeaderLength(secondLength);
  const thirdHeader = pushHeaderLength(thirdLength);
  return `tx.inputs[${inputIndex}].unlockingBytecode.split(${firstTotal + secondTotal})[1]` +
    `.split(${thirdLength + thirdHeader})[0].split(${thirdHeader})[1]`;
};
const coordinatorHeaderExpression = firstPushExpression(0, transcriptHeader.length);
const statementExpression = secondPushExpression(0, transcriptHeader.length, statementBytes.length);
const limbExpression = (blob, offset, width = W) => offset === 0
  ? `int(${blob}.split(${width})[0] + 0x00)`
  : `int(${blob}.split(${offset + width})[0].split(${offset})[1] + 0x00)`;
const byteExpression = (blob, offset) => offset === 0
  ? `int(${blob}.split(1)[0] + 0x00)`
  : `int(${blob}.split(${offset + 1})[0].split(${offset})[1] + 0x00)`;
const statementLimbExpression = (index) => limbExpression(
  'statementBlob',
  statementLayout[index].offset,
  statementLayout[index].width,
);

const COMMON_SOURCE = `pragma cashscript ^0.14.0;

function mAdd(int x, int y) returns (int) { return (x + y) % ${P}; }
function mSub(int x, int y) returns (int) { return (x - y + ${P}) % ${P}; }
function mulFp(int x, int y) returns (int) { return (x * y) % ${P}; }
function mSqr(int x) returns (int) { return (x * x) % ${P}; }

function r2Sub(int a0,int a1,int b0,int b1) returns (int,int) {
    return mSub(a0,b0),mSub(a1,b1);
}
function r2Sc(int a0,int a1,int k) returns (int,int) {
    return mulFp(a0,k),mulFp(a1,k);
}
function r2Mul(int a0,int a1,int b0,int b1) returns (int,int) {
    return mSub(mulFp(a0,b0),mulFp(a1,b1)),mAdd(mulFp(a0,b1),mulFp(a1,b0));
}
function r2Sqr(int a0,int a1) returns (int,int) {
    return mulFp(mAdd(a0,a1),mSub(a0,a1)),mulFp(mAdd(a0,a0),a1);
}

function eval6(int c0,int c1,int c2,int c3,int c4,int c5,int a) returns (int) {
    int result = c5;
    result = mAdd(mulFp(result,a),c4);
    result = mAdd(mulFp(result,a),c3);
    result = mAdd(mulFp(result,a),c2);
    result = mAdd(mulFp(result,a),c1);
    result = mAdd(mulFp(result,a),c0);
    return result;
}
function pairSquareEval(int x,int y,int a) returns (int,int) {
    return mAdd(mSqr(x),mulFp(a,mSqr(y))),mulFp(mAdd(x,x),y);
}
function pairMulEval(int x,int y,int t,int a) returns (int,int) {
    return mAdd(x,mulFp(a,mulFp(y,t))),mAdd(y,mulFp(x,t));
}
function lineEval(
    int x,int y,int d0a,int d0b,int ma,int mb,int u,int v,
    int a,int a2,int a4,int a5
) returns (int,int) {
    int qa = mulFp(mSub(0,mAdd(d0a,d0b)),v);
    int qb = mulFp(mSub(d0a,d0b),v);
    int ra = mulFp(mAdd(ma,mb),u);
    int rb = mulFp(mSub(mb,ma),u);
    int t = mAdd(
        mAdd(mulFp(mSub(qa,qb),a),mulFp(mSub(ra,rb),a2)),
        mAdd(mulFp(qb,a4),mulFp(rb,a5))
    );
    return mAdd(x,mulFp(a,mulFp(y,t))),mAdd(y,mulFp(x,t));
}
function pointDoubleAffine(
    int xa,int xb,int ya,int yb,int ma,int mb
) returns (int,int,int,int,int,int) {
    require(ya != 0 || yb != 0);
    (int dena,int denb) = r2Sc(ya,yb,2);
    (int lhsa,int lhsb) = r2Mul(ma,mb,dena,denb);
    (int x2a,int x2b) = r2Sqr(xa,xb);
    (int rhsa,int rhsb) = r2Sc(x2a,x2b,3);
    require(lhsa == rhsa); require(lhsb == rhsb);
    (int mxa,int mxb) = r2Mul(ma,mb,xa,xb);
    (int d0a,int d0b) = r2Sub(mxa,mxb,ya,yb);
    (int m2a,int m2b) = r2Sqr(ma,mb);
    (int twoXa,int twoXb) = r2Sc(xa,xb,2);
    (int nXa,int nXb) = r2Sub(m2a,m2b,twoXa,twoXb);
    (int mnXa,int mnXb) = r2Mul(ma,mb,nXa,nXb);
    (int nYa,int nYb) = r2Sub(d0a,d0b,mnXa,mnXb);
    return d0a,d0b,nXa,nXb,nYa,nYb;
}
function pointAddAffine(
    int xa,int xb,int ya,int yb,int qxa,int qxb,int qya,int qyb,int ma,int mb
) returns (int,int,int,int,int,int) {
    (int dena,int denb) = r2Sub(qxa,qxb,xa,xb);
    require(dena != 0 || denb != 0);
    (int lhsa,int lhsb) = r2Mul(ma,mb,dena,denb);
    (int rhsa,int rhsb) = r2Sub(qya,qyb,ya,yb);
    require(lhsa == rhsa); require(lhsb == rhsb);
    (int mxa,int mxb) = r2Mul(ma,mb,xa,xb);
    (int d0a,int d0b) = r2Sub(mxa,mxb,ya,yb);
    (int m2a,int m2b) = r2Sqr(ma,mb);
    (int tXa,int tXb) = r2Sub(m2a,m2b,xa,xb);
    (int nXa,int nXb) = r2Sub(tXa,tXb,qxa,qxb);
    (int mnXa,int mnXb) = r2Mul(ma,mb,nXa,nXb);
    (int nYa,int nYb) = r2Sub(d0a,d0b,mnXa,mnXb);
    return d0a,d0b,nXa,nXb,nYa,nYb;
}
function absorbRelation(int power,int total,int residual,int beta) returns (int,int) {
    return mulFp(power,beta),mAdd(total,mulFp(power,residual));
}
function torusFrobFlat(
    int u0,int u1,int u2,int u3,int u4,int u5
) returns (int,int,int,int,int,int) {
    int x0a=mAdd(u0,u3); int x0b=u3;
    int x1a=mAdd(u1,u4); int x1b=u4;
    int x2a=mAdd(u2,u5); int x2b=u5;
    int c0a=x0a; int c0b=mSub(0,x0b);
    int c1a=x1a; int c1b=mSub(0,x1b);
    int c2a=x2a; int c2b=mSub(0,x2b);
    (int d1a,int d1b)=r2Mul(c1a,c1b,
        0,
        4002409555221667392624310435006688643935503118305586438271171395842971157480381377015405980053539358417135540939436);
    (int d2a,int d2b)=r2Mul(c2a,c2b,
        4002409555221667392624310435006688643935503118305586438271171395842971157480381377015405980053539358417135540939437,
        0);
    (int f0a,int f0b)=r2Mul(c0a,c0b,
        3850754370037169011952147076051364057158807420970682438676050522613628423219637725072182697113062777891589506424760,
        151655185184498381465642749684540099398075398968325446656007613510403227271200139370504932015952886146304766135027);
    (int f1a,int f1b)=r2Mul(d1a,d1b,
        3850754370037169011952147076051364057158807420970682438676050522613628423219637725072182697113062777891589506424760,
        151655185184498381465642749684540099398075398968325446656007613510403227271200139370504932015952886146304766135027);
    (int f2a,int f2b)=r2Mul(d2a,d2b,
        3850754370037169011952147076051364057158807420970682438676050522613628423219637725072182697113062777891589506424760,
        151655185184498381465642749684540099398075398968325446656007613510403227271200139370504932015952886146304766135027);
    return mSub(f0a,f0b),mSub(f1a,f1b),mSub(f2a,f2b),f0b,f1b,f2b;
}
`;

const BASELINE_TOTAL_INPUTS = 1 + blockPayloads.length + quotientPayloads.length;
const FUSED_QUOTIENT_BLOCK_INDEX = 4;
const FUSED_QUOTIENT_INPUT_INDEX = FUSED_QUOTIENT_BLOCK_INDEX + 1;
const FUSED_QUOTIENT_TAIL_BLOCK_INDEX = 15;
const FUSED_QUOTIENT_TAIL_INPUT_INDEX = FUSED_QUOTIENT_TAIL_BLOCK_INDEX + 1;
const TEMPLATE_TOTAL_INPUTS = 1 + blockPayloads.length;
const rangeLine = (name) => `        require(within(${name},0,${P}));`;
const declareLimb = (lines, name, blob, offset, requireRange = true) => {
  lines.push(`        int ${name} = ${limbExpression(blob, offset)};`);
  if (requireRange) lines.push(rangeLine(name));
};
const constantRelationPowerLines = (blockIndex) => {
  const exponent = relationStartExponent(blockIndex);
  if (exponent === 0) return ['        int relationPower=1;'];

  const lines = ['        int betaPower=beta;'];
  const highestBit = Math.floor(Math.log2(exponent));
  let declared = false;
  for (let bit = 0; bit <= highestBit; bit += 1) {
    if (bit > 0) lines.push('        betaPower=mulFp(betaPower,betaPower);');
    if ((exponent & (1 << bit)) !== 0) {
      lines.push(declared
        ? '        relationPower=mulFp(relationPower,betaPower);'
        : '        int relationPower=betaPower;');
      declared = true;
    }
  }
  assert(declared, `block ${blockIndex} relation power was not initialized`);
  return lines;
};
const templateRelationPowerLines = (members) => {
  if (members.length === 1) {
    if (members[0] === 0) return constantRelationPowerLines(0);
    return [
      `        require(blockIndex==${members[0]});`,
      ...constantRelationPowerLines(members[0]),
    ];
  }
  if (members.length === 2 && members[0] === 1 && members[1] === 4) {
    return [
      '        require(blockIndex==1 || blockIndex==4);',
      '        int betaPower=mulFp(beta,beta);',
      '        int relationPower=betaPower;',
      '        if (blockIndex==4) {',
      '            betaPower=mulFp(betaPower,betaPower);',
      '            relationPower=mulFp(betaPower,beta);',
      '        }',
    ];
  }
  return [
    `        require(within(blockIndex,${members[0]},${members.at(-1) + 1}));`,
    '        require(blockIndex!=4); require(blockIndex!=15);',
    '        int relationExponent=blockIndex;',
    '        int betaPower=beta;',
    '        int relationPower=betaPower;',
    '        for (int relationBit=0;relationBit<4;relationBit=relationBit+1) {',
    '            if (((relationExponent >> relationBit) % 2)==1) {',
    '                relationPower=mulFp(relationPower,betaPower);',
    '            }',
    '            betaPower=mulFp(betaPower,betaPower);',
    '        }',
    '        if (relationExponent>=16) {',
    '            relationPower=mulFp(relationPower,betaPower);',
    '            relationPower=mulFp(relationPower,beta);',
    '        }',
  ];
};

const blockSource = (
  record,
  usePicFixedBlob = false,
  totalInputs = BASELINE_TOTAL_INPUTS,
) => {
  const needsB = record.blockIndex === 0 || record.runtimeOps.some((op) => op.t === 'al') ||
    record.terminalRelation !== undefined;
  const needsRootEval = record.operations.some((op) => op.t === 'cf');
  const needsRoot = record.blockIndex === 0 || needsRootEval || record.terminalRelation !== undefined;
  const lines = [COMMON_SOURCE,
    `contract D3TwoChartBlock${record.blockIndex}() {`,
    '    function spend(bytes evaluationBlob,bytes payload) {',
    `        require(this.activeInputIndex == ${record.blockIndex + 1});`,
    `        require(tx.inputs.length == ${totalInputs});`,
    `        require(payload.length == ${record.payload.length});`,
    '        require(evaluationBlob.length == 48);',
    `        bytes transcriptHeader = ${coordinatorHeaderExpression};`,
    '        int beta = int(transcriptHeader.split(96)[0].split(64)[1] + 0x00);',
    '        int alpha = int(transcriptHeader.split(96)[1] + 0x00);',
    `        bytes statementBlob = ${statementExpression};`,
  ];

  if (needsB) {
    [['Bxa', 'effectiveBxa'], ['Bxb', 'effectiveBxb'],
      ['Bya', 'effectiveBya'], ['Byb', 'effectiveByb']].forEach(([name, field]) => {
      lines.push(`        int ${name} = ${statementLimbExpression(statementIndex[field])};`);
    });
  }
  if (needsRoot) {
    Array.from({ length: 6 }, (_, index) => `root${index}`).forEach((name, index) => {
      lines.push(`        int ${name} = ${statementLimbExpression(statementIndex[`root${index}`])};`);
    });
  }
  (SKIP_GAMMA ? ['p0u', 'p0v', 'p3u', 'p3v'] :
    ['p0u', 'p0v', 'p2u', 'p2v', 'p3u', 'p3v'])
    .forEach((name) => {
      lines.push(`        int ${name} = ${statementLimbExpression(statementIndex[name])};`);
    });
  lines.push(
    `        int bIdentity=${statementLimbExpression(statementIndex.Bidentity)};`,
    '        int pairP0u=p0u; int pairP0v=p0v;',
    '        if (bIdentity==1) { pairP0u=0; pairP0v=0; }',
  );

  Array.from({ length: 6 }, (_, index) => `outU${index}`).forEach((name, index) => {
    declareLimb(lines, name, 'payload', record.layout.outputU + index * W);
  });
  lines.push(`        int outFlag = ${byteExpression('payload', record.layout.outputFlag)};`);
  lines.push('        require(outFlag == 0 || outFlag == 1);');
  lines.push('        if (outFlag == 1) {');
  Array.from({ length: 6 }, (_, index) => lines.push(`            require(outU${index} == 0);`));
  lines.push('        }');
  if (INVERSE_RELATIONS) {
    Array.from({ length: 6 }, (_, index) => `outZ${index}`).forEach((name, index) => {
      declareLimb(lines, name, 'payload', record.layout.outputInverse + index * W);
    });
  }
  ['outRxa', 'outRxb', 'outRya', 'outRyb'].forEach((name, index) => {
    declareLimb(lines, name, 'payload', record.layout.outputR + index * W);
  });

  record.runtimeOps.forEach((_, index) => {
    declareLimb(lines, `s${index}a`, 'payload', record.layout.runtimeSlopes + index * 2 * W);
    declareLimb(lines, `s${index}b`, 'payload', record.layout.runtimeSlopes + (index * 2 + 1) * W);
  });
  record.fixedOps.forEach((_, index) => {
    ['d0a', 'd0b', 'ma', 'mb'].forEach((suffix, limbIndex) => {
      declareLimb(lines, `f${index}${suffix}`, 'payload',
        record.layout.fixedCoefficients + (index * 4 + limbIndex) * W, false);
    });
  });
  const fixedEnd = record.layout.fixedCoefficients + record.fixedCoefficients.length * W;
  lines.push(
    `        bytes fixedBlob = payload.split(${fixedEnd})[0]` +
      `.split(${record.layout.fixedCoefficients})[1];`,
    `        require(sha256(fixedBlob) == 0x${hex(record.fixedCommitment)});`,
  );
  let liftRecordOffset = record.layout.liftRecords;
  record.liftRecords.forEach((liftRecord, factorIndex) => {
    Array.from({ length: 6 }, (_, limbIndex) => {
      declareLimb(
        lines,
        `lift${factorIndex}_${limbIndex}`,
        'payload',
        liftRecordOffset + limbIndex * W,
        !PIC32_RECORDS,
      );
    });
    liftRecordOffset += liftRecord.payload.length;
  });
  if (record.splitRelation !== undefined) {
    Array.from({ length: 6 }, (_, index) => `splitU${index}`).forEach((name, index) => {
      declareLimb(lines, name, 'payload', record.layout.splitU + index * W);
    });
    lines.push(`        int splitFlag = ${byteExpression('payload', record.layout.splitFlag)};`);
    lines.push('        require(splitFlag == 0 || splitFlag == 1);');
    lines.push('        if (splitFlag == 1) {');
    Array.from({ length: 6 }, (_, index) => lines.push(`            require(splitU${index} == 0);`));
    lines.push('        }');
  }
  if (record.terminalRelation !== undefined && INVERSE_RELATIONS) {
    Array.from({ length: 6 }, (_, index) => `terminalZ${index}`).forEach((name, index) => {
      declareLimb(lines, name, 'payload', record.layout.terminalInverse + index * W);
    });
  }

  if (record.blockIndex === 0) {
    lines.push(
      '        int inFlag = 0;',
      '        int inU0=mSub(0,root0); int inU1=mSub(0,root1); int inU2=mSub(0,root2);',
      '        int inU3=mSub(0,root3); int inU4=mSub(0,root4); int inU5=mSub(0,root5);',
      '        int rXa=Bxa; int rXb=Bxb; int rYa=Bya; int rYb=Byb;',
      '        int relationTotal=0;',
    );
  } else {
    const previous = blockRecords[record.blockIndex - 1];
    lines.push(
      `        bytes previousPayload = ${firstPushExpression(record.blockIndex, previous.payload.length)};`,
    );
    Array.from({ length: 6 }, (_, index) => `inU${index}`).forEach((name, index) => {
      declareLimb(lines, name, 'previousPayload', previous.layout.outputU + index * W, false);
    });
    lines.push(`        int inFlag = ${byteExpression('previousPayload', previous.layout.outputFlag)};`);
    ['rXa', 'rXb', 'rYa', 'rYb'].forEach((name, index) => {
      declareLimb(lines, name, 'previousPayload', previous.layout.outputR + index * W, false);
    });
    lines.push(
      `        bytes previousEvaluation = ${secondPushExpression(
        record.blockIndex,
        previous.payload.length,
        blockEvaluationPayloads[record.blockIndex - 1].length,
      )};`,
      `        int relationTotal=${limbExpression('previousEvaluation', 0)};`,
    );
  }

  lines.push(
    ...constantRelationPowerLines(record.blockIndex),
    `        int expectedTotal=${limbExpression('evaluationBlob', 0)};`,
    rangeLine('expectedTotal'),
    '        int alpha2=mulFp(alpha,alpha);',
    '        int alpha4=mulFp(alpha2,alpha2);',
    '        int alpha5=mulFp(alpha4,alpha);',
    '        int inEval=eval6(inU0,inU1,inU2,inU3,inU4,inU5,alpha);',
    '        int state0=1; int state1=inEval;',
    '        if (inFlag == 1) { state0=inEval; state1=1; }',
  );
  if (needsRootEval) {
    lines.push('        int rootEval=eval6(root0,root1,root2,root3,root4,root5,alpha);');
  }

  let runtimeIndex = 0;
  let fixedIndex = 0;
  let operationIndex = 0;
  record.operations.forEach((op) => {
    if (op.t === 'sqr') {
      lines.push('        (state0,state1)=pairSquareEval(state0,state1,alpha);');
    } else if (op.t === 'cf') {
      lines.push(`        (state0,state1)=pairMulEval(state0,state1,${op.neg ? 'rootEval' : 'mSub(0,rootEval)'},alpha);`);
    } else if (op.j === 0) {
      const suffix = operationIndex;
      if (op.t === 'dl') {
        lines.push(
          `        (int d${suffix}a,int d${suffix}b,int nx${suffix}a,int nx${suffix}b,` +
            `int ny${suffix}a,int ny${suffix}b)=pointDoubleAffine(` +
            `rXa,rXb,rYa,rYb,s${runtimeIndex}a,s${runtimeIndex}b);`,
        );
      } else {
        const qya = op.neg ? 'mSub(0,Bya)' : 'Bya';
        const qyb = op.neg ? 'mSub(0,Byb)' : 'Byb';
        lines.push(
          `        (int d${suffix}a,int d${suffix}b,int nx${suffix}a,int nx${suffix}b,` +
            `int ny${suffix}a,int ny${suffix}b)=pointAddAffine(` +
            `rXa,rXb,rYa,rYb,Bxa,Bxb,${qya},${qyb},s${runtimeIndex}a,s${runtimeIndex}b);`,
        );
      }
      lines.push(
        `        (state0,state1)=lineEval(state0,state1,d${suffix}a,d${suffix}b,` +
          `s${runtimeIndex}a,s${runtimeIndex}b,pairP0u,pairP0v,alpha,alpha2,alpha4,alpha5);`,
        `        rXa=nx${suffix}a; rXb=nx${suffix}b; rYa=ny${suffix}a; rYb=ny${suffix}b;`,
      );
      runtimeIndex += 1;
    } else if (op.j === 2 || op.j === 3) {
      lines.push(
        `        (state0,state1)=lineEval(state0,state1,f${fixedIndex}d0a,f${fixedIndex}d0b,` +
          `f${fixedIndex}ma,f${fixedIndex}mb,p${op.j}u,p${op.j}v,` +
          'alpha,alpha2,alpha4,alpha5);',
      );
      fixedIndex += 1;
    } else {
      throw new Error(`unsupported operation ${op.t}/${op.j} in block ${record.blockIndex}`);
    }
    if (record.splitRelation?.operationCount === operationIndex + 1) {
      lines.push(
        '        int splitEval=eval6(splitU0,splitU1,splitU2,splitU3,splitU4,splitU5,alpha);',
        '        int splitSelected=state0; int splitOther=state1;',
        '        if (splitFlag == 1) { splitSelected=state1; splitOther=state0; }',
        '        int splitResidual=mSub(splitOther,mulFp(splitSelected,splitEval));',
        '        (relationPower,relationTotal)=absorbRelation(relationPower,relationTotal,splitResidual,beta);',
        '        state0=1; state1=splitEval;',
        '        if (splitFlag == 1) { state0=0; state1=1; }',
      );
    }
    operationIndex += 1;
  });
  assert(runtimeIndex === record.runtimeOps.length, `block ${record.blockIndex} runtime source count changed`);
  assert(fixedIndex === record.fixedOps.length, `block ${record.blockIndex} fixed source count changed`);
  record.liftRecords.forEach((_, factorIndex) => {
    if (PIC32_RECORDS) {
      if (PIC_FLAT_RECORDS) {
        lines.push(
          `        int liftEval${factorIndex}=eval6(` +
            Array.from({ length: 6 }, (__, limbIndex) =>
              `lift${factorIndex}_${limbIndex}`).join(',') + ',alpha);',
          `        (state0,state1)=pairMulEval(state0,state1,liftEval${factorIndex},alpha);`,
        );
      } else {
        lines.push(
          `        int liftEval${factorIndex}=eval6(` +
            `mSub(lift${factorIndex}_0,lift${factorIndex}_1),` +
            `mSub(lift${factorIndex}_2,lift${factorIndex}_3),` +
            `mSub(lift${factorIndex}_4,lift${factorIndex}_5),` +
            `lift${factorIndex}_1,lift${factorIndex}_3,lift${factorIndex}_5,alpha);`,
          `        liftEval${factorIndex}=mSub(0,liftEval${factorIndex});`,
          `        (state0,state1)=pairMulEval(state0,state1,liftEval${factorIndex},alpha);`,
        );
      }
    } else {
      lines.push(
        `        int liftEval${factorIndex}=eval6(` +
          Array.from({ length: 6 }, (__, limbIndex) =>
            `lift${factorIndex}_${limbIndex}`).join(',') + ',alpha);',
        `        (state0,state1)=pairMulEval(state0,state1,liftEval${factorIndex},alpha);`,
      );
    }
  });

  lines.push(
    '        require(rXa==outRxa); require(rXb==outRxb);',
    '        require(rYa==outRya); require(rYb==outRyb);',
    '        int outEval=eval6(outU0,outU1,outU2,outU3,outU4,outU5,alpha);',
    '        int selected=state0; int other=state1;',
    '        if (outFlag == 1) { selected=state1; other=state0; }',
    '        int crossResidual=mSub(other,mulFp(selected,outEval));',
    '        (relationPower,relationTotal)=absorbRelation(relationPower,relationTotal,crossResidual,beta);',
  );
  if (record.terminalRelation !== undefined) {
    if (usePicFixedBlob) {
      lines.push(
        '        require(picFixedBlob.length==336);',
        `        int psiXb=${limbExpression('picFixedBlob', 192)};`,
        `        int psiYa=${limbExpression('picFixedBlob', 192 + W)};`,
        `        int psiYb=${limbExpression('picFixedBlob', 192 + 2 * W)};`,
      );
    }
    lines.push(
      '        int conjugateBxb=mSub(0,Bxb); int conjugateByb=mSub(0,Byb);',
      '        (int psiBxa,int psiBxb)=r2Mul(0,' +
        (usePicFixedBlob ? 'psiXb,' :
          '4002409555221667392624310435006688643935503118305586438271171395842971157480381377015405980053539358417135540939437,') +
        'Bxa,conjugateBxb);',
      '        (int psiBya,int psiByb)=r2Mul(' +
        (usePicFixedBlob ? 'psiYa,psiYb,' :
          '2973677408986561043442465346520108879172042883009249989176415018091420807192182638567116318576472649347015917690530,' +
          '1028732146235106349975324479215795277384839936929757896155643118032610843298655225875571310552543014690878354869257,') +
        'Bya,conjugateByb);',
      '        require(outRxa==psiBxa); require(outRxb==psiBxb);',
      '        require(outRya==mSub(0,psiBya)); require(outRyb==mSub(0,psiByb));',
    );
  }
  if (INVERSE_RELATIONS) {
    lines.push(
      '        int inverseEval=eval6(outZ0,outZ1,outZ2,outZ3,outZ4,outZ5,alpha);',
      '        int inverseResidual=mSub(mulFp(selected,inverseEval),1);',
      '        (relationPower,relationTotal)=absorbRelation(relationPower,relationTotal,inverseResidual,beta);',
    );
  }
  if (record.terminalRelation !== undefined) {
    lines.push(
      '        state0=1; state1=outEval;',
      '        if (outFlag == 1) { state0=0; state1=1; }',
      `        int fixedEval=eval6(${fixedTorusFlat.join(',')},alpha);`,
      '        (state0,state1)=pairMulEval(state0,state1,fixedEval,alpha);',
      '        (int frob0,int frob1,int frob2,int frob3,int frob4,int frob5)=' +
        'torusFrobFlat(root0,root1,root2,root3,root4,root5);',
      '        int frobEval=eval6(frob0,frob1,frob2,frob3,frob4,frob5,alpha);',
      '        int terminalCross=mSub(state1,mulFp(state0,frobEval));',
      '        (relationPower,relationTotal)=absorbRelation(relationPower,relationTotal,terminalCross,beta);',
    );
    if (INVERSE_RELATIONS) {
      lines.push(
        '        int terminalInverseEval=eval6(terminalZ0,terminalZ1,terminalZ2,terminalZ3,terminalZ4,terminalZ5,alpha);',
        '        int terminalInverse=mSub(mulFp(state0,terminalInverseEval),1);',
        '        (relationPower,relationTotal)=absorbRelation(relationPower,relationTotal,terminalInverse,beta);',
      );
    }
  }
  lines.push(
    '        require(relationTotal==expectedTotal);',
    '    }',
    '}',
  );
  return `${lines.join('\n')}\n`;
};

const replaceExactlyOnce = (source, before, after, label) => {
  const first = source.indexOf(before);
  assert(first !== -1, `${label} replacement target is missing`);
  assert(source.indexOf(before, first + before.length) === -1,
    `${label} replacement target is repeated`);
  return `${source.slice(0, first)}${after}${source.slice(first + before.length)}`;
};
const templateBlockSource = (record, template) => {
  const { name } = template;
  let source = blockSource(record, name === 'Terminal', TEMPLATE_TOTAL_INPUTS);
  source = replaceExactlyOnce(
    source,
    `contract D3TwoChartBlock${record.blockIndex}() {`,
    `contract D3TwoChartTemplate${name}() {`,
    `${name} contract`,
  );
  source = replaceExactlyOnce(
    source,
    '    function spend(bytes evaluationBlob,bytes payload) {',
    `    function spend(${name === 'Terminal' ? 'bytes picFixedBlob,' : ''}` +
      'bytes fixedCommitment,int previousPayloadLength,int blockIndex,' +
      'bytes evaluationBlob,bytes payload) {',
    `${name} signature`,
  );
  source = replaceExactlyOnce(
    source,
    `        require(this.activeInputIndex == ${record.blockIndex + 1});`,
    `        require(within(blockIndex,0,${blockRecords.length}));\n` +
      '        require(this.activeInputIndex == blockIndex + 1);',
    `${name} input index`,
  );
  source = replaceExactlyOnce(
    source,
    `        require(sha256(fixedBlob) == 0x${hex(record.fixedCommitment)});`,
    '        require(fixedCommitment.length == 32);\n' +
      '        require(sha256(fixedBlob) == fixedCommitment);',
    `${name} fixed commitment`,
  );
  if (record.blockIndex === 0) {
    source = replaceExactlyOnce(
      source,
      '        int inFlag = 0;',
      '        require(blockIndex == 0);\n' +
        '        require(previousPayloadLength == 0);\n' +
        '        int inFlag = 0;',
      `${name} first block`,
    );
  } else {
    const previous = blockRecords[record.blockIndex - 1];
    source = replaceExactlyOnce(
      source,
      firstPushExpression(record.blockIndex, previous.payload.length),
      'tx.inputs[blockIndex].unlockingBytecode.split(previousPayloadLength+3)[0]' +
        '.split(3)[1]',
      `${name} previous payload expression`,
    );
    source = replaceExactlyOnce(
      source,
      secondPushExpression(
        record.blockIndex,
        previous.payload.length,
        blockEvaluationPayloads[record.blockIndex - 1].length,
      ),
      'tx.inputs[blockIndex].unlockingBytecode.split(previousPayloadLength+3)[1]' +
        '.split(49)[0].split(1)[1]',
      `${name} previous evaluation expression`,
    );
  }
  source = replaceExactlyOnce(
    source,
    constantRelationPowerLines(record.blockIndex).join('\n'),
    templateRelationPowerLines(template.members).join('\n'),
    `${name} relation power`,
  );
  return source;
};
const templateClasses = [
  { name: 'First', representative: 0, members: [0] },
  { name: 'AdditionTail', representative: 1, members: [1, 4] },
  {
    name: 'Regular',
    representative: 2,
    members: blockRecords.map((_, index) => index).filter(
      (index) => ![0, 1, 4, 15, 20].includes(index),
    ),
  },
  { name: 'AdditionMiddle', representative: 15, members: [15] },
  { name: 'Terminal', representative: 20, members: [20] },
];
assert(templateClasses.flatMap(({ members }) => members).sort((a, b) => a - b)
  .every((index, position) => index === position),
'template classes do not partition the blocks');

const Q_COMMON_SOURCE = 'pragma cashscript ^0.14.0;';

const quotientSource = (
  index,
  inputIndex = 1 + blockPayloads.length + index,
  totalInputs = BASELINE_TOTAL_INPUTS,
  splitTailBytes = 0,
) => {
  const payload = quotientPayloads[index];
  const isOnlyQuotientCarrier = quotientPayloads.length === 1;
  const hasPhysicalTail = splitTailBytes > 0;
  assert(!hasPhysicalTail || isOnlyQuotientCarrier,
    'only the sole logical quotient carrier can have a physical tail');
  const lines = [Q_COMMON_SOURCE,
    `contract D3TwoChartQuotient${index}() {`,
    `    function spend(${hasPhysicalTail
      ? 'bytes tail,bytes payload'
      : isOnlyQuotientCarrier
        ? 'bytes payload'
        : 'bytes evaluationBlob,bytes payload'}) {`,
    `        require(this.activeInputIndex == ${inputIndex});`,
    `        require(tx.inputs.length == ${totalInputs});`,
    `        require(payload.length == ${payload.length - splitTailBytes});`,
    ...(hasPhysicalTail ? [`        require(tail.length == ${splitTailBytes});`] : []),
    `        bytes transcriptHeader=${coordinatorHeaderExpression};`,
    '        int alpha=int(transcriptHeader.split(96)[1]+0x00);',
  ];
  if (!isOnlyQuotientCarrier) {
    lines.push('        require(evaluationBlob.length == 48);');
  }
  if (index === 0) {
    lines.push('        int accumulator=0;');
  } else {
    const previousInput = inputIndex - 1;
    lines.push(
      `        bytes previousEvaluation=${secondPushExpression(
        previousInput,
        quotientPayloads[index - 1].length,
        quotientEvaluationPayloads[index - 1].length,
      )};`,
      `        int accumulator=${limbExpression('previousEvaluation', 0)};`,
    );
  }
  lines.push(
    `        bytes remaining=${hasPhysicalTail ? 'payload+tail' : 'payload'};`,
    `        for (int coefficientIndex=0;coefficientIndex<${quotientChunkCounts[index]};` +
      'coefficientIndex=coefficientIndex+1) {',
    '            bytes coefficientBytes=remaining.split(48)[0];',
    '            remaining=remaining.split(48)[1];',
    '            int coefficient=int(coefficientBytes+0x00);',
    `            require(coefficient<${P});`,
    `            accumulator=(accumulator*alpha+coefficient)%${P};`,
    '        }',
  );
  if (!isOnlyQuotientCarrier) {
    lines.push(
      `        int expectedAccumulator=${limbExpression('evaluationBlob', 0)};`,
      rangeLine('expectedAccumulator'),
      '        require(accumulator==expectedAccumulator);',
    );
  }
  if (index === quotientPayloads.length - 1) {
    const lastBlockInput = blockPayloads.length;
    lines.push(
      `        bytes finalBlockEvaluation=${secondPushExpression(
        lastBlockInput,
        blockPayloads.at(-1).length,
        blockEvaluationPayloads.at(-1).length,
      )};`,
      `        int finalRelationTotal=${limbExpression('finalBlockEvaluation', 0)};`,
      `        int alpha3=((alpha*alpha)%${P}*alpha)%${P};`,
      `        int modulusValue=((alpha3*alpha3)%${P}+${P}-(2*alpha3)%${P}+2)%${P};`,
      `        require((accumulator*modulusValue)%${P}==finalRelationTotal);`,
    );
  }
  lines.push('    }', '}');
  return `${lines.join('\n')}\n`;
};

const prefixHex = (tag, payloadLength) => binToHex(framePrefix(tag, payloadLength));
const metadataHex = (index, count, length) => binToHex(concat(u32(index), u32(count), u32(length)));
const nodeMetadataHex = (level, index) => binToHex(concat(u32(level), u32(index)));
const appendTreeSource = (lines, namespace, leafSpecs) => {
  let nodes = leafSpecs.map((leaf, index) => {
    const variable = `${namespace}Leaf${index}`;
    lines.push(
      `        bytes ${variable}=sha256(0x${prefixHex('leaf', 12 + leaf.payloadLength)}+` +
        `0x${metadataHex(index, leafSpecs.length, leaf.metadataLength)}+${leaf.expression});`,
    );
    return variable;
  });
  let level = 0;
  while (nodes.length > 1) {
    const next = [];
    for (let index = 0; index < nodes.length; index += 2) {
      const left = nodes[index];
      const right = nodes[index + 1] ?? left;
      const variable = `${namespace}Node${level}_${index / 2}`;
      lines.push(
        `        bytes ${variable}=sha256(0x${prefixHex('node', 72)}+` +
          `0x${nodeMetadataHex(level, index / 2)}+${left}+${right});`,
      );
      next.push(variable);
    }
    nodes = next;
    level += 1;
  }
  return nodes[0];
};

const coordinatorSource = (
  siblingLockingDigest,
  usePicFixedBlob = false,
  totalInputs = BASELINE_TOTAL_INPUTS,
  fusedQuotient = false,
) => {
  const lines = [
    'pragma cashscript ^0.14.0;',
    `function cAdd(int x,int y) returns (int) { return (x+y)%${P}; }`,
    `function cSub(int x,int y) returns (int) { return (x-y+${P})%${P}; }`,
    `function cMul(int x,int y) returns (int) { return (x*y)%${P}; }`,
    'function c2Mul(int a0,int a1,int b0,int b1) returns (int,int) {',
    '    return cSub(cMul(a0,b0),cMul(a1,b1)),cAdd(cMul(a0,b1),cMul(a1,b0));',
    '}',
    'function c2Sqr(int a0,int a1) returns (int,int) {',
    '    return cMul(cAdd(a0,a1),cSub(a0,a1)),cMul(cAdd(a0,a0),a1);',
    '}',
    'contract D3TwoChartCoordinator() {',
    `    function spend(${usePicFixedBlob ? 'bytes picFixedBlob,' : ''}` +
      'bytes statementBlob,bytes transcriptHeader) {',
    '        require(this.activeInputIndex==0);',
    `        require(tx.inputs.length==${totalInputs});`,
    '        require(tx.outputs.length==1);',
    '        require(tx.outputs[0].lockingBytecode==0x6a);',
    `        require(statementBlob.length==${statementBytes.length});`,
    '        require(transcriptHeader.length==128);',
    '        bytes committedRoot=transcriptHeader.split(32)[0];',
    '        bytes committedQuotientRoot=transcriptHeader.split(64)[0].split(32)[1];',
    '        bytes committedBeta=transcriptHeader.split(96)[0].split(64)[1];',
    '        bytes committedAlpha=transcriptHeader.split(96)[1];',
    '        require(int(committedBeta+0x00)!=0);',
  ];
  statementFields.forEach(([name, , upperBound]) => {
    lines.push(
      `        int ${name}=${statementLimbExpression(statementIndex[name])};`,
      `        require(within(${name},0,${upperBound}));`,
    );
  });
  if (usePicFixedBlob) {
    lines.push(
      `        require(picFixedBlob.length==${picFixedBlob.length});`,
      `        int substituteBxa=${limbExpression('picFixedBlob', 0)};`,
      `        int substituteBxb=${limbExpression('picFixedBlob', W)};`,
      `        int substituteBya=${limbExpression('picFixedBlob', 2 * W)};`,
      `        int substituteByb=${limbExpression('picFixedBlob', 3 * W)};`,
    );
  }
  lines.push(
    '        int effectiveBSum=effectiveBxa+effectiveBxb+effectiveBya+effectiveByb;',
    '        if (Bidentity==1) {',
    `            require(effectiveBxa==${usePicFixedBlob ? 'substituteBxa' : identitySubstituteB.x.c0});`,
    `            require(effectiveBxb==${usePicFixedBlob ? 'substituteBxb' : identitySubstituteB.x.c1});`,
    `            require(effectiveBya==${usePicFixedBlob ? 'substituteBya' : identitySubstituteB.y.c0});`,
    `            require(effectiveByb==${usePicFixedBlob ? 'substituteByb' : identitySubstituteB.y.c1});`,
    '        } else {',
    '            require(effectiveBSum!=0);',
    '            (int bx2a,int bx2b)=c2Sqr(effectiveBxa,effectiveBxb);',
    '            (int bx3a,int bx3b)=c2Mul(bx2a,bx2b,effectiveBxa,effectiveBxb);',
    '            int rhsBa=cAdd(bx3a,4); int rhsBb=cAdd(bx3b,4);',
    '            (int by2a,int by2b)=c2Sqr(effectiveBya,effectiveByb);',
    '            require(by2a==rhsBa); require(by2b==rhsBb);',
    '        }',
  );
  (SKIP_GAMMA ? ['p0', 'p3'] : ['p0', 'p2', 'p3']).forEach((prefix) => {
    lines.push(
      `        int ${prefix}u2=(${prefix}u*${prefix}u)%${P};`,
      `        int ${prefix}u3=(${prefix}u2*${prefix}u)%${P};`,
      `        int ${prefix}v2=(${prefix}v*${prefix}v)%${P};`,
      `        int ${prefix}v3=(${prefix}v2*${prefix}v)%${P};`,
      `        require(${prefix}v==(4*${prefix}u3+16*${prefix}v3)%${P});`,
    );
  });
  Array.from({ length: totalInputs - 1 }, (_, index) => index + 1).forEach((inputIndex) => {
    lines.push(`        require(tx.inputs[${inputIndex}].lockingBytecode.length==35);`);
  });
  lines.push(
    `        bytes siblingLockings=${Array.from(
      { length: totalInputs - 1 },
      (_, index) => `tx.inputs[${index + 1}].lockingBytecode`,
    ).join('+')};`,
    `        require(sha256(siblingLockings)==0x${hex(siblingLockingDigest)});`,
  );
  const commitmentSpecs = [{
    expression: 'statementBlob',
    payloadLength: statementBytes.length,
    metadataLength: statementBytes.length,
  }, ...blockPayloads.map((payload, index) => {
    const variable = `blockPayload${index}`;
    lines.push(`        bytes ${variable}=${firstPushExpression(index + 1, payload.length)};`);
    lines.push(`        require(${variable}.length==${payload.length});`);
    return { expression: variable, payloadLength: payload.length, metadataLength: payload.length };
  })];
  const commitmentTreeRoot = appendTreeSource(lines, 'commitment', commitmentSpecs);
  const quotientSpecs = fusedQuotient
    ? (() => {
      const headVariable = 'quotientHeadPayload';
      const tailVariable = 'quotientTailPayload';
      const logicalVariable = 'quotientPayload0';
      const headExpression = thirdPushExpression(
        FUSED_QUOTIENT_INPUT_INDEX,
        blockPayloads[FUSED_QUOTIENT_BLOCK_INDEX].length,
        blockEvaluationPayloads[FUSED_QUOTIENT_BLOCK_INDEX].length,
        fusedQuotientHeadPayload.length,
      );
      const tailExpression = thirdPushExpression(
        FUSED_QUOTIENT_TAIL_INPUT_INDEX,
        blockPayloads[FUSED_QUOTIENT_TAIL_BLOCK_INDEX].length,
        blockEvaluationPayloads[FUSED_QUOTIENT_TAIL_BLOCK_INDEX].length,
        fusedQuotientTailPayload.length,
      );
      const expectedHeadUnlockingBytes = encodeDataPush(
        blockPayloads[FUSED_QUOTIENT_BLOCK_INDEX],
      ).length + encodeDataPush(
        blockEvaluationPayloads[FUSED_QUOTIENT_BLOCK_INDEX],
      ).length + encodeDataPush(fusedQuotientHeadPayload).length + encodeDataPush(
        templateBlockRedeems[FUSED_QUOTIENT_BLOCK_INDEX],
      ).length;
      const expectedTailUnlockingBytes = encodeDataPush(
        blockPayloads[FUSED_QUOTIENT_TAIL_BLOCK_INDEX],
      ).length + encodeDataPush(
        blockEvaluationPayloads[FUSED_QUOTIENT_TAIL_BLOCK_INDEX],
      ).length + encodeDataPush(fusedQuotientTailPayload).length + encodeDataPush(
        templateBlockRedeems[FUSED_QUOTIENT_TAIL_BLOCK_INDEX],
      ).length;
      lines.push(
        `        require(tx.inputs[${FUSED_QUOTIENT_INPUT_INDEX}].unlockingBytecode.length==` +
          `${expectedHeadUnlockingBytes});`,
        `        require(tx.inputs[${FUSED_QUOTIENT_TAIL_INPUT_INDEX}].unlockingBytecode.length==` +
          `${expectedTailUnlockingBytes});`,
        `        bytes ${headVariable}=${headExpression};`,
        `        require(${headVariable}.length==${fusedQuotientHeadPayload.length});`,
        `        bytes ${tailVariable}=${tailExpression};`,
        `        require(${tailVariable}.length==${fusedQuotientTailPayload.length});`,
        `        bytes ${logicalVariable}=${headVariable}+${tailVariable};`,
        `        require(${logicalVariable}.length==${quotientBytes.length});`,
      );
      return [{
        expression: logicalVariable,
        payloadLength: quotientBytes.length,
        metadataLength: quotientBytes.length,
      }];
    })()
    : quotientPayloads.map((payload, index) => {
      const inputIndex = 1 + blockPayloads.length + index;
      const variable = `quotientPayload${index}`;
      lines.push(`        bytes ${variable}=${firstPushExpression(inputIndex, payload.length)};`);
      lines.push(`        require(${variable}.length==${payload.length});`);
      return {
        expression: variable,
        payloadLength: payload.length,
        metadataLength: quotientBytes.length,
      };
    });
  const quotientTreeRoot = appendTreeSource(lines, 'quotient', quotientSpecs);
  lines.push(
    `        require(committedRoot==${commitmentTreeRoot});`,
    `        require(committedQuotientRoot==${quotientTreeRoot});`,
    `        require(committedBeta==sha256(0x${prefixHex('beta', 36)}+` +
      `0x${binToHex(u32(blockPayloads.length))}+committedRoot));`,
    `        require(committedAlpha==sha256(0x${prefixHex('alpha', 64)}+` +
      'committedRoot+committedQuotientRoot));',
    '    }',
    '}',
  );
  return `${lines.join('\n')}\n`;
};

const compileNamed = (source, label, compilerOptions = {}) => {
  try {
    return compileBytecode(source, compilerOptions);
  } catch (error) {
    const line = error?.location?.start?.line ?? 1;
    const numbered = source.split('\n').slice(Math.max(0, line - 4), line + 3)
      .map((item, index) => `${Math.max(1, line - 3) + index}: ${item}`).join('\n');
    throw new Error(`${label} compile failed:\n${numbered}`, { cause: error });
  }
};
const blockSources = blockRecords.map((record) => blockSource(record));
const blockRedeems = blockSources.map((source, index) => compileNamed(source, `block ${index}`));
templateClasses.forEach((template) => {
  const representative = blockRecords[template.representative];
  template.source = templateBlockSource(representative, template);
  template.core = compileNamed(template.source, `${template.name} template`);
  template.digest = sha256(template.core);
  assert(template.core.length <= 10_000,
    `${template.name} template exceeds the 10,000-byte script element limit`);
});

const PIC_RECORD_BYTES = 800;
const PIC_FACTOR_BYTES = 288;
const PIC_PATH_BYTES = 512;
const PIC_RECORD_REGION_BYTES = 2 * PIC_RECORD_BYTES;
const PIC_REGULAR_PAYLOAD_BYTES = blockRecords[2].payload.length;
const PIC_RECORD_REGION_OFFSET = PIC_REGULAR_PAYLOAD_BYTES - PIC_RECORD_REGION_BYTES;
const PIC_LEAF_TAG = Uint8Array.of(...Buffer.from('BLSGTF1', 'ascii'), 0x4c);
const PIC_NODE_TAG = Uint8Array.of(...Buffer.from('BLSGTF1', 'ascii'), 0x4e);
assert(PIC_FLAT_RECORDS && picCache.version === 4, 'batch authentication requires the v4 flat cache');
assert(picCache.globalRoot === 'b64e1bdd14a1d88d7448b23f654b37e369bda13e1612d97f4c78b0b447ba1911',
  'v4 PIC global root changed');
assert(picCache.windowRoots.length === 32, 'v4 PIC window-root count changed');
assert(regularPicCarrierBlocks.every((blockIndex) =>
  blockRecords[blockIndex].payload.length === PIC_REGULAR_PAYLOAD_BYTES &&
  blockRecords[blockIndex].layout.liftRecords === PIC_RECORD_REGION_OFFSET &&
  blockRecords[blockIndex].liftRecords.length === 2 &&
  blockRecords[blockIndex].liftRecords.every((record) => record.payload.length === PIC_RECORD_BYTES)),
'v4 PIC record region changed');
regularPicCarrierBlocks.forEach((blockIndex) => {
  const block = blockRecords[blockIndex];
  block.liftRecords.forEach((record, recordIndex) => {
    const factorOffset = block.layout.liftRecords + recordIndex * PIC_RECORD_BYTES;
    assert(equalBytes(
      block.payload.slice(factorOffset, factorOffset + PIC_FACTOR_BYTES),
      serializeLimbs(record.authenticatedLimbs),
    ), `block ${blockIndex} authenticated factor ${recordIndex} differs from its Miller payload`);
  });
});
const picWindowRootBlob = concat(...picCache.windowRoots.map(
  (root) => Uint8Array.from(Buffer.from(root, 'hex')),
));
assert(picWindowRootBlob.length === 1024, 'v4 PIC window-root blob length changed');
assert(hex(sha256(picWindowRootBlob)) ===
  '9fa1294e6f2d904ac0a1f181ea43fdfac13b8cbb007b1814482d6d807a55a9ef',
'v4 PIC window-root blob changed');
const picAuthBatches = [
  { host: 'coordinator', firstWindow: 0, windowCount: 11 },
  { host: 'block-2', firstWindow: 11, windowCount: 8 },
  { host: 'block-1', firstWindow: 19, windowCount: 4 },
  { host: 'block-20', firstWindow: 23, windowCount: 5 },
  { host: 'block-15', firstWindow: 28, windowCount: 4 },
];
assert(picAuthBatches.reduce((count, batch) => count + batch.windowCount, 0) === 32 &&
  picAuthBatches.every((batch, index) => batch.firstWindow ===
    picAuthBatches.slice(0, index).reduce((count, prior) => count + prior.windowCount, 0)),
'v4 PIC authentication batch partition changed');
const PIC_BATCH_TAG = Uint8Array.of(...Buffer.from('BLSGTF1', 'ascii'), 0x42);
const picBatchCommitments = picAuthBatches.map(({ firstWindow, windowCount }) => sha256(concat(
  PIC_BATCH_TAG,
  Uint8Array.of(firstWindow, windowCount),
  ...picCache.windowRoots.slice(firstWindow, firstWindow + windowCount).map(
    (root) => Uint8Array.from(Buffer.from(root, 'hex')),
  ),
)));
const picBatchCommitmentBlob = concat(...picBatchCommitments);
assert(picBatchCommitmentBlob.length === 160,
  'v4 PIC batch-commitment blob length changed');
const picBSubstituteBlob = serializeLimbs([
  identitySubstituteB.x.c0,
  identitySubstituteB.x.c1,
  identitySubstituteB.y.c0,
  identitySubstituteB.y.c1,
]);
const picPsiBlob = serializeLimbs([
  4002409555221667392624310435006688643935503118305586438271171395842971157480381377015405980053539358417135540939437n,
  2973677408986561043442465346520108879172042883009249989176415018091420807192182638567116318576472649347015917690530n,
  1028732146235106349975324479215795277384839936929757896155643118032610843298655225875571310552543014690878354869257n,
]);
const picFixedBlob = concat(picBSubstituteBlob, picPsiBlob);
assert(picBSubstituteBlob.length === 192 && picPsiBlob.length === 144 && picFixedBlob.length === 336,
  'block-4 fixed PIC/B/psi blob layout changed');

const public0Offset = statementLayout[statementIndex.public0].offset;
const public1Offset = statementLayout[statementIndex.public1].offset;
const picBatchDomainChecks = picAuthBatches.map(({ firstWindow, windowCount }) =>
  `(firstWindow==${firstWindow} && windowCount==${windowCount})`).join(' || ');
const picBatchCommitmentSelection = picAuthBatches.slice(1).map(
  ({ firstWindow }, index) =>
    `        if (firstWindow==${firstWindow}) { expectedBatch=0x${hex(picBatchCommitments[index + 1])}; }`,
).join('\n');
const picAuthHelperSource = `pragma cashscript ^0.14.0;
contract PicBatchAuth() {
    function spend(int firstWindow,int windowCount) {
        require(${picBatchDomainChecks});
        int finalWindow=firstWindow+windowCount;
        require(finalWindow<=32);
        bytes statementBlob=${statementExpression};
        bytes scalar0=statementBlob.split(${public0Offset + 32})[0].split(${public0Offset})[1];
        bytes scalar1=statementBlob.split(${public1Offset + 32})[0].split(${public1Offset})[1];
        bytes windowRootBlob=0x;
        for (int window=firstWindow;window<finalWindow;window=window+1) {
            int carrier=window>>1;
            int blockIndex=carrier+2;
            if (carrier>=2) { blockIndex=blockIndex+1; }
            if (carrier>=12) { blockIndex=blockIndex+1; }
            bytes payload=tx.inputs[blockIndex+1].unlockingBytecode
                .split(${PIC_REGULAR_PAYLOAD_BYTES + pushHeaderLength(PIC_REGULAR_PAYLOAD_BYTES)})[0]
                .split(${pushHeaderLength(PIC_REGULAR_PAYLOAD_BYTES)})[1];
            bytes recordRegion=payload.split(${PIC_RECORD_REGION_OFFSET})[1];
            bytes record=recordRegion.split(${PIC_RECORD_BYTES})[0];
            if (window%2==1) { record=recordRegion.split(${PIC_RECORD_BYTES})[1]; }
            bytes factor=record.split(${PIC_FACTOR_BYTES})[0];
            bytes path=record.split(${PIC_FACTOR_BYTES})[1];
            bytes digitBytes=scalar0.split(window+1)[0].split(window)[1]
                +scalar1.split(window+1)[0].split(window)[1];
            bytes root=sha256(0x${hex(PIC_LEAF_TAG)}+toPaddedBytes(blockIndex,1)
                +toPaddedBytes(window,1)+digitBytes+factor);
            int globalIndex=int(digitBytes+toPaddedBytes(window,1)+0x00);
            for (int level=0;level<16;level=level+1) {
                bytes sibling=path.split(32)[0];
                path=path.split(32)[1];
                int parent=globalIndex>>1;
                bytes prefix=0x${hex(PIC_NODE_TAG)}+toPaddedBytes(level+1,1)
                    +toPaddedBytes(parent,4);
                if (globalIndex%2==0) { root=sha256(prefix+root+sibling); }
                else { root=sha256(prefix+sibling+root); }
                globalIndex=parent;
            }
            require(path.length==0); require(globalIndex==window);
            windowRootBlob=windowRootBlob+root;
        }
        bytes expectedBatch=0x${hex(picBatchCommitments[0])};
${picBatchCommitmentSelection}
        bytes batchCommitment=sha256(0x${hex(PIC_BATCH_TAG)}+toPaddedBytes(firstWindow,1)
            +toPaddedBytes(windowCount,1)+windowRootBlob);
        require(batchCommitment==expectedBatch);
    }
}
`;
const picAuthHelper = compileNamed(picAuthHelperSource, 'v4 PIC batch authentication helper', {
  rescheduleStacks: false,
  optimizeFor: 'size',
});
assert(picAuthHelper.length <= 1000, 'v4 PIC batch authentication helper unexpectedly expanded');
const picBatchCommitmentOffsets = picBatchCommitments.map((commitment, index) => {
  const offset = Buffer.from(picAuthHelper).indexOf(Buffer.from(commitment));
  assert(offset >= 0 && Buffer.from(picAuthHelper).indexOf(Buffer.from(commitment), offset + 1) < 0,
    `v4 PIC batch commitment ${index} is not uniquely embedded in the helper`);
  return offset;
});
const picBatchDomainOffset = Buffer.from(picAuthHelper).indexOf(Buffer.from(PIC_BATCH_TAG));
assert(picBatchDomainOffset >= 0 &&
  Buffer.from(picAuthHelper).indexOf(Buffer.from(PIC_BATCH_TAG), picBatchDomainOffset + 1) < 0,
'v4 PIC batch domain is not uniquely embedded in the helper');

const quotientSources = quotientPayloads.map((_, index) => quotientSource(index));
const quotientRedeems = quotientSources.map((source, index) => compileNamed(
  source,
  `quotient ${index}`,
  { optimizeFor: 'size' },
));
const fusedQuotientSource = quotientSource(
  0,
  FUSED_QUOTIENT_INPUT_INDEX,
  TEMPLATE_TOTAL_INPUTS,
  fusedQuotientTailBytes,
);
const fusedQuotientRedeem = compileNamed(
  fusedQuotientSource,
  'fused block-4 quotient verifier',
  { optimizeFor: 'size' },
);
const OP = {
  ONE: 0x51,
  VERIFY: 0x69,
  TWODROP: 0x6d,
  TOALTSTACK: 0x6b,
  FROMALTSTACK: 0x6c,
  CAT: 0x7e,
  DROP: 0x75,
  DUP: 0x76,
  NIP: 0x77,
  SPLIT: 0x7f,
  SIZE: 0x82,
  EQUALVERIFY: 0x88,
  DEFINE: 0x89,
  INVOKE: 0x8a,
  SUB: 0x94,
  INPUTBYTECODE: 0xca,
};
const pushVmNumber = (value) => value === 0
  ? Uint8Array.of(0)
  : value <= 16
    ? Uint8Array.of(0x50 + value)
    : encodeDataPush(bigIntToVmNumber(BigInt(value)));
const sliceTopBytes = (start, end) => concat(
  pushVmNumber(end),
  Uint8Array.of(OP.SPLIT, OP.DROP),
  ...(start === 0 ? [] : [
    pushVmNumber(start),
    Uint8Array.of(OP.SPLIT, OP.NIP),
  ]),
);
const TEMPLATE_FUNCTION_ID = 101;
const TEMPLATE_COMMON_FUNCTION_ID = 102;
const TEMPLATE_EXTRA_FUNCTION_ID = 103;
const PIC_AUTH_FUNCTION_ID = 117;
const templateCommonOffsets = new Map([
  ['First', 756],
  ['AdditionTail', 633],
  ['AdditionMiddle', 648],
]);
const templateCommonLength = 1615;
const templateCommonCarrier = templateClasses.find(({ name }) => name === 'AdditionTail');
const templateExtraOffsets = new Map([
  ['AdditionTail', 633 + templateCommonLength],
  ['AdditionMiddle', 648 + templateCommonLength],
]);
const templateExtraLength = 257;
const templateExtraCarrier = templateClasses.find(({ name }) => name === 'AdditionMiddle');
assert(templateCommonCarrier !== undefined, 'shared template carrier is missing');
assert(templateExtraCarrier !== undefined, 'extra shared template carrier is missing');
const templateCommonBody = templateCommonCarrier.core.slice(
  templateCommonOffsets.get(templateCommonCarrier.name),
  templateCommonOffsets.get(templateCommonCarrier.name) + templateCommonLength,
);
assert(templateCommonBody.length === templateCommonLength,
  'shared template body length changed');
const templateCommonOpcodes = decodeAuthenticationInstructions(templateCommonBody)
  .map((instruction) => OpcodesBCH[instruction.opcode]);
let templateCommonConditionalDepth = 0;
let templateCommonLoopDepth = 0;
templateCommonOpcodes.forEach((opcode) => {
  if (opcode === 'OP_IF' || opcode === 'OP_NOTIF') templateCommonConditionalDepth += 1;
  if (opcode === 'OP_ENDIF') templateCommonConditionalDepth -= 1;
  if (opcode === 'OP_BEGIN') templateCommonLoopDepth += 1;
  if (opcode === 'OP_UNTIL') templateCommonLoopDepth -= 1;
  assert(templateCommonConditionalDepth >= 0 && templateCommonLoopDepth >= 0,
    'shared template body crosses a control-flow boundary');
});
assert(templateCommonConditionalDepth === 0 && templateCommonLoopDepth === 0,
  'shared template body has unbalanced control flow');
assert(!templateCommonOpcodes.some((opcode) => [
  'OP_ACTIVEBYTECODE',
  'OP_CODESEPARATOR',
  'OP_DEFINE',
  'OP_INVOKE',
  'OP_RETURN',
].includes(opcode)), 'shared template body contains a context-sensitive opcode');
const templateExtraBody = templateExtraCarrier.core.slice(
  templateExtraOffsets.get(templateExtraCarrier.name),
  templateExtraOffsets.get(templateExtraCarrier.name) + templateExtraLength,
);
assert(templateExtraBody.length === templateExtraLength,
  'extra shared template body length changed');
const templateExtraOpcodes = decodeAuthenticationInstructions(templateExtraBody)
  .map((instruction) => OpcodesBCH[instruction.opcode]);
let templateExtraConditionalDepth = 0;
let templateExtraLoopDepth = 0;
templateExtraOpcodes.forEach((opcode) => {
  if (opcode === 'OP_IF' || opcode === 'OP_NOTIF') templateExtraConditionalDepth += 1;
  if (opcode === 'OP_ENDIF') templateExtraConditionalDepth -= 1;
  if (opcode === 'OP_BEGIN') templateExtraLoopDepth += 1;
  if (opcode === 'OP_UNTIL') templateExtraLoopDepth -= 1;
  assert(templateExtraConditionalDepth >= 0 && templateExtraLoopDepth >= 0,
    'extra shared template body crosses a control-flow boundary');
});
assert(templateExtraConditionalDepth === 0 && templateExtraLoopDepth === 0,
  'extra shared template body has unbalanced control flow');
assert(!templateExtraOpcodes.some((opcode) => [
  'OP_ACTIVEBYTECODE',
  'OP_CODESEPARATOR',
  'OP_DEFINE',
  'OP_INVOKE',
  'OP_RETURN',
].includes(opcode)), 'extra shared template body contains a context-sensitive opcode');
[templateCommonCarrier, ...templateClasses.filter(
  (template) => template !== templateCommonCarrier,
)].forEach((template) => {
  const offset = templateCommonOffsets.get(template.name);
  if (offset === undefined) return;
  assert(equalBytes(template.core.slice(offset, offset + templateCommonLength), templateCommonBody),
    `${template.name} no longer contains the exact shared template body`);
  const extraOffset = templateExtraOffsets.get(template.name);
  if (extraOffset !== undefined) {
    assert(extraOffset === offset + templateCommonLength,
      `${template.name} extra shared body is no longer adjacent`);
    assert(equalBytes(template.core.slice(extraOffset, extraOffset + templateExtraLength),
      templateExtraBody), `${template.name} no longer contains the exact extra shared body`);
  }
  template.core = concat(
    template.core.slice(0, offset),
    pushVmNumber(TEMPLATE_COMMON_FUNCTION_ID),
    Uint8Array.of(OP.INVOKE),
    ...(extraOffset === undefined ? [] : [
      pushVmNumber(TEMPLATE_EXTRA_FUNCTION_ID),
      Uint8Array.of(OP.INVOKE),
    ]),
    template.core.slice(
      offset + templateCommonLength + (extraOffset === undefined ? 0 : templateExtraLength),
    ),
  );
  template.digest = sha256(template.core);
});
const templateForBlock = (index) => templateClasses.find(({ members }) => members.includes(index));
const templateConfig = (record, index) => concat(
  pushVmNumber(index),
  pushVmNumber(index === 0 ? 0 : blockRecords[index - 1].payload.length),
  encodeDataPush(record.fixedCommitment),
  ...(index === 20 ? [Uint8Array.of(OP.FROMALTSTACK)] : []),
  pushVmNumber(TEMPLATE_FUNCTION_ID),
  Uint8Array.of(OP.INVOKE),
);
const templateCommonBodyPush = encodeDataPush(templateCommonBody);
const templateCommonStart = templateCommonBodyPush.length - templateCommonBody.length;
const templateCommonEnd = templateCommonStart + templateCommonBody.length;
const templateExtraBodyPush = encodeDataPush(templateExtraBody);
const templateExtraStart = templateExtraBodyPush.length - templateExtraBody.length;
const templateExtraEnd = templateExtraStart + templateExtraBody.length;
const templateFactorDensityPaddingBytes = Number(
  process.env.RPA_TEMPLATE_FACTOR_DENSITY_PADDING ?? 156,
);
let templateFactorDensityPadding = new Uint8Array();
for (let payloadLength = 0;
  payloadLength <= templateFactorDensityPaddingBytes && templateFactorDensityPadding.length === 0;
  payloadLength += 1) {
  const candidate = concat(encodeDataPush(new Uint8Array(payloadLength)), Uint8Array.of(OP.DROP));
  if (candidate.length === templateFactorDensityPaddingBytes) {
    templateFactorDensityPadding = candidate;
  }
}
assert(templateFactorDensityPadding.length === templateFactorDensityPaddingBytes,
  'shared-template density padding cannot be encoded at the requested length');
const templateTailDensityPaddingBytes = Number(
  process.env.RPA_TEMPLATE_TAIL_DENSITY_PADDING ?? 41,
);
let templateTailDensityPadding = new Uint8Array();
for (let payloadLength = 0;
  payloadLength <= templateTailDensityPaddingBytes && templateTailDensityPadding.length === 0;
  payloadLength += 1) {
  const candidate = concat(encodeDataPush(new Uint8Array(payloadLength)), Uint8Array.of(OP.DROP));
  if (candidate.length === templateTailDensityPaddingBytes) {
    templateTailDensityPadding = candidate;
  }
}
assert(templateTailDensityPadding.length === templateTailDensityPaddingBytes,
  'AdditionTail shared-template density padding cannot be encoded');
const loadTemplateBody = (carrier, carrierRedeemLength, start, end, functionId) => concat(
  pushVmNumber(carrier.representative + 1),
  Uint8Array.of(OP.INPUTBYTECODE, OP.SIZE),
  pushVmNumber(carrierRedeemLength),
  Uint8Array.of(OP.SUB, OP.SPLIT, OP.NIP),
  sliceTopBytes(start, end),
  pushVmNumber(functionId),
  Uint8Array.of(OP.DEFINE),
);
let templateCarrierLengths = new Map([
  [templateCommonCarrier.name, 4_000],
  [templateExtraCarrier.name, 4_000],
]);
let templateCarrierLengthsStable = false;
for (let iteration = 0;iteration < 4 && !templateCarrierLengthsStable;iteration += 1) {
  templateClasses.forEach((template) => {
    const record = blockRecords[template.representative];
    const definitions = [];
    if (template === templateCommonCarrier) {
      definitions.push(concat(
        templateCommonBodyPush,
        pushVmNumber(TEMPLATE_COMMON_FUNCTION_ID),
        Uint8Array.of(OP.DEFINE),
      ));
    }
    if (template === templateExtraCarrier) {
      definitions.push(concat(
        templateExtraBodyPush,
        pushVmNumber(TEMPLATE_EXTRA_FUNCTION_ID),
        Uint8Array.of(OP.DEFINE),
      ));
    }
    if (templateCommonOffsets.has(template.name) && template !== templateCommonCarrier) {
      definitions.push(loadTemplateBody(
        templateCommonCarrier,
        templateCarrierLengths.get(templateCommonCarrier.name),
        templateCommonStart,
        templateCommonEnd,
        TEMPLATE_COMMON_FUNCTION_ID,
      ));
    }
    if (templateExtraOffsets.has(template.name) && template !== templateExtraCarrier) {
      definitions.push(loadTemplateBody(
        templateExtraCarrier,
        templateCarrierLengths.get(templateExtraCarrier.name),
        templateExtraStart,
        templateExtraEnd,
        TEMPLATE_EXTRA_FUNCTION_ID,
      ));
    }
    const commonDefinition = concat(...definitions);
    const factorDensityPadding = template.name === 'AdditionMiddle'
      ? templateFactorDensityPadding
      : template.name === 'AdditionTail'
        ? templateTailDensityPadding
        : new Uint8Array();
    const corePush = encodeDataPush(template.core);
    template.coreStart = commonDefinition.length + factorDensityPadding.length +
      corePush.length - template.core.length;
    template.representativeRedeem = concat(
      commonDefinition,
      factorDensityPadding,
      corePush,
      pushVmNumber(TEMPLATE_FUNCTION_ID),
      Uint8Array.of(OP.DEFINE),
      templateConfig(record, template.representative),
    );
  });
  const nextCarrierLengths = new Map([
    [templateCommonCarrier.name, templateCommonCarrier.representativeRedeem.length],
    [templateExtraCarrier.name, templateExtraCarrier.representativeRedeem.length],
  ]);
  templateCarrierLengthsStable = [...nextCarrierLengths].every(([name, length]) =>
    templateCarrierLengths.get(name) === length);
  templateCarrierLengths = nextCarrierLengths;
}
assert(templateCarrierLengthsStable, 'shared-template carrier lengths did not converge');
templateClasses.forEach((template) => {
  assert(template.representativeRedeem.length ===
    (templateCarrierLengths.get(template.name) ?? template.representativeRedeem.length),
  `${template.name} representative redeem length changed after convergence`);
});
const loadTemplateCommonBody = () => loadTemplateBody(
  templateCommonCarrier,
  templateCarrierLengths.get(templateCommonCarrier.name),
  templateCommonStart,
  templateCommonEnd,
  TEMPLATE_COMMON_FUNCTION_ID,
);
const loadTemplateExtraBody = () => loadTemplateBody(
  templateExtraCarrier,
  templateCarrierLengths.get(templateExtraCarrier.name),
  templateExtraStart,
  templateExtraEnd,
  TEMPLATE_EXTRA_FUNCTION_ID,
);
const templateBlockRedeems = blockRecords.map((record, index) => {
  const template = templateForBlock(index);
  assert(template !== undefined, `block ${index} has no template class`);
  if (index === template.representative) return template.representativeRedeem;

  const representativeRedeem = template.representativeRedeem;
  const coreStart = template.coreStart;
  const coreEnd = coreStart + template.core.length;
  const redeem = concat(
    ...(templateCommonOffsets.has(template.name) ? [loadTemplateCommonBody()] : []),
    ...(templateExtraOffsets.has(template.name) ? [loadTemplateExtraBody()] : []),
    pushVmNumber(template.representative + 1),
    Uint8Array.of(OP.INPUTBYTECODE),
    Uint8Array.of(OP.SIZE),
    pushVmNumber(representativeRedeem.length),
    Uint8Array.of(OP.SUB, OP.SPLIT, OP.NIP),
    sliceTopBytes(coreStart, coreEnd),
    pushVmNumber(TEMPLATE_FUNCTION_ID),
    Uint8Array.of(OP.DEFINE),
    templateConfig(record, index),
  );
  const densityPaddingBytes = Number(REGULAR_DENSITY_PADDING[index] ?? 0);
  assert(Number.isInteger(densityPaddingBytes) && densityPaddingBytes >= 0,
    `block ${index} density padding is invalid`);
  if (densityPaddingBytes === 0) return redeem;
  assert(template.name === 'Regular' && densityPaddingBytes >= 2 && densityPaddingBytes <= 76,
    `block ${index} density padding is outside the audited Regular form`);
  return concat(
    encodeDataPush(new Uint8Array(densityPaddingBytes - 2)),
    Uint8Array.of(OP.DROP),
    redeem,
  );
});

const PIC_BLOCK4_INDEX = 4;
const PIC_BLOCK4_INPUT = PIC_BLOCK4_INDEX + 1;
const picBaseBlock4Redeem = templateBlockRedeems[PIC_BLOCK4_INDEX];
const picAuthHelperPush = encodeDataPush(picAuthHelper);
const picFixedBlobPush = encodeDataPush(picFixedBlob);
const fusedQuotientOpcodes = decodeAuthenticationInstructions(fusedQuotientRedeem)
  .map((instruction) => OpcodesBCH[instruction.opcode]);
assert(!fusedQuotientOpcodes.some((opcode) => [
  'OP_ACTIVEBYTECODE',
  'OP_CODESEPARATOR',
  'OP_DEFINE',
  'OP_INVOKE',
  'OP_RETURN',
].includes(opcode)), 'inline fused quotient helper contains a context-sensitive opcode');
const fusedQuotientTailStart = encodeDataPush(
  blockPayloads[FUSED_QUOTIENT_TAIL_BLOCK_INDEX],
).length + encodeDataPush(
  blockEvaluationPayloads[FUSED_QUOTIENT_TAIL_BLOCK_INDEX],
).length + (encodeDataPush(fusedQuotientTailPayload).length -
  fusedQuotientTailPayload.length);
const fusedQuotientTailEnd = fusedQuotientTailStart + fusedQuotientTailPayload.length;
const fusedQuotientTailLoader = concat(
  pushVmNumber(FUSED_QUOTIENT_TAIL_INPUT_INDEX),
  Uint8Array.of(OP.INPUTBYTECODE),
  sliceTopBytes(fusedQuotientTailStart, fusedQuotientTailEnd),
);
const fusedQuotientTailLengthGuard = concat(
  Uint8Array.of(OP.SIZE),
  pushVmNumber(fusedQuotientTailPayload.length),
  Uint8Array.of(OP.EQUALVERIFY, OP.DROP),
);
assert(Number.isInteger(PIC_BLOCK4_DENSITY_PADDING) &&
  PIC_BLOCK4_DENSITY_PADDING >= 0 && PIC_BLOCK4_DENSITY_PADDING <= 1_000,
'block-4 density padding is outside the audited form');
let picBlock4DensityPadding = new Uint8Array();
for (let payloadLength = 0;
  payloadLength <= PIC_BLOCK4_DENSITY_PADDING && picBlock4DensityPadding.length === 0;
  payloadLength += 1) {
  const candidate = concat(encodeDataPush(new Uint8Array(payloadLength)), Uint8Array.of(OP.DROP));
  if (candidate.length === PIC_BLOCK4_DENSITY_PADDING) picBlock4DensityPadding = candidate;
}
assert(PIC_BLOCK4_DENSITY_PADDING === 0 ||
  picBlock4DensityPadding.length === PIC_BLOCK4_DENSITY_PADDING,
'block-4 density padding cannot be encoded at the requested length');
const picBlock4Redeem = concat(
  picAuthHelperPush,
  Uint8Array.of(OP.DROP),
  picFixedBlobPush,
  Uint8Array.of(OP.DROP),
  fusedQuotientTailLoader,
  fusedQuotientRedeem,
  Uint8Array.of(OP.VERIFY),
  picBlock4DensityPadding,
  picBaseBlock4Redeem,
);
templateBlockRedeems[PIC_BLOCK4_INDEX] = picBlock4Redeem;

const picHelperStart = picAuthHelperPush.length - picAuthHelper.length;
const picHelperEnd = picHelperStart + picAuthHelper.length;
const picFixedStart = picAuthHelperPush.length + 1 +
  (picFixedBlobPush.length - picFixedBlob.length);
const picFixedEnd = picFixedStart + picFixedBlob.length;
const picCarrierRedeemLoader = concat(
  pushVmNumber(PIC_BLOCK4_INPUT),
  Uint8Array.of(OP.INPUTBYTECODE, OP.SIZE),
  pushVmNumber(picBlock4Redeem.length),
  Uint8Array.of(OP.SUB, OP.SPLIT, OP.NIP),
);
const picAuthLoader = concat(
  picCarrierRedeemLoader,
  sliceTopBytes(picHelperStart, picHelperEnd),
  pushVmNumber(PIC_AUTH_FUNCTION_ID),
  Uint8Array.of(OP.DEFINE),
);
const picAuthWrapper = (firstWindow, windowCount, retainCarrierRedeem = false) => concat(
  ...(retainCarrierRedeem ? [picCarrierRedeemLoader, Uint8Array.of(OP.DUP)] : [picAuthLoader]),
  ...(retainCarrierRedeem ? [
    sliceTopBytes(picHelperStart, picHelperEnd),
    pushVmNumber(PIC_AUTH_FUNCTION_ID),
    Uint8Array.of(OP.DEFINE),
  ] : []),
  pushVmNumber(windowCount),
  pushVmNumber(firstWindow),
  pushVmNumber(PIC_AUTH_FUNCTION_ID),
  Uint8Array.of(OP.INVOKE, OP.ONE, OP.EQUALVERIFY),
);
const picBlock2AuthWrapper = picAuthWrapper(
  picAuthBatches[1].firstWindow,
  picAuthBatches[1].windowCount,
);
assert(picBlock2AuthWrapper.at(-2) === OP.ONE &&
  picBlock2AuthWrapper.at(-1) === OP.EQUALVERIFY,
'block-2 PIC authentication result guard changed');
assert(Number.isInteger(PIC_BLOCK2_DENSITY_PADDING) &&
  PIC_BLOCK2_DENSITY_PADDING >= 0 && PIC_BLOCK2_DENSITY_PADDING <= 1_000,
'block-2 density padding is outside the audited form');
let picBlock2DensityPadding = new Uint8Array();
for (let payloadLength = 0;
  payloadLength <= PIC_BLOCK2_DENSITY_PADDING && picBlock2DensityPadding.length === 0;
  payloadLength += 1) {
  const candidate = concat(encodeDataPush(new Uint8Array(payloadLength)), Uint8Array.of(OP.DROP));
  if (candidate.length === PIC_BLOCK2_DENSITY_PADDING) picBlock2DensityPadding = candidate;
}
assert(PIC_BLOCK2_DENSITY_PADDING === 0 ||
  picBlock2DensityPadding.length === PIC_BLOCK2_DENSITY_PADDING,
'block-2 density padding cannot be encoded');
templateBlockRedeems[2] = concat(
  picBlock2DensityPadding,
  picBlock2AuthWrapper.slice(0, -2),
  Uint8Array.of(OP.VERIFY),
  templateBlockRedeems[2],
);
const picBlock1AuthWrapper = picAuthWrapper(
  picAuthBatches[2].firstWindow,
  picAuthBatches[2].windowCount,
);
assert(picBlock1AuthWrapper.at(-2) === OP.ONE &&
  picBlock1AuthWrapper.at(-1) === OP.EQUALVERIFY,
'block-1 PIC authentication result guard changed');
templateBlockRedeems[1] = concat(
  picBlock1AuthWrapper.slice(0, -2),
  Uint8Array.of(OP.VERIFY),
  templateBlockRedeems[1],
);
const picBlock20AuthWrapper = picAuthWrapper(
  picAuthBatches[3].firstWindow,
  picAuthBatches[3].windowCount,
  true,
);
assert(picBlock20AuthWrapper.at(-2) === OP.ONE &&
  picBlock20AuthWrapper.at(-1) === OP.EQUALVERIFY,
'block-20 PIC authentication result guard changed');
templateBlockRedeems[20] = concat(
  picBlock20AuthWrapper.slice(0, -2),
  Uint8Array.of(OP.VERIFY),
  sliceTopBytes(picFixedStart, picFixedEnd),
  Uint8Array.of(OP.TOALTSTACK),
  templateBlockRedeems[20],
);
const picBlock15AuthWrapper = picAuthWrapper(
  picAuthBatches[4].firstWindow,
  picAuthBatches[4].windowCount,
);
assert(picBlock15AuthWrapper.at(-2) === OP.ONE &&
  picBlock15AuthWrapper.at(-1) === OP.EQUALVERIFY,
'block-15 PIC authentication result guard changed');
templateBlockRedeems[15] = concat(
  fusedQuotientTailLengthGuard,
  picBlock15AuthWrapper.slice(0, -2),
  Uint8Array.of(OP.VERIFY),
  templateBlockRedeems[15],
);
const templateSiblingLockings = templateBlockRedeems.map(
  (redeem) => encodeLockingBytecodeP2sh32(hash256(redeem)),
);
const templateSiblingLockingDigest = sha256(concat(...templateSiblingLockings));
const templateCoordinatorCore = compileNamed(
  coordinatorSource(
    templateSiblingLockingDigest,
    true,
    TEMPLATE_TOTAL_INPUTS,
    true,
  ),
  'template coordinator',
);
const templateCoordinatorCoreRedeem = concat(
  picAuthWrapper(
    picAuthBatches[0].firstWindow,
    picAuthBatches[0].windowCount,
    true,
  ).slice(0, -2),
  Uint8Array.of(OP.VERIFY),
  sliceTopBytes(picFixedStart, picFixedEnd),
  templateCoordinatorCore,
);
assert(Number.isInteger(COORDINATOR_DENSITY_PADDING) &&
  COORDINATOR_DENSITY_PADDING >= 0 && COORDINATOR_DENSITY_PADDING <= 1_000,
'coordinator density padding is outside the audited form');
let coordinatorDensityPadding = new Uint8Array();
for (let payloadLength = 0;
  payloadLength <= COORDINATOR_DENSITY_PADDING && coordinatorDensityPadding.length === 0;
  payloadLength += 1) {
  const candidate = concat(encodeDataPush(new Uint8Array(payloadLength)), Uint8Array.of(OP.DROP));
  if (candidate.length === COORDINATOR_DENSITY_PADDING) coordinatorDensityPadding = candidate;
}
assert(COORDINATOR_DENSITY_PADDING === 0 ||
  coordinatorDensityPadding.length === COORDINATOR_DENSITY_PADDING,
'coordinator density padding cannot be encoded at the requested length');
const templateCoordinatorRedeem = concat(
  coordinatorDensityPadding,
  templateCoordinatorCoreRedeem,
);
const siblingLockings = [...blockRedeems, ...quotientRedeems].map(
  (redeem) => encodeLockingBytecodeP2sh32(hash256(redeem)),
);
assert(siblingLockings.every((locking) => locking.length === 35), 'sibling P2SH32 locking length changed');
const siblingLockingDigest = sha256(concat(...siblingLockings));
const coordinatorRedeem = compileNamed(
  coordinatorSource(siblingLockingDigest),
  'coordinator',
);
const coordinatorLocking = encodeLockingBytecodeP2sh32(hash256(coordinatorRedeem));

const makeCoordinatorInput = (header = transcriptHeader, statement = statementBytes) => ({
  role: 'coordinator',
  payload: null,
  evaluation: null,
  redeem: coordinatorRedeem,
  locking: coordinatorLocking,
  unlocking: concat(
    encodeDataPush(header),
    encodeDataPush(statement),
    encodeDataPush(coordinatorRedeem),
  ),
});
const makePayloadInput = (role, payload, evaluation, redeem) => ({
  role,
  payload,
  evaluation,
  redeem,
  locking: encodeLockingBytecodeP2sh32(hash256(redeem)),
  unlocking: evaluation === null
    ? concat(encodeDataPush(payload), encodeDataPush(redeem))
    : concat(encodeDataPush(payload), encodeDataPush(evaluation), encodeDataPush(redeem)),
});
const makeInputs = () => [
  makeCoordinatorInput(),
  ...blockPayloads.map((payload, index) => makePayloadInput(
    `block-${index}`,
    payload,
    blockEvaluationPayloads[index],
    blockRedeems[index],
  )),
  ...quotientPayloads.map((payload, index) => makePayloadInput(
    `quotient-${index}`,
    payload,
    quotientPayloads.length === 1 ? null : quotientEvaluationPayloads[index],
    quotientRedeems[index],
  )),
];
const makeTemplateBlockUnlocking = (payload, evaluation, quotientChunk, redeem) => concat(
  encodeDataPush(payload),
  encodeDataPush(evaluation),
  ...(quotientChunk === null ? [] : [encodeDataPush(quotientChunk)]),
  encodeDataPush(redeem),
);
const makeTemplateInputs = () => [{
  role: 'coordinator-template-classes',
  payload: null,
  evaluation: null,
  redeem: templateCoordinatorRedeem,
  locking: encodeLockingBytecodeP2sh32(hash256(templateCoordinatorRedeem)),
  unlocking: concat(
    encodeDataPush(transcriptHeader),
    encodeDataPush(statementBytes),
    encodeDataPush(templateCoordinatorRedeem),
  ),
}, ...blockPayloads.map((payload, index) => {
  const evaluation = blockEvaluationPayloads[index];
  const redeem = templateBlockRedeems[index];
  const quotientChunk = index === FUSED_QUOTIENT_BLOCK_INDEX
    ? fusedQuotientHeadPayload
    : index === FUSED_QUOTIENT_TAIL_BLOCK_INDEX
      ? fusedQuotientTailPayload
      : null;
  return {
    role: `block-${index}-template-${templateForBlock(index).name}`,
    payload,
    evaluation,
    quotientChunk,
    quotientChunkRole: index === FUSED_QUOTIENT_BLOCK_INDEX
      ? 'head'
      : index === FUSED_QUOTIENT_TAIL_BLOCK_INDEX
        ? 'tail'
        : null,
    redeem,
    locking: encodeLockingBytecodeP2sh32(hash256(redeem)),
    unlocking: makeTemplateBlockUnlocking(payload, evaluation, quotientChunk, redeem),
  };
})];

const verificationData = (inputs) => {
  const transaction = {
    version: 2,
    inputs: inputs.map((input, index) => ({
      outpointTransactionHash: new Uint8Array(32),
      outpointIndex: index,
      sequenceNumber: 0,
      unlockingBytecode: input.unlocking,
    })),
    outputs: [{ lockingBytecode: OP_RETURN, valueSatoshis: OUTPUT_SATOSHIS }],
    locktime: 0,
  };
  const wireBytes = encodeTransactionBch(transaction).length;
  const totalInputSatoshis = OUTPUT_SATOSHIS + BigInt(wireBytes);
  const quotient = totalInputSatoshis / BigInt(inputs.length);
  const remainder = totalInputSatoshis % BigInt(inputs.length);
  return {
    transaction,
    sourceOutputs: inputs.map((input, index) => ({
      lockingBytecode: input.locking,
      valueSatoshis: quotient + (BigInt(index) < remainder ? 1n : 0n),
    })),
  };
};
const evaluateInput = (inputs, inputIndex, vm) => {
  const state = vm.evaluate({ inputIndex, ...verificationData(inputs) });
  const top = state.stack[state.stack.length - 1];
  return {
    accepted: state.error === undefined && state.stack.length === 1 &&
      top?.length === 1 && top[0] === 1,
    error: state.error ?? null,
    operationCost: state.metrics.operationCost,
    metrics: state.metrics,
    instructionPointer: state.ip,
    functionTable: state.functionTable,
  };
};

const inputs = makeInputs();
const consensusOutcomes = inputs.map((_, index) => evaluateInput(inputs, index, consensusVm));
const standardOutcomes = inputs.map((_, index) => evaluateInput(inputs, index, standardVm));
const validData = verificationData(inputs);
const wireBytes = encodeTransactionBch(validData.transaction).length;
const wholeConsensusVerified = consensusVm.verify(validData) === true;
const wholeStandardVerified = standardVm.verify(validData) === true;

assert(inputs.every((input) => input.locking.length <= 10_000), 'locking bytecode exceeds 10,000 bytes');
assert(inputs.every((input) => input.unlocking.length <= 10_000), 'unlocking bytecode exceeds 10,000 bytes');
assert(consensusOutcomes.every((outcome) => outcome.accepted),
  `valid relation transaction failed consensus VM: ${JSON.stringify(consensusOutcomes.map(
    (outcome, index) => outcome.accepted ? null : { index, ...outcome },
  ).filter(Boolean))}`);
assert(standardOutcomes.every((outcome) => outcome.accepted),
  `valid relation transaction failed standard VM input evaluation: ${JSON.stringify(standardOutcomes.map(
    (outcome, index) => outcome.accepted ? null : { index, ...outcome },
  ).filter(Boolean))}`);
assert(wholeConsensusVerified, 'whole relation transaction failed consensus verification');

if (process.env.RPA_TEMPLATE_RUN === '1') {
  const templateInputs = makeTemplateInputs();
  const densityLimitsEnforced = process.env.RPA_TEMPLATE_RELAX_DENSITY !== '1';
  const templateConsensusVm = densityLimitsEnforced ? consensusVm : measurementConsensusVm;
  const templateStandardVm = densityLimitsEnforced ? standardVm : measurementStandardVm;
  const templateConsensusOutcomes = templateInputs.map(
    (_, index) => evaluateInput(templateInputs, index, templateConsensusVm),
  );
  const templateStandardOutcomes = templateInputs.map(
    (_, index) => evaluateInput(templateInputs, index, templateStandardVm),
  );
  const templateValidData = verificationData(templateInputs);
  const templateWireBytes = encodeTransactionBch(templateValidData.transaction).length;
  const templateFeeSatoshis = templateValidData.sourceOutputs.reduce(
    (total, output) => total + output.valueSatoshis,
    0n,
  ) - templateValidData.transaction.outputs.reduce(
    (total, output) => total + output.valueSatoshis,
    0n,
  );
  const templateWholeConsensusVerified = templateConsensusVm.verify(templateValidData) === true;
  const templateWholeStandardVerified = templateStandardVm.verify(templateValidData) === true;
  assert(templateFeeSatoshis === BigInt(templateWireBytes),
    'template transaction fee is not exactly one satoshi per byte');
  assert(templateInputs.every((input) => input.locking.length <= 10_000),
    'template locking bytecode exceeds 10,000 bytes');
  assert(templateInputs.every((input) => input.unlocking.length <= 10_000),
    `template unlocking bytecode exceeds 10,000 bytes: ${Math.max(
      ...templateInputs.map((input) => input.unlocking.length),
    )}`);

  const picAuthHostIndices = new Map([
    ['coordinator', 0],
    ['block-1', 2],
    ['block-2', 3],
    ['block-15', 16],
    ['block-20', 21],
  ]);
  const padPicGateRedeem = (prefix, targetLength, payloadOnly) => {
    const suffix = payloadOnly
      ? Uint8Array.of(OP.DROP, OP.ONE)
      : Uint8Array.of(OP.TWODROP, OP.ONE);
    const gap = targetLength - prefix.length - suffix.length;
    for (let payloadLength = 0; payloadLength <= gap; payloadLength += 1) {
      const padding = encodeDataPush(new Uint8Array(payloadLength));
      if (padding.length + 1 === gap) {
        return concat(prefix, padding, Uint8Array.of(OP.DROP), suffix);
      }
    }
    throw new Error(`cannot pad PIC gate redeem to ${targetLength} bytes`);
  };
  const picGateRedeems = new Map(picAuthBatches.map((batch) => {
    const inputIndex = picAuthHostIndices.get(batch.host);
    assert(inputIndex !== undefined, `PIC auth host ${batch.host} has no input`);
    return [inputIndex, padPicGateRedeem(
      picAuthWrapper(batch.firstWindow, batch.windowCount),
      templateInputs[inputIndex].redeem.length,
      templateInputs[inputIndex].evaluation === null && inputIndex !== 0,
    )];
  }));
  const makePicGateInputs = (fixtureName) => {
    const fixtureRecords = picCache.records[fixtureName];
    assert(fixtureRecords.length === 32, `${fixtureName} PIC fixture count changed`);
    const fixturePublicInputs = publicInputsFromPicRecords(fixtureRecords);
    assert(fixturePublicInputs.every((value) => value >= 0n && value < SCALAR_ORDER),
      `${fixtureName} PIC fixture scalar is noncanonical`);
    const publicBytes = fixturePublicInputs.map((value) => serializeUnsignedLe(value, 32));
    fixtureRecords.forEach((record, window) => {
      assert((publicBytes[0][window] | (publicBytes[1][window] << 8)) === record.index,
        `${fixtureName} window ${window} index endian changed`);
    });

    const inputsForFixture = templateInputs.map((input) => ({
      ...input,
      payload: input.payload === null ? null : Uint8Array.from(input.payload),
      evaluation: input.evaluation === null ? null : Uint8Array.from(input.evaluation),
      redeem: Uint8Array.from(input.redeem),
      locking: Uint8Array.from(input.locking),
      unlocking: Uint8Array.from(input.unlocking),
    }));
    const fixtureStatement = Uint8Array.from(statementBytes);
    fixtureStatement.set(publicBytes[0], public0Offset);
    fixtureStatement.set(publicBytes[1], public1Offset);

    regularPicCarrierBlocks.forEach((blockIndex, carrier) => {
      const inputIndex = blockIndex + 1;
      const payload = inputsForFixture[inputIndex].payload;
      fixtureRecords.slice(carrier * 2, carrier * 2 + 2).forEach((record, inCarrier) => {
        const recordBytes = concat(
          serializeLimbs(record.factor.map(BigInt)),
          Uint8Array.from(Buffer.from(record.path, 'hex')),
        );
        assert(recordBytes.length === PIC_RECORD_BYTES,
          `${fixtureName} window ${carrier * 2 + inCarrier} record length changed`);
        payload.set(recordBytes, PIC_RECORD_REGION_OFFSET + inCarrier * PIC_RECORD_BYTES);
      });
      inputsForFixture[inputIndex].unlocking = concat(
        encodeDataPush(payload),
        encodeDataPush(inputsForFixture[inputIndex].evaluation),
        encodeDataPush(inputsForFixture[inputIndex].redeem),
      );
    });

    picGateRedeems.forEach((redeem, inputIndex) => {
      const input = inputsForFixture[inputIndex];
      input.redeem = redeem;
      input.locking = encodeLockingBytecodeP2sh32(hash256(redeem));
      input.unlocking = inputIndex === 0
        ? concat(
          encodeDataPush(transcriptHeader),
          encodeDataPush(fixtureStatement),
          encodeDataPush(redeem),
        )
        : input.evaluation === null
          ? concat(encodeDataPush(input.payload), encodeDataPush(redeem))
          : concat(
            encodeDataPush(input.payload),
            encodeDataPush(input.evaluation),
            encodeDataPush(redeem),
          );
    });
    return inputsForFixture;
  };
  const picAuthFixtureRows = picFixtureNames.map((fixtureName) => {
    const gateInputs = makePicGateInputs(fixtureName);
    const hosts = picAuthBatches.map((batch) => {
      const inputIndex = picAuthHostIndices.get(batch.host);
      const consensus = evaluateInput(gateInputs, inputIndex, consensusVm);
      const standard = evaluateInput(gateInputs, inputIndex, standardVm);
      assert(consensus.accepted && standard.accepted,
        `${fixtureName} PIC auth batch ${batch.host} failed: ${JSON.stringify({ consensus, standard })}`);
      return {
        host: batch.host,
        inputIndex,
        firstWindow: batch.firstWindow,
        windowCount: batch.windowCount,
        consensusOperationCost: consensus.operationCost,
        standardOperationCost: standard.operationCost,
      };
    });
    return { fixture: fixtureName, publicInputs: publicInputsFromPicRecords(
      picCache.records[fixtureName],
    ).map(String), hosts };
  });
  const replacePicGatePayload = (inputsForFixture, inputIndex, payload) => {
    inputsForFixture[inputIndex].payload = payload;
    inputsForFixture[inputIndex].unlocking = concat(
      encodeDataPush(payload),
      encodeDataPush(inputsForFixture[inputIndex].evaluation),
      encodeDataPush(inputsForFixture[inputIndex].redeem),
    );
  };
  const picGateRejection = (name, inputsForFixture, window) => {
    const owner = picAuthBatches.find((batch) =>
      window >= batch.firstWindow && window < batch.firstWindow + batch.windowCount);
    assert(owner !== undefined, `${name} has no PIC auth owner`);
    const ownerInputIndex = picAuthHostIndices.get(owner.host);
    const consensus = evaluateInput(inputsForFixture, ownerInputIndex, consensusVm);
    const standard = evaluateInput(inputsForFixture, ownerInputIndex, standardVm);
    assert(!consensus.accepted && !standard.accepted,
      `${name} passed its owning PIC auth batch`);
    return {
      window,
      owner: owner.host,
      consensusRejected: true,
      standardRejected: true,
    };
  };
  const mutatedRecordPayload = (inputsForFixture, window) => {
    const inputIndex = regularPicCarrierBlocks[window >> 1] + 1;
    return {
      inputIndex,
      payload: Uint8Array.from(inputsForFixture[inputIndex].payload),
      recordOffset: PIC_RECORD_REGION_OFFSET + (window & 1) * PIC_RECORD_BYTES,
    };
  };

  const changedFactorInputs = makePicGateInputs('committed');
  const changedFactor = mutatedRecordPayload(changedFactorInputs, 12);
  changedFactor.payload[changedFactor.recordOffset] ^= 1;
  replacePicGatePayload(changedFactorInputs, changedFactor.inputIndex, changedFactor.payload);
  const changedFactorRejection = picGateRejection('changed v4 PIC factor', changedFactorInputs, 12);

  const changedPathInputs = makePicGateInputs('committed');
  const changedPath = mutatedRecordPayload(changedPathInputs, 12);
  changedPath.payload[changedPath.recordOffset + PIC_FACTOR_BYTES + 7 * 32] ^= 1;
  replacePicGatePayload(changedPathInputs, changedPath.inputIndex, changedPath.payload);
  const changedPathRejection = picGateRejection('changed v4 PIC path', changedPathInputs, 12);

  const changedScalarInputs = makePicGateInputs('committed');
  const changedScalarStatement = Uint8Array.from(statementBytes);
  changedScalarStatement[public0Offset + 12] ^= 1;
  changedScalarInputs[0].unlocking = concat(
    encodeDataPush(transcriptHeader),
    encodeDataPush(changedScalarStatement),
    encodeDataPush(changedScalarInputs[0].redeem),
  );
  const changedScalarRejection = picGateRejection(
    'changed public scalar with old v4 PIC record', changedScalarInputs, 12,
  );

  const changedBatchCommitmentRejections = picAuthBatches.map((batch, batchIndex) => {
    const changedRootInputs = makePicGateInputs('committed');
    const changedRootRedeem = Uint8Array.from(changedRootInputs[PIC_BLOCK4_INPUT].redeem);
    changedRootRedeem[picHelperStart + picBatchCommitmentOffsets[batchIndex]] ^= 1;
    changedRootInputs[PIC_BLOCK4_INPUT].redeem = changedRootRedeem;
    changedRootInputs[PIC_BLOCK4_INPUT].unlocking = concat(
      encodeDataPush(changedRootInputs[PIC_BLOCK4_INPUT].payload),
      encodeDataPush(changedRootInputs[PIC_BLOCK4_INPUT].evaluation),
      encodeDataPush(changedRootRedeem),
    );
    return {
      host: batch.host,
      ...picGateRejection(
        `changed v4 PIC batch commitment for ${batch.host}`,
        changedRootInputs,
        batch.firstWindow,
      ),
    };
  });

  const changedBatchDomainInputs = makePicGateInputs('committed');
  const changedBatchDomainRedeem = Uint8Array.from(
    changedBatchDomainInputs[PIC_BLOCK4_INPUT].redeem,
  );
  changedBatchDomainRedeem[
    picHelperStart + picBatchDomainOffset + PIC_BATCH_TAG.length - 1
  ] ^= 1;
  changedBatchDomainInputs[PIC_BLOCK4_INPUT].redeem = changedBatchDomainRedeem;
  changedBatchDomainInputs[PIC_BLOCK4_INPUT].unlocking = concat(
    encodeDataPush(changedBatchDomainInputs[PIC_BLOCK4_INPUT].payload),
    encodeDataPush(changedBatchDomainInputs[PIC_BLOCK4_INPUT].evaluation),
    encodeDataPush(changedBatchDomainRedeem),
  );
  const changedBatchDomainRejection = picGateRejection(
    'changed v4 PIC batch domain', changedBatchDomainInputs, 12,
  );

  const changedBatchOrderInputs = makePicGateInputs('committed');
  const changedBatchOrder = mutatedRecordPayload(changedBatchOrderInputs, 12);
  const changedBatchOrderSecond = mutatedRecordPayload(changedBatchOrderInputs, 13);
  assert(changedBatchOrder.inputIndex === changedBatchOrderSecond.inputIndex,
    'v4 PIC order fixture records moved to different carriers');
  const firstRecord = changedBatchOrder.payload.slice(
    changedBatchOrder.recordOffset,
    changedBatchOrder.recordOffset + PIC_RECORD_BYTES,
  );
  const secondRecord = changedBatchOrder.payload.slice(
    changedBatchOrderSecond.recordOffset,
    changedBatchOrderSecond.recordOffset + PIC_RECORD_BYTES,
  );
  changedBatchOrder.payload.set(secondRecord, changedBatchOrder.recordOffset);
  changedBatchOrder.payload.set(firstRecord, changedBatchOrderSecond.recordOffset);
  replacePicGatePayload(
    changedBatchOrderInputs,
    changedBatchOrder.inputIndex,
    changedBatchOrder.payload,
  );
  const changedBatchOrderRejection = picGateRejection(
    'changed v4 PIC record order', changedBatchOrderInputs, 12,
  );

  const wrongCarrierInputs = makePicGateInputs('committed');
  const sourceRecord = mutatedRecordPayload(wrongCarrierInputs, 12);
  const targetRecord = mutatedRecordPayload(wrongCarrierInputs, 14);
  targetRecord.payload.set(
    sourceRecord.payload.slice(sourceRecord.recordOffset, sourceRecord.recordOffset + PIC_RECORD_BYTES),
    targetRecord.recordOffset,
  );
  replacePicGatePayload(wrongCarrierInputs, targetRecord.inputIndex, targetRecord.payload);
  const wrongCarrierRejection = picGateRejection(
    'v4 PIC record under wrong carrier/window tag', wrongCarrierInputs, 14,
  );

  const wrongCountInputs = makePicGateInputs('committed');
  const wrongCountBatch = picAuthBatches[1];
  const wrongCountInputIndex = picAuthHostIndices.get(wrongCountBatch.host);
  const wrongCountRedeem = padPicGateRedeem(
    picAuthWrapper(wrongCountBatch.firstWindow, wrongCountBatch.windowCount - 1),
    templateInputs[wrongCountInputIndex].redeem.length,
    false,
  );
  wrongCountInputs[wrongCountInputIndex].redeem = wrongCountRedeem;
  wrongCountInputs[wrongCountInputIndex].locking =
    encodeLockingBytecodeP2sh32(hash256(wrongCountRedeem));
  wrongCountInputs[wrongCountInputIndex].unlocking = concat(
    encodeDataPush(wrongCountInputs[wrongCountInputIndex].payload),
    encodeDataPush(wrongCountInputs[wrongCountInputIndex].evaluation),
    encodeDataPush(wrongCountRedeem),
  );
  const wrongCountRejection = picGateRejection(
    'v4 PIC batch with changed count', wrongCountInputs, 12,
  );

  const truncatedPathInputs = makePicGateInputs('committed');
  const truncatedPath = mutatedRecordPayload(truncatedPathInputs, 12);
  const truncatedAt = truncatedPath.recordOffset + PIC_FACTOR_BYTES + 101;
  const truncatedRegionEnd = PIC_RECORD_REGION_OFFSET + PIC_RECORD_REGION_BYTES;
  truncatedPath.payload.copyWithin(truncatedAt, truncatedAt + 1, truncatedRegionEnd);
  truncatedPath.payload[truncatedRegionEnd - 1] = 0;
  replacePicGatePayload(truncatedPathInputs, truncatedPath.inputIndex, truncatedPath.payload);
  const truncatedPathRejection = picGateRejection(
    'truncated v4 PIC path layout', truncatedPathInputs, 12,
  );

  const extendedPathInputs = makePicGateInputs('committed');
  const extendedPath = mutatedRecordPayload(extendedPathInputs, 12);
  const extendedAt = extendedPath.recordOffset + PIC_FACTOR_BYTES + 101;
  extendedPath.payload.copyWithin(extendedAt + 1, extendedAt, truncatedRegionEnd - 1);
  extendedPath.payload[extendedAt] = 0;
  replacePicGatePayload(extendedPathInputs, extendedPath.inputIndex, extendedPath.payload);
  const extendedPathRejection = picGateRejection(
    'extended v4 PIC path layout', extendedPathInputs, 12,
  );

  const cloneTemplateInputs = () => templateInputs.map((input) => ({
    ...input,
    payload: input.payload === null ? null : Uint8Array.from(input.payload),
    evaluation: input.evaluation === null ? null : Uint8Array.from(input.evaluation),
    quotientChunk: input.quotientChunk === null || input.quotientChunk === undefined
      ? null
      : Uint8Array.from(input.quotientChunk),
    redeem: Uint8Array.from(input.redeem),
    locking: Uint8Array.from(input.locking),
    unlocking: Uint8Array.from(input.unlocking),
  }));
  const strictRejection = (name, changed) => {
    const data = verificationData(changed);
    const consensusRejected = consensusVm.verify(data) !== true;
    const standardRejected = standardVm.verify(data) !== true;
    assert(consensusRejected && standardRejected, `${name} passed a strict whole-transaction VM`);
    return { name, consensusRejected, standardRejected };
  };
  const templateLoaderLayout = (carrier, start, end, functionId) => {
    const carrierRedeemLength = templateCarrierLengths.get(carrier.name);
    const sourceInputPush = pushVmNumber(carrier.representative + 1);
    const carrierLengthPush = pushVmNumber(carrierRedeemLength);
    const endPush = pushVmNumber(end);
    const startPush = pushVmNumber(start);
    const functionIdPush = pushVmNumber(functionId);
    const loader = loadTemplateBody(carrier, carrierRedeemLength, start, end, functionId);
    const endOffset = sourceInputPush.length + 2 + carrierLengthPush.length + 3;
    const startOffset = endOffset + endPush.length + 2;
    const functionIdOffset = startOffset + startPush.length + 2;
    assert(functionIdOffset + functionIdPush.length + 1 === loader.length,
      `${carrier.name} shared-template loader layout changed`);
    return {
      loader,
      sourceInputPush,
      endPush,
      startPush,
      functionIdPush,
      endOffset,
      startOffset,
      functionIdOffset,
    };
  };
  const mutateTemplateLoader = (layout, offset, before, after, label) => {
    assert(before.length === after.length &&
      equalBytes(layout.loader.slice(offset, offset + before.length), before),
    `${label} no longer identifies the expected loader bytes`);
    const changed = Uint8Array.from(layout.loader);
    changed.set(after, offset);
    return changed;
  };
  const replaceTemplateBlockRedeem = (inputsForFixture, inputIndex, redeem) => {
    const input = inputsForFixture[inputIndex];
    assert(input.payload !== null && input.evaluation !== null,
      `shared template mutation target ${inputIndex} is not a block input`);
    input.redeem = redeem;
    input.locking = encodeLockingBytecodeP2sh32(hash256(redeem));
    input.unlocking = makeTemplateBlockUnlocking(
      input.payload,
      input.evaluation,
      input.quotientChunk,
      redeem,
    );
  };
  const assertTemplateMutationRejected = (name, changed, targetInput) => {
    assert(!evaluateInput(changed, targetInput, consensusVm).accepted &&
      !evaluateInput(changed, targetInput, standardVm).accepted,
    `${name} passed its shared-template consumer under a strict VM`);
  };
  const templateFactoringMutationInputs = [];
  const commonCarrierInput = templateCommonCarrier.representative + 1;
  const commonMutationTarget = templateClasses.find(({ name }) => name === 'First')
    .representative + 1;
  const changedCommonHelperInputs = cloneTemplateInputs();
  const changedCommonCarrierRedeem = Uint8Array.from(
    changedCommonHelperInputs[commonCarrierInput].redeem,
  );
  const commonCarrierPrefix = changedCommonCarrierRedeem.length -
    templateCommonCarrier.representativeRedeem.length;
  const commonBodyOffset = commonCarrierPrefix + templateCommonStart;
  assert(commonCarrierPrefix >= 0 && changedCommonCarrierRedeem[commonBodyOffset] !== 0x6a,
    'shared template helper mutation is invalid');
  changedCommonCarrierRedeem[commonBodyOffset] = 0x6a;
  replaceTemplateBlockRedeem(changedCommonHelperInputs, commonCarrierInput,
    changedCommonCarrierRedeem);
  assertTemplateMutationRejected(
    'changed common template helper byte',
    changedCommonHelperInputs,
    commonMutationTarget,
  );
  templateFactoringMutationInputs.push({
    name: 'changed-template-common-helper-byte',
    inputs: changedCommonHelperInputs,
  });

  const extraCarrierInput = templateExtraCarrier.representative + 1;
  const extraMutationTarget = commonCarrierInput;
  const changedExtraHelperInputs = cloneTemplateInputs();
  const changedExtraCarrierRedeem = Uint8Array.from(
    changedExtraHelperInputs[extraCarrierInput].redeem,
  );
  const extraCarrierPrefix = changedExtraCarrierRedeem.length -
    templateExtraCarrier.representativeRedeem.length;
  const extraBodyOffset = extraCarrierPrefix + loadTemplateCommonBody().length +
    templateExtraStart;
  assert(extraCarrierPrefix >= 0 && changedExtraCarrierRedeem[extraBodyOffset] !== 0x6a,
    'extra shared template helper mutation is invalid');
  changedExtraCarrierRedeem[extraBodyOffset] = 0x6a;
  replaceTemplateBlockRedeem(changedExtraHelperInputs, extraCarrierInput,
    changedExtraCarrierRedeem);
  assertTemplateMutationRejected(
    'changed extra template helper byte',
    changedExtraHelperInputs,
    extraMutationTarget,
  );
  templateFactoringMutationInputs.push({
    name: 'changed-template-extra-helper-byte',
    inputs: changedExtraHelperInputs,
  });

  const commonLoaderLayout = templateLoaderLayout(
    templateCommonCarrier,
    templateCommonStart,
    templateCommonEnd,
    TEMPLATE_COMMON_FUNCTION_ID,
  );
  const extraLoaderLayout = templateLoaderLayout(
    templateExtraCarrier,
    templateExtraStart,
    templateExtraEnd,
    TEMPLATE_EXTRA_FUNCTION_ID,
  );
  const commonDefinitionBytes = templateCommonBodyPush.length +
    pushVmNumber(TEMPLATE_COMMON_FUNCTION_ID).length + 1;
  const extraLoaderOffset = templateInputs[extraMutationTarget].redeem.length -
    templateCommonCarrier.representativeRedeem.length + commonDefinitionBytes;
  [
    {
      name: 'changed-template-common-slice-start',
      layout: commonLoaderLayout,
      targetInput: commonMutationTarget,
      loaderOffset: 0,
      mutationOffset: commonLoaderLayout.startOffset,
      before: commonLoaderLayout.startPush,
      after: pushVmNumber(templateCommonStart + 1),
    },
    {
      name: 'changed-template-common-slice-end',
      layout: commonLoaderLayout,
      targetInput: commonMutationTarget,
      loaderOffset: 0,
      mutationOffset: commonLoaderLayout.endOffset,
      before: commonLoaderLayout.endPush,
      after: pushVmNumber(templateCommonEnd - 1),
    },
    {
      name: 'changed-template-common-function-id',
      layout: commonLoaderLayout,
      targetInput: commonMutationTarget,
      loaderOffset: 0,
      mutationOffset: commonLoaderLayout.functionIdOffset,
      before: commonLoaderLayout.functionIdPush,
      after: pushVmNumber(TEMPLATE_COMMON_FUNCTION_ID + 1),
    },
    {
      name: 'changed-template-common-loader-source-input',
      layout: commonLoaderLayout,
      targetInput: commonMutationTarget,
      loaderOffset: 0,
      mutationOffset: 0,
      before: commonLoaderLayout.sourceInputPush,
      after: pushVmNumber(commonCarrierInput + 1),
    },
    {
      name: 'changed-template-extra-slice-start',
      layout: extraLoaderLayout,
      targetInput: extraMutationTarget,
      loaderOffset: extraLoaderOffset,
      mutationOffset: extraLoaderLayout.startOffset,
      before: extraLoaderLayout.startPush,
      after: pushVmNumber(templateExtraStart + 1),
    },
    {
      name: 'changed-template-extra-slice-end',
      layout: extraLoaderLayout,
      targetInput: extraMutationTarget,
      loaderOffset: extraLoaderOffset,
      mutationOffset: extraLoaderLayout.endOffset,
      before: extraLoaderLayout.endPush,
      after: pushVmNumber(templateExtraEnd - 1),
    },
    {
      name: 'changed-template-extra-function-id',
      layout: extraLoaderLayout,
      targetInput: extraMutationTarget,
      loaderOffset: extraLoaderOffset,
      mutationOffset: extraLoaderLayout.functionIdOffset,
      before: extraLoaderLayout.functionIdPush,
      after: pushVmNumber(TEMPLATE_EXTRA_FUNCTION_ID + 1),
    },
    {
      name: 'changed-template-extra-loader-source-input',
      layout: extraLoaderLayout,
      targetInput: extraMutationTarget,
      loaderOffset: extraLoaderOffset,
      mutationOffset: 0,
      before: extraLoaderLayout.sourceInputPush,
      after: pushVmNumber(extraCarrierInput - 1),
    },
  ].forEach((fixture) => {
    const changed = cloneTemplateInputs();
    const changedLoader = mutateTemplateLoader(
      fixture.layout,
      fixture.mutationOffset,
      fixture.before,
      fixture.after,
      fixture.name,
    );
    const originalRedeem = changed[fixture.targetInput].redeem;
    assert(equalBytes(originalRedeem.slice(
      fixture.loaderOffset,
      fixture.loaderOffset + fixture.layout.loader.length,
    ), fixture.layout.loader), `${fixture.name} loader moved in its redeem`);
    replaceTemplateBlockRedeem(changed, fixture.targetInput, concat(
      originalRedeem.slice(0, fixture.loaderOffset),
      changedLoader,
      originalRedeem.slice(fixture.loaderOffset + fixture.layout.loader.length),
    ));
    assertTemplateMutationRejected(fixture.name, changed, fixture.targetInput);
    templateFactoringMutationInputs.push({ name: fixture.name, inputs: changed });
  });

  const fullChangedSiblingLockingInputs = cloneTemplateInputs();
  fullChangedSiblingLockingInputs[1].locking[
    fullChangedSiblingLockingInputs[1].locking.length - 1
  ] ^= 1;
  assert(!evaluateInput(fullChangedSiblingLockingInputs, 0, consensusVm).accepted &&
    !evaluateInput(fullChangedSiblingLockingInputs, 0, standardVm).accepted,
  'changed fixed-width sibling locking passed the coordinator under a strict VM');

  const fullChangedSiblingLockingLengthInputs = cloneTemplateInputs();
  fullChangedSiblingLockingLengthInputs[1].locking =
    fullChangedSiblingLockingLengthInputs[1].locking.slice(0, -1);
  assert(!evaluateInput(fullChangedSiblingLockingLengthInputs, 0, consensusVm).accepted &&
    !evaluateInput(fullChangedSiblingLockingLengthInputs, 0, standardVm).accepted,
  'changed fixed-width sibling locking length passed the coordinator under a strict VM');

  const fullChangedPathInputs = cloneTemplateInputs();
  const fullChangedPathInputIndex = regularPicCarrierBlocks[12 >> 1] + 1;
  const fullChangedPathPayload = Uint8Array.from(
    fullChangedPathInputs[fullChangedPathInputIndex].payload,
  );
  fullChangedPathPayload[
    PIC_RECORD_REGION_OFFSET + PIC_FACTOR_BYTES + 7 * 32
  ] ^= 1;
  fullChangedPathInputs[fullChangedPathInputIndex].payload = fullChangedPathPayload;
  fullChangedPathInputs[fullChangedPathInputIndex].unlocking = makeTemplateBlockUnlocking(
    fullChangedPathPayload,
    fullChangedPathInputs[fullChangedPathInputIndex].evaluation,
    fullChangedPathInputs[fullChangedPathInputIndex].quotientChunk,
    fullChangedPathInputs[fullChangedPathInputIndex].redeem,
  );

  const setRecomputedStatement = (changedInputs, changedStatement) => {
    assert(changedStatement.length === statementBytes.length &&
      !equalBytes(changedStatement, statementBytes), 'changed statement is not distinct and canonical');
    const changedRoot = treeFor([changedStatement, ...blockPayloads]);
    const changedBeta = sha256(frame(
      'beta',
      concat(u32(blockPayloads.length), changedRoot),
    ));
    const changedAlpha = sha256(frame('alpha', concat(changedRoot, quotientRoot)));
    const changedHeader = concat(changedRoot, quotientRoot, changedBeta, changedAlpha);
    assert(digestToUnsignedLe(changedBeta) !== 0n && changedHeader.length === 128 &&
      !equalBytes(changedHeader, transcriptHeader), 'changed statement transcript is invalid');
    changedInputs[0].unlocking = concat(
      encodeDataPush(changedHeader),
      encodeDataPush(changedStatement),
      encodeDataPush(changedInputs[0].redeem),
    );
  };

  const fullChangedScalarInputs = cloneTemplateInputs();
  const fullChangedScalarStatement = Uint8Array.from(statementBytes);
  const publicMutationMask = Array.from(
    { length: 8 },
    (_, index) => 1n << BigInt(96 + index),
  ).find((mask) => (activePublicInputs[0] ^ mask) < SCALAR_ORDER);
  assert(publicMutationMask !== undefined, 'no canonical window-12 public-input change exists');
  fullChangedScalarStatement.set(
    serializeUnsignedLe(activePublicInputs[0] ^ publicMutationMask, 32),
    public0Offset,
  );
  setRecomputedStatement(fullChangedScalarInputs, fullChangedScalarStatement);
  assert(evaluateInput(fullChangedScalarInputs, 0, consensusVm).accepted &&
    evaluateInput(fullChangedScalarInputs, 0, standardVm).accepted,
  'canonical changed public input did not pass the coordinator');
  assert(!evaluateInput(fullChangedScalarInputs, 3, consensusVm).accepted &&
    !evaluateInput(fullChangedScalarInputs, 3, standardVm).accepted,
  'canonical changed public input passed its PIC host');

  const fullChangedProofInputs = cloneTemplateInputs();
  const fullChangedProofStatement = Uint8Array.from(statementBytes);
  const changedAPoint = pairs[0].P.is0() ? G1.BASE : pairs[0].P.negate();
  const changedAUnit = unitG1(changedAPoint);
  assert((changedAUnit.u !== units[0] || changedAUnit.v !== units[1]) &&
    unitCurveHolds(changedAUnit.u, changedAUnit.v), 'alternate A unit is not valid and distinct');
  [['p0u', changedAUnit.u], ['p0v', changedAUnit.v]].forEach(([name, value]) => {
    const layout = statementLayout[statementIndex[name]];
    fullChangedProofStatement.set(serializeUnsignedLe(value, layout.width), layout.offset);
  });
  setRecomputedStatement(fullChangedProofInputs, fullChangedProofStatement);
  assert(evaluateInput(fullChangedProofInputs, 0, consensusVm).accepted &&
    evaluateInput(fullChangedProofInputs, 0, standardVm).accepted,
  'canonical changed proof A did not pass the coordinator');
  assert(!evaluateInput(fullChangedProofInputs, 1, consensusVm).accepted &&
    !evaluateInput(fullChangedProofInputs, 1, standardVm).accepted,
  'canonical changed proof A passed the relation verifier');

  const fullChangedProofBInputs = cloneTemplateInputs();
  const fullChangedProofBStatement = Uint8Array.from(statementBytes);
  const changedProofB = effectiveProof.b.negate().toAffine();
  assert(changedProofB.y.c0 !== effectiveProofB.y.c0 ||
    changedProofB.y.c1 !== effectiveProofB.y.c1, 'alternate B point is not distinct');
  [
    ['effectiveBxa', changedProofB.x.c0],
    ['effectiveBxb', changedProofB.x.c1],
    ['effectiveBya', changedProofB.y.c0],
    ['effectiveByb', changedProofB.y.c1],
  ].forEach(([name, value]) => {
    const layout = statementLayout[statementIndex[name]];
    fullChangedProofBStatement.set(serializeUnsignedLe(value, layout.width), layout.offset);
  });
  setRecomputedStatement(fullChangedProofBInputs, fullChangedProofBStatement);
  if (bIdentity) {
    assert(!evaluateInput(fullChangedProofBInputs, 0, consensusVm).accepted &&
      !evaluateInput(fullChangedProofBInputs, 0, standardVm).accepted,
    'changed identity substitute B passed the coordinator');
  } else {
    assert(evaluateInput(fullChangedProofBInputs, 0, consensusVm).accepted &&
      evaluateInput(fullChangedProofBInputs, 0, standardVm).accepted,
    'canonical changed proof B did not pass the coordinator');
    assert(!evaluateInput(fullChangedProofBInputs, 1, consensusVm).accepted &&
      !evaluateInput(fullChangedProofBInputs, 1, standardVm).accepted,
    'canonical changed proof B passed the relation verifier');
  }

  const fullChangedBIdentityInputs = cloneTemplateInputs();
  const fullChangedBIdentityStatement = Uint8Array.from(statementBytes);
  fullChangedBIdentityStatement[statementLayout[statementIndex.Bidentity].offset] ^= 1;
  setRecomputedStatement(fullChangedBIdentityInputs, fullChangedBIdentityStatement);

  const fullChangedProofCInputs = cloneTemplateInputs();
  const fullChangedProofCStatement = Uint8Array.from(statementBytes);
  const changedCPoint = pairs[3].P.is0() ? G1.BASE : pairs[3].P.negate();
  const changedCUnit = unitG1(changedCPoint);
  assert((changedCUnit.u !== units.at(-2) || changedCUnit.v !== units.at(-1)) &&
    unitCurveHolds(changedCUnit.u, changedCUnit.v), 'alternate C unit is not valid and distinct');
  [['p3u', changedCUnit.u], ['p3v', changedCUnit.v]].forEach(([name, value]) => {
    const layout = statementLayout[statementIndex[name]];
    fullChangedProofCStatement.set(serializeUnsignedLe(value, layout.width), layout.offset);
  });
  setRecomputedStatement(fullChangedProofCInputs, fullChangedProofCStatement);
  assert(evaluateInput(fullChangedProofCInputs, 0, consensusVm).accepted &&
    evaluateInput(fullChangedProofCInputs, 0, standardVm).accepted,
  'canonical changed proof C did not pass the coordinator');
  assert(!evaluateInput(fullChangedProofCInputs, 1, consensusVm).accepted &&
    !evaluateInput(fullChangedProofCInputs, 1, standardVm).accepted,
  'canonical changed proof C passed the relation verifier');

  const fullChangedEvaluationInputs = cloneTemplateInputs();
  const fullEvaluationBefore = Uint8Array.from(fullChangedEvaluationInputs[8].evaluation);
  const fullChangedEvaluation = Uint8Array.from(fullEvaluationBefore);
  fullChangedEvaluation[0] ^= 1;
  assert(!equalBytes(fullEvaluationBefore, fullChangedEvaluation),
    'full evaluation recurrence mutation was a no-op');
  fullChangedEvaluationInputs[8].evaluation = fullChangedEvaluation;
  fullChangedEvaluationInputs[8].unlocking = makeTemplateBlockUnlocking(
    fullChangedEvaluationInputs[8].payload,
    fullChangedEvaluation,
    fullChangedEvaluationInputs[8].quotientChunk,
    fullChangedEvaluationInputs[8].redeem,
  );

  const fullChangedSplitUInputs = cloneTemplateInputs();
  const fullChangedSplitUPayload = Uint8Array.from(fullChangedSplitUInputs[1].payload);
  fullChangedSplitUPayload[blockRecords[0].layout.splitU] ^= 1;
  fullChangedSplitUInputs[1].payload = fullChangedSplitUPayload;
  fullChangedSplitUInputs[1].unlocking = makeTemplateBlockUnlocking(
    fullChangedSplitUPayload,
    fullChangedSplitUInputs[1].evaluation,
    fullChangedSplitUInputs[1].quotientChunk,
    fullChangedSplitUInputs[1].redeem,
  );
  assert(!evaluateInput(fullChangedSplitUInputs, 1, consensusVm).accepted &&
    !evaluateInput(fullChangedSplitUInputs, 1, standardVm).accepted,
  'changed split U passed the owning block under a strict VM');
  assert(!evaluateInput(fullChangedSplitUInputs, 0, consensusVm).accepted &&
    !evaluateInput(fullChangedSplitUInputs, 0, standardVm).accepted,
  'changed split payload passed the committed-root input under a strict VM');

  const fullChangedSplitFlagInputs = cloneTemplateInputs();
  const fullChangedSplitFlagPayload = Uint8Array.from(fullChangedSplitFlagInputs[1].payload);
  fullChangedSplitFlagPayload[blockRecords[0].layout.splitFlag] = 1;
  fullChangedSplitFlagInputs[1].payload = fullChangedSplitFlagPayload;
  fullChangedSplitFlagInputs[1].unlocking = makeTemplateBlockUnlocking(
    fullChangedSplitFlagPayload,
    fullChangedSplitFlagInputs[1].evaluation,
    fullChangedSplitFlagInputs[1].quotientChunk,
    fullChangedSplitFlagInputs[1].redeem,
  );
  assert(!evaluateInput(fullChangedSplitFlagInputs, 1, consensusVm).accepted &&
    !evaluateInput(fullChangedSplitFlagInputs, 1, standardVm).accepted,
  'nonzero chart-1 split U passed the owning block under a strict VM');

  const fullInvalidSplitFlagInputs = cloneTemplateInputs();
  const fullInvalidSplitFlagPayload = Uint8Array.from(fullInvalidSplitFlagInputs[1].payload);
  fullInvalidSplitFlagPayload[blockRecords[0].layout.splitFlag] = 2;
  fullInvalidSplitFlagInputs[1].payload = fullInvalidSplitFlagPayload;
  fullInvalidSplitFlagInputs[1].unlocking = makeTemplateBlockUnlocking(
    fullInvalidSplitFlagPayload,
    fullInvalidSplitFlagInputs[1].evaluation,
    fullInvalidSplitFlagInputs[1].quotientChunk,
    fullInvalidSplitFlagInputs[1].redeem,
  );
  assert(!evaluateInput(fullInvalidSplitFlagInputs, 1, consensusVm).accepted &&
    !evaluateInput(fullInvalidSplitFlagInputs, 1, standardVm).accepted,
  'out-of-domain split flag passed the owning block under a strict VM');

  const fullChangedSecondSplitUInputs = cloneTemplateInputs();
  const fullChangedSecondSplitUPayload = Uint8Array.from(
    fullChangedSecondSplitUInputs[16].payload,
  );
  fullChangedSecondSplitUPayload[blockRecords[15].layout.splitU] ^= 1;
  fullChangedSecondSplitUInputs[16].payload = fullChangedSecondSplitUPayload;
  fullChangedSecondSplitUInputs[16].unlocking = makeTemplateBlockUnlocking(
    fullChangedSecondSplitUPayload,
    fullChangedSecondSplitUInputs[16].evaluation,
    fullChangedSecondSplitUInputs[16].quotientChunk,
    fullChangedSecondSplitUInputs[16].redeem,
  );
  assert(!evaluateInput(fullChangedSecondSplitUInputs, 16, consensusVm).accepted &&
    !evaluateInput(fullChangedSecondSplitUInputs, 16, standardVm).accepted,
  'changed block-15 split U passed the owning block under a strict VM');
  assert(!evaluateInput(fullChangedSecondSplitUInputs, 0, consensusVm).accepted &&
    !evaluateInput(fullChangedSecondSplitUInputs, 0, standardVm).accepted,
  'changed block-15 split payload passed the committed-root input under a strict VM');

  const fullChangedSecondSplitFlagInputs = cloneTemplateInputs();
  const fullChangedSecondSplitFlagPayload = Uint8Array.from(
    fullChangedSecondSplitFlagInputs[16].payload,
  );
  fullChangedSecondSplitFlagPayload[blockRecords[15].layout.splitFlag] = 1;
  fullChangedSecondSplitFlagInputs[16].payload = fullChangedSecondSplitFlagPayload;
  fullChangedSecondSplitFlagInputs[16].unlocking = makeTemplateBlockUnlocking(
    fullChangedSecondSplitFlagPayload,
    fullChangedSecondSplitFlagInputs[16].evaluation,
    fullChangedSecondSplitFlagInputs[16].quotientChunk,
    fullChangedSecondSplitFlagInputs[16].redeem,
  );
  assert(!evaluateInput(fullChangedSecondSplitFlagInputs, 16, consensusVm).accepted &&
    !evaluateInput(fullChangedSecondSplitFlagInputs, 16, standardVm).accepted,
  'nonzero chart-1 block-15 split U passed the owning block under a strict VM');

  const fullInvalidSecondSplitFlagInputs = cloneTemplateInputs();
  const fullInvalidSecondSplitFlagPayload = Uint8Array.from(
    fullInvalidSecondSplitFlagInputs[16].payload,
  );
  fullInvalidSecondSplitFlagPayload[blockRecords[15].layout.splitFlag] = 2;
  fullInvalidSecondSplitFlagInputs[16].payload = fullInvalidSecondSplitFlagPayload;
  fullInvalidSecondSplitFlagInputs[16].unlocking = makeTemplateBlockUnlocking(
    fullInvalidSecondSplitFlagPayload,
    fullInvalidSecondSplitFlagInputs[16].evaluation,
    fullInvalidSecondSplitFlagInputs[16].quotientChunk,
    fullInvalidSecondSplitFlagInputs[16].redeem,
  );
  assert(!evaluateInput(fullInvalidSecondSplitFlagInputs, 16, consensusVm).accepted &&
    !evaluateInput(fullInvalidSecondSplitFlagInputs, 16, standardVm).accepted,
  'out-of-domain block-15 split flag passed the owning block under a strict VM');

  const fullChangedQuotientInputs = cloneTemplateInputs();
  const quotientInputIndex = FUSED_QUOTIENT_INPUT_INDEX;
  const quotientTailInputIndex = FUSED_QUOTIENT_TAIL_INPUT_INDEX;
  assert(fullChangedQuotientInputs[quotientInputIndex].quotientChunkRole === 'head' &&
    fullChangedQuotientInputs[quotientTailInputIndex].quotientChunkRole === 'tail',
  'fused quotient physical chunk roles changed');
  const fullChangedQuotientHead = Uint8Array.from(
    fullChangedQuotientInputs[quotientInputIndex].quotientChunk,
  );
  fullChangedQuotientHead[fullChangedQuotientHead.length - 1] ^= 1;
  fullChangedQuotientInputs[quotientInputIndex].quotientChunk = fullChangedQuotientHead;
  fullChangedQuotientInputs[quotientInputIndex].unlocking = makeTemplateBlockUnlocking(
    fullChangedQuotientInputs[quotientInputIndex].payload,
    fullChangedQuotientInputs[quotientInputIndex].evaluation,
    fullChangedQuotientHead,
    fullChangedQuotientInputs[quotientInputIndex].redeem,
  );
  assert(!evaluateInput(fullChangedQuotientInputs, quotientInputIndex, consensusVm).accepted &&
    !evaluateInput(fullChangedQuotientInputs, quotientInputIndex, standardVm).accepted,
  'changed quotient passed its owning input under a strict VM');

  const fullChangedQuotientRootInputs = cloneTemplateInputs();
  fullChangedQuotientRootInputs[quotientInputIndex].quotientChunk = fullChangedQuotientHead;
  fullChangedQuotientRootInputs[quotientInputIndex].unlocking = makeTemplateBlockUnlocking(
    fullChangedQuotientRootInputs[quotientInputIndex].payload,
    fullChangedQuotientRootInputs[quotientInputIndex].evaluation,
    fullChangedQuotientHead,
    fullChangedQuotientRootInputs[quotientInputIndex].redeem,
  );
  const changedLogicalQuotient = concat(
    fullChangedQuotientHead,
    fullChangedQuotientRootInputs[quotientTailInputIndex].quotientChunk,
  );
  const changedQuotientRoot = treeFor(
    [changedLogicalQuotient],
    [quotientBytes.length],
  );
  const oldAlphaHeader = concat(commitmentRoot, changedQuotientRoot, betaDigest, alphaDigest);
  fullChangedQuotientRootInputs[0].unlocking = concat(
    encodeDataPush(oldAlphaHeader),
    encodeDataPush(statementBytes),
    encodeDataPush(fullChangedQuotientRootInputs[0].redeem),
  );
  assert(!evaluateInput(fullChangedQuotientRootInputs, 0, consensusVm).accepted &&
    !evaluateInput(fullChangedQuotientRootInputs, 0, standardVm).accepted,
  'changed quotient root with old alpha passed the coordinator under a strict VM');

  const fullChangedQuotientOrderInputs = cloneTemplateInputs();
  fullChangedQuotientOrderInputs[quotientInputIndex].unlocking = concat(
    encodeDataPush(fullChangedQuotientOrderInputs[quotientInputIndex].payload),
    encodeDataPush(fullChangedQuotientOrderInputs[quotientInputIndex].quotientChunk),
    encodeDataPush(fullChangedQuotientOrderInputs[quotientInputIndex].evaluation),
    encodeDataPush(fullChangedQuotientOrderInputs[quotientInputIndex].redeem),
  );
  assert(!evaluateInput(fullChangedQuotientOrderInputs, quotientInputIndex, consensusVm).accepted &&
    !evaluateInput(fullChangedQuotientOrderInputs, quotientInputIndex, standardVm).accepted,
  'changed fused quotient push order passed its owning input under a strict VM');

  const fullTruncatedQuotientInputs = cloneTemplateInputs();
  const truncatedQuotientHead = fullTruncatedQuotientInputs[
    quotientInputIndex
  ].quotientChunk.slice(0, -1);
  fullTruncatedQuotientInputs[quotientInputIndex].quotientChunk = truncatedQuotientHead;
  fullTruncatedQuotientInputs[quotientInputIndex].unlocking = makeTemplateBlockUnlocking(
    fullTruncatedQuotientInputs[quotientInputIndex].payload,
    fullTruncatedQuotientInputs[quotientInputIndex].evaluation,
    truncatedQuotientHead,
    fullTruncatedQuotientInputs[quotientInputIndex].redeem,
  );
  assert(!evaluateInput(fullTruncatedQuotientInputs, quotientInputIndex, consensusVm).accepted &&
    !evaluateInput(fullTruncatedQuotientInputs, quotientInputIndex, standardVm).accepted,
  'truncated fused quotient payload passed its owning input under a strict VM');

  const fullChangedQuotientTailInputs = cloneTemplateInputs();
  const changedQuotientTail = Uint8Array.from(
    fullChangedQuotientTailInputs[quotientTailInputIndex].quotientChunk,
  );
  changedQuotientTail[changedQuotientTail.length - 1] ^= 1;
  fullChangedQuotientTailInputs[quotientTailInputIndex].quotientChunk = changedQuotientTail;
  fullChangedQuotientTailInputs[quotientTailInputIndex].unlocking = makeTemplateBlockUnlocking(
    fullChangedQuotientTailInputs[quotientTailInputIndex].payload,
    fullChangedQuotientTailInputs[quotientTailInputIndex].evaluation,
    changedQuotientTail,
    fullChangedQuotientTailInputs[quotientTailInputIndex].redeem,
  );
  assert(!evaluateInput(fullChangedQuotientTailInputs, quotientInputIndex, consensusVm).accepted &&
    !evaluateInput(fullChangedQuotientTailInputs, quotientInputIndex, standardVm).accepted &&
    !evaluateInput(fullChangedQuotientTailInputs, 0, consensusVm).accepted &&
    !evaluateInput(fullChangedQuotientTailInputs, 0, standardVm).accepted,
  'changed quotient tail passed a strict consumer');

  const fullTruncatedQuotientTailInputs = cloneTemplateInputs();
  const truncatedQuotientTail = fullTruncatedQuotientTailInputs[
    quotientTailInputIndex
  ].quotientChunk.slice(0, -1);
  fullTruncatedQuotientTailInputs[quotientTailInputIndex].quotientChunk =
    truncatedQuotientTail;
  fullTruncatedQuotientTailInputs[quotientTailInputIndex].unlocking =
    makeTemplateBlockUnlocking(
      fullTruncatedQuotientTailInputs[quotientTailInputIndex].payload,
      fullTruncatedQuotientTailInputs[quotientTailInputIndex].evaluation,
      truncatedQuotientTail,
      fullTruncatedQuotientTailInputs[quotientTailInputIndex].redeem,
    );
  assert(!evaluateInput(
    fullTruncatedQuotientTailInputs,
    quotientTailInputIndex,
    consensusVm,
  ).accepted && !evaluateInput(
    fullTruncatedQuotientTailInputs,
    quotientTailInputIndex,
    standardVm,
  ).accepted, 'truncated quotient tail passed its owning input under a strict VM');

  const fullSwappedQuotientChunksInputs = cloneTemplateInputs();
  const originalHead = fullSwappedQuotientChunksInputs[quotientInputIndex].quotientChunk;
  const originalTail = fullSwappedQuotientChunksInputs[quotientTailInputIndex].quotientChunk;
  fullSwappedQuotientChunksInputs[quotientInputIndex].quotientChunk = originalTail;
  fullSwappedQuotientChunksInputs[quotientTailInputIndex].quotientChunk = originalHead;
  fullSwappedQuotientChunksInputs[quotientInputIndex].unlocking = makeTemplateBlockUnlocking(
    fullSwappedQuotientChunksInputs[quotientInputIndex].payload,
    fullSwappedQuotientChunksInputs[quotientInputIndex].evaluation,
    originalTail,
    fullSwappedQuotientChunksInputs[quotientInputIndex].redeem,
  );
  fullSwappedQuotientChunksInputs[quotientTailInputIndex].unlocking =
    makeTemplateBlockUnlocking(
      fullSwappedQuotientChunksInputs[quotientTailInputIndex].payload,
      fullSwappedQuotientChunksInputs[quotientTailInputIndex].evaluation,
      originalHead,
      fullSwappedQuotientChunksInputs[quotientTailInputIndex].redeem,
    );
  assert(!evaluateInput(fullSwappedQuotientChunksInputs, quotientInputIndex, consensusVm).accepted &&
    !evaluateInput(fullSwappedQuotientChunksInputs, quotientInputIndex, standardVm).accepted &&
    !evaluateInput(
      fullSwappedQuotientChunksInputs,
      quotientTailInputIndex,
      consensusVm,
    ).accepted && !evaluateInput(
      fullSwappedQuotientChunksInputs,
      quotientTailInputIndex,
      standardVm,
    ).accepted, 'swapped quotient chunks passed a strict owning input');

  const fullShiftedQuotientBoundaryInputs = cloneTemplateInputs();
  const boundaryHead = fullShiftedQuotientBoundaryInputs[quotientInputIndex].quotientChunk;
  const boundaryTail = fullShiftedQuotientBoundaryInputs[quotientTailInputIndex].quotientChunk;
  const shiftedHead = boundaryHead.slice(0, -1);
  const shiftedTail = concat(boundaryHead.slice(-1), boundaryTail);
  assert(equalBytes(concat(shiftedHead, shiftedTail), concat(boundaryHead, boundaryTail)),
    'cross-carrier boundary mutation changed the logical quotient');
  fullShiftedQuotientBoundaryInputs[quotientInputIndex].quotientChunk = shiftedHead;
  fullShiftedQuotientBoundaryInputs[quotientTailInputIndex].quotientChunk = shiftedTail;
  fullShiftedQuotientBoundaryInputs[quotientInputIndex].unlocking = makeTemplateBlockUnlocking(
    fullShiftedQuotientBoundaryInputs[quotientInputIndex].payload,
    fullShiftedQuotientBoundaryInputs[quotientInputIndex].evaluation,
    shiftedHead,
    fullShiftedQuotientBoundaryInputs[quotientInputIndex].redeem,
  );
  fullShiftedQuotientBoundaryInputs[quotientTailInputIndex].unlocking =
    makeTemplateBlockUnlocking(
      fullShiftedQuotientBoundaryInputs[quotientTailInputIndex].payload,
      fullShiftedQuotientBoundaryInputs[quotientTailInputIndex].evaluation,
      shiftedTail,
      fullShiftedQuotientBoundaryInputs[quotientTailInputIndex].redeem,
    );
  assert(!evaluateInput(
    fullShiftedQuotientBoundaryInputs,
    quotientInputIndex,
    consensusVm,
  ).accepted && !evaluateInput(
    fullShiftedQuotientBoundaryInputs,
    quotientInputIndex,
    standardVm,
  ).accepted && !evaluateInput(
    fullShiftedQuotientBoundaryInputs,
    quotientTailInputIndex,
    consensusVm,
  ).accepted && !evaluateInput(
    fullShiftedQuotientBoundaryInputs,
    quotientTailInputIndex,
    standardVm,
  ).accepted, 'shifted quotient boundary passed a strict owning input');
  const fullRejectionFixtures = [
    ...templateFactoringMutationInputs.map(({ name, inputs: changed }) =>
      strictRejection(name, changed)),
    strictRejection('changed-fixed-width-sibling-locking', fullChangedSiblingLockingInputs),
    strictRejection(
      'changed-fixed-width-sibling-locking-length',
      fullChangedSiblingLockingLengthInputs,
    ),
    strictRejection('changed-authenticated-PIC-path', fullChangedPathInputs),
    strictRejection('changed-public-input', fullChangedScalarInputs),
    strictRejection('changed-proof-A-unit', fullChangedProofInputs),
    strictRejection('changed-proof-B-coordinate', fullChangedProofBInputs),
    strictRejection('changed-B-identity-flag', fullChangedBIdentityInputs),
    strictRejection('changed-proof-C-unit', fullChangedProofCInputs),
    strictRejection('changed-evaluation-recurrence', fullChangedEvaluationInputs),
    strictRejection('changed-split-payload-old-root', fullChangedSplitUInputs),
    strictRejection('nonzero-chart-1-split-U', fullChangedSplitFlagInputs),
    strictRejection('out-of-domain-split-flag', fullInvalidSplitFlagInputs),
    strictRejection('changed-block15-split-payload-old-root', fullChangedSecondSplitUInputs),
    strictRejection('nonzero-chart-1-block15-split-U', fullChangedSecondSplitFlagInputs),
    strictRejection('out-of-domain-block15-split-flag', fullInvalidSecondSplitFlagInputs),
    strictRejection('changed-q132-coefficient-old-root', fullChangedQuotientInputs),
    strictRejection('changed-q132-root-old-alpha', fullChangedQuotientRootInputs),
    strictRejection('changed-q132-push-order', fullChangedQuotientOrderInputs),
    strictRejection('truncated-q132-payload', fullTruncatedQuotientInputs),
    strictRejection('changed-q132-tail-chunk-old-root', fullChangedQuotientTailInputs),
    strictRejection('truncated-q132-tail-chunk', fullTruncatedQuotientTailInputs),
    strictRejection('swapped-q132-physical-chunks', fullSwappedQuotientChunksInputs),
    strictRejection('cross-carrier-q132-boundary-shift', fullShiftedQuotientBoundaryInputs),
  ];
  const templateTransactionBytes = encodeTransactionBch(templateValidData.transaction);

  const metricKeys = [
    'evaluatedInstructionCount',
    'hashDigestIterations',
    'arithmeticCost',
    'stackPushedBytes',
    'definedFunctions',
  ];
  const totalMetrics = (outcomes) => Object.fromEntries(metricKeys.map((key) => [
    key,
    sum(outcomes, (outcome) => outcome.metrics[key]),
  ]));
  const baselineMetrics = totalMetrics(standardOutcomes);
  const templateMetrics = totalMetrics(templateStandardOutcomes);
  const metricDelta = Object.fromEntries(metricKeys.map((key) => [
    key,
    templateMetrics[key] - baselineMetrics[key],
  ]));
  const operationDeltaBreakdown = {
    baseInstructions: metricDelta.evaluatedInstructionCount * 100,
    standardHashing: metricDelta.hashDigestIterations * 192,
    arithmetic: metricDelta.arithmeticCost,
    pushedBytes: metricDelta.stackPushedBytes,
  };
  writeFileSync(1, `${JSON.stringify({
    construction: 'atomic-validation-hoist-plus-five-exact-unrolled-classes',
    fixture: activeFixtureName,
    cacheFixture: activeFixture.cacheName,
    publicInputs: activePublicInputs.map(String),
    proofScalars: Object.fromEntries(Object.entries(activeFixture.scalars).map(
      ([name, value]) => [name, value.toString()],
    )),
    identities: {
      A: semanticProof.a.is0(),
      B: bIdentity,
      C: semanticProof.c.is0(),
      msmContribution: pairs[2].P.is0(),
    },
    inverseRelations: INVERSE_RELATIONS,
    densityLimitsEnforced,
    completeVerifier: true,
    omitted: [],
    fixedWidthGraphCertificate: {
      siblingCount: templateSiblingLockings.length,
      siblingWidthBytes: 35,
      digestPreimageBytes: sum(templateSiblingLockings, (locking) => locking.length),
      siblingLockingDigest: hex(templateSiblingLockingDigest),
      encoding: 'concatenated complete 35-byte locking bytecodes in input order',
      exactLengthChecksRetained: true,
    },
    q132SplitCertificate: {
      splitBlocks: SPLIT_RELATION_BLOCKS,
      splits: SPLIT_RELATION_BLOCKS.map((blockIndex) => ({
        blockIndex,
        splitAfterOperations: blockRecords[blockIndex].splitRelation.operationCount,
        splitPayloadOffset: blockRecords[blockIndex].layout.splitU,
        splitPayloadBytes: 6 * W + 1,
        splitFlagOffset: blockRecords[blockIndex].layout.splitFlag,
      })),
      totalSplitPayloadBytes: SPLIT_RELATION_BLOCKS.length * (6 * W + 1),
      canonicalChartRule: 'flag 0 encodes 1+u*W; flag 1 requires all six u limbs equal zero',
      selectedScaleNonzeroProof:
        'each split begins with a nonzero canonical representative and applies only field squares and nonzero 1+W*t factors; if a selected scale were zero, the canonical cross identity would force both projective components to zero',
      preBetaBinding: {
        commitmentRoot: hex(commitmentRoot),
        beta: hex(betaDigest),
        splitBindings: [
          {
            blockIndex: 0,
            commitmentPayload: 'blockPayloads[0], including split U and flag',
            changedSplitRoot: hex(splitCommitmentMutationRoot),
            changedSplitBeta: hex(splitCommitmentMutationBeta),
          },
          {
            blockIndex: 15,
            commitmentPayload: 'blockPayloads[15], including split U and flag',
            changedSplitRoot: hex(secondSplitCommitmentMutationRoot),
            changedSplitBeta: hex(secondSplitCommitmentMutationBeta),
          },
        ],
      },
      relationExponents: relationRecords.map((relation, exponent) => ({
        exponent,
        blockIndex: relation.blockIndex,
        kind: relation.kind,
      })),
      exponentDomain: [0, relationRecords.length - 1],
      exponentsContiguous: expectedRelationExponent === relationRecords.length,
      universalDegreeSegments,
      secondSplitBoundaryScan,
      degreeOptimalSecondSplit,
      terminalDegreeCeiling,
      universalMaximumRelationDegree,
      universalMaximumQuotientCoefficients,
      quotientBytes: quotientBytes.length,
      preAlphaBinding: {
        quotientRoot: hex(quotientRoot),
        changedQuotientRoot: hex(quotientCommitmentMutationRoot),
        alpha: hex(alphaDigest),
        changedQuotientAlpha: hex(quotientCommitmentMutationAlpha),
      },
      randomOracleBound: {
        nonzeroBetaDomainSize: '2^256-1',
        betaCancellationDegree: relationRecords.length - 1,
        alphaIdentityDegree: universalMaximumRelationDegree,
        numerator: relationRecords.length - 1 + universalMaximumRelationDegree,
        bound: `${relationRecords.length - 1 + universalMaximumRelationDegree}/(2^256-1)`,
      },
      postAlphaWitnessRule:
        'one logical quotient leaf is split at a fixed byte boundary; block 4 concatenates the exact head and tail and performs Horner directly over every root-committed coefficient',
    },
    quotientFusion: {
      inputIndex: FUSED_QUOTIENT_INPUT_INDEX,
      blockIndex: FUSED_QUOTIENT_BLOCK_INDEX,
      totalInputCount: TEMPLATE_TOTAL_INPUTS,
      siblingCount: templateSiblingLockings.length,
      pushIndex: 2,
      pushOrder: 'each physical carrier pushes block payload || block evaluation || its fixed quotient chunk || redeem',
      quotientPayloadBytes: quotientPayloads[0].length,
      quotientCoefficientCount: QUOTIENT_COEFFICIENTS,
      logicalLeafCount: 1,
      physicalChunkCount: 2,
      logicalConcatenationOrder: 'block-4 head || block-15 tail',
      exactPhysicalChunkLengthsRequired: true,
      physicalChunks: [
        {
          role: 'head',
          inputIndex: FUSED_QUOTIENT_INPUT_INDEX,
          blockIndex: FUSED_QUOTIENT_BLOCK_INDEX,
          coefficientCount: QUOTIENT_COEFFICIENTS - FUSED_QUOTIENT_TAIL_COEFFICIENTS,
          bytes: fusedQuotientHeadPayload.length,
          unlockingBytes: templateInputs[FUSED_QUOTIENT_INPUT_INDEX].unlocking.length,
          standardOperationCost:
            templateStandardOutcomes[FUSED_QUOTIENT_INPUT_INDEX].operationCost,
          densityMargin: (41 +
            templateInputs[FUSED_QUOTIENT_INPUT_INDEX].unlocking.length) * 800 -
            templateStandardOutcomes[FUSED_QUOTIENT_INPUT_INDEX].operationCost,
        },
        {
          role: 'tail',
          inputIndex: FUSED_QUOTIENT_TAIL_INPUT_INDEX,
          blockIndex: FUSED_QUOTIENT_TAIL_BLOCK_INDEX,
          coefficientCount: FUSED_QUOTIENT_TAIL_COEFFICIENTS,
          bytes: fusedQuotientTailPayload.length,
          unlockingBytes: templateInputs[FUSED_QUOTIENT_TAIL_INPUT_INDEX].unlocking.length,
          standardOperationCost:
            templateStandardOutcomes[FUSED_QUOTIENT_TAIL_INPUT_INDEX].operationCost,
          densityMargin: (41 +
            templateInputs[FUSED_QUOTIENT_TAIL_INPUT_INDEX].unlocking.length) * 800 -
            templateStandardOutcomes[FUSED_QUOTIENT_TAIL_INPUT_INDEX].operationCost,
        },
      ],
      quotientHelperBytes: fusedQuotientRedeem.length,
      quotientHelperSha256: hex(sha256(fusedQuotientRedeem)),
      quotientHelperCompilerOptions: {
        optimizeFor: 'size',
        inlinedIntoBlock4: true,
        contextSensitiveOpcodesAbsent: true,
      },
      commitmentTiming:
        'block payloads are committed before beta; the concatenated physical quotient chunks are committed as one framed logical leaf after beta and before alpha',
      quotientRoot: hex(quotientRoot),
      alpha: hex(alphaDigest),
      block4UnlockingBytes: templateInputs[FUSED_QUOTIENT_INPUT_INDEX].unlocking.length,
      block4StandardOperationCost:
        templateStandardOutcomes[FUSED_QUOTIENT_INPUT_INDEX].operationCost,
      block4DensityMargin: (41 +
        templateInputs[FUSED_QUOTIENT_INPUT_INDEX].unlocking.length) * 800 -
        templateStandardOutcomes[FUSED_QUOTIENT_INPUT_INDEX].operationCost,
      block15UnlockingBytes: templateInputs[FUSED_QUOTIENT_TAIL_INPUT_INDEX].unlocking.length,
      block15StandardOperationCost:
        templateStandardOutcomes[FUSED_QUOTIENT_TAIL_INPUT_INDEX].operationCost,
      block15DensityMargin: (41 +
        templateInputs[FUSED_QUOTIENT_TAIL_INPUT_INDEX].unlocking.length) * 800 -
        templateStandardOutcomes[FUSED_QUOTIENT_TAIL_INPUT_INDEX].operationCost,
      strictPhysicalChunkRejections: fullRejectionFixtures.filter(({ name }) =>
        name.includes('q132')),
    },
    regularDensityPadding: REGULAR_DENSITY_PADDING,
    coordinatorDensityPadding: COORDINATOR_DENSITY_PADDING,
    picBlock2DensityPadding: PIC_BLOCK2_DENSITY_PADDING,
    picBlock4DensityPadding: PIC_BLOCK4_DENSITY_PADDING,
    regeneratedWitnesses: {
      proofStatementSha256: hex(sha256(statementBytes)),
      residueRootSha256: hex(sha256(serializeLimbs(fp6ToFlat(residue.u)))),
      transcriptHeaderSha256: hex(sha256(transcriptHeader)),
      blockPayloadsSha256: hex(sha256(concat(...blockPayloads))),
      quotientPayloadsSha256: hex(sha256(concat(...quotientPayloads))),
      quotientPhysicalChunksSha256: hex(sha256(concat(
        fusedQuotientHeadPayload,
        fusedQuotientTailPayload,
      ))),
      transactionSha256: hex(sha256(templateTransactionBytes)),
    },
    picAuthentication: {
      fixture: 'v4 public-vk position-adjusted flat GT cache',
      globalRoot: picCache.globalRoot,
      cachePath: picCachePath,
      cacheSha256: hex(sha256(picCacheBytes)),
      helperBytes: picAuthHelper.length,
      helperSha256: hex(sha256(picAuthHelper)),
      helperCompilerOptions: { rescheduleStacks: false, optimizeFor: 'size' },
      oneSha256PerMerkleLevel: true,
      batchCommitmentBytes: picBatchCommitmentBlob.length,
      batchCommitmentSha256: hex(sha256(picBatchCommitmentBlob)),
      batchCommitmentDomain: hex(PIC_BATCH_TAG),
      batchCommitments: picBatchCommitments.map(hex),
      block4FixedBlob: {
        bytes: picFixedBlob.length,
        layout: 'Bsubstitute[0..192) || psi[192..336)',
        p2shPinnedByCoordinatorSiblingDigest: true,
        batchCommitmentsEmbeddedInAuthHelper: true,
        bSubstituteAndPsiConsumedByOwningChecks: true,
      },
      block4CarrierPrefixBytes: picBlock4Redeem.length - picBaseBlock4Redeem.length,
      wrapperBytes: picAuthBatches.map((batch) => ({
        ...batch,
        bytes: picAuthWrapper(batch.firstWindow, batch.windowCount).length,
      })),
      batches: picAuthBatches,
      fixtureGate: picAuthFixtureRows,
      rejectionFixtures: {
        changedFactor: changedFactorRejection,
        changedPath: changedPathRejection,
        changedScalarWithOldRecord: changedScalarRejection,
        changedBatchCommitmentByHost: changedBatchCommitmentRejections,
        changedBatchDomain: changedBatchDomainRejection,
        changedBatchOrder: changedBatchOrderRejection,
        wrongCarrierOrWindowTag: wrongCarrierRejection,
        changedBatchCount: wrongCountRejection,
        truncatedPathLayout: truncatedPathRejection,
        extendedPathLayout: extendedPathRejection,
      },
      limitations: [],
    },
    templateFactoring: {
      functions: [
        {
          functionId: TEMPLATE_COMMON_FUNCTION_ID,
          bodyBytes: templateCommonBody.length,
          bodySha256: hex(sha256(templateCommonBody)),
          instructionCount: templateCommonOpcodes.length,
          controlFlowBalanced: templateCommonConditionalDepth === 0 &&
            templateCommonLoopDepth === 0,
          contextSensitiveOpcodesAbsent: true,
          carrierTemplate: templateCommonCarrier.name,
          carrierBlockIndex: templateCommonCarrier.representative,
          factoredTemplates: [...templateCommonOffsets.keys()],
          originalOffsets: Object.fromEntries(templateCommonOffsets),
        },
        {
          functionId: TEMPLATE_EXTRA_FUNCTION_ID,
          bodyBytes: templateExtraBody.length,
          bodySha256: hex(sha256(templateExtraBody)),
          instructionCount: templateExtraOpcodes.length,
          controlFlowBalanced: templateExtraConditionalDepth === 0 &&
            templateExtraLoopDepth === 0,
          contextSensitiveOpcodesAbsent: true,
          carrierTemplate: templateExtraCarrier.name,
          carrierBlockIndex: templateExtraCarrier.representative,
          factoredTemplates: [...templateExtraOffsets.keys()],
          originalOffsets: Object.fromEntries(templateExtraOffsets),
        },
      ],
      replacementBytesPerInvocation: pushVmNumber(TEMPLATE_COMMON_FUNCTION_ID).length + 1,
      carrierLengthsConverged: templateCarrierLengthsStable,
      carrierRedeemLengths: Object.fromEntries(templateCarrierLengths),
      additionTailDensityPaddingBytes: templateTailDensityPadding.length,
      additionMiddleDensityPaddingBytes: templateFactorDensityPaddingBytes,
      p2shPinnedByCoordinatorSiblingDigest: true,
      mutationRejections: fullRejectionFixtures.filter(({ name }) =>
        name.startsWith('changed-template-')),
    },
    lockingBytecodes: templateInputs.map((input) => hex(input.locking)),
    resourceBytecodes: process.env.RPA_EXPORT_RESOURCE_BYTECODES === '1'
      ? {
        inputs: templateInputs.map((input) => ({
          locking: hex(input.locking),
          unlocking: hex(input.unlocking),
        })),
      }
      : undefined,
    lockingSetSha256: hex(sha256(concat(...templateInputs.map(
      (input) => concat(numberToBinUint16LE(input.locking.length), input.locking),
    )))),
    rejectionFixtures: fullRejectionFixtures,
    templates: templateClasses.map((template) => ({
      name: template.name,
      representative: template.representative,
      members: template.members,
      coreBytes: template.core.length,
      coreDigest: hex(template.digest),
      representativeRedeemBytes: template.representativeRedeem.length,
    })),
    wireBytes: templateWireBytes,
    feeSatoshis: Number(templateFeeSatoshis),
    exactOneSatPerByteFee: templateFeeSatoshis === BigInt(templateWireBytes),
    scriptBytes: sum(templateInputs, (input) => input.locking.length + input.unlocking.length),
    redeemBytes: sum(templateInputs, (input) => input.redeem.length),
    unlockingBytes: sum(templateInputs, (input) => input.unlocking.length),
    consensusOperationCost: sum(templateConsensusOutcomes, (outcome) => outcome.operationCost),
    standardOperationCost: sum(templateStandardOutcomes, (outcome) => outcome.operationCost),
    baselineWireBytes: wireBytes,
    baselineStandardOperationCost: sum(standardOutcomes, (outcome) => outcome.operationCost),
    standardOperationDelta: sum(templateStandardOutcomes, (outcome) => outcome.operationCost) -
      sum(standardOutcomes, (outcome) => outcome.operationCost),
    baselineMetrics,
    templateMetrics,
    metricDelta,
    operationDeltaBreakdown,
    inputs: templateInputs.map((input, index) => ({
      index,
      role: input.role,
      payloadBytes: input.payload?.length ?? 0,
      evaluationBytes: input.evaluation?.length ?? 0,
      quotientChunkRole: input.quotientChunkRole ?? null,
      quotientChunkBytes: input.quotientChunk?.length ?? 0,
      redeemBytes: input.redeem.length,
      lockingBytes: input.locking.length,
      unlockingBytes: input.unlocking.length,
      consensusAccepted: templateConsensusOutcomes[index].accepted,
      consensusError: templateConsensusOutcomes[index].error,
      consensusOperationCost: templateConsensusOutcomes[index].operationCost,
      standardAccepted: templateStandardOutcomes[index].accepted,
      standardError: templateStandardOutcomes[index].error,
      standardOperationCost: templateStandardOutcomes[index].operationCost,
      densityBudget: (41 + input.unlocking.length) * 800,
      densityMargin: (41 + input.unlocking.length) * 800 -
        templateStandardOutcomes[index].operationCost,
    })),
    maxRedeemBytes: Math.max(...templateInputs.map((input) => input.redeem.length)),
    maxUnlockingBytes: Math.max(...templateInputs.map((input) => input.unlocking.length)),
    maxConsensusInputOperationCost: Math.max(
      ...templateConsensusOutcomes.map((outcome) => outcome.operationCost),
    ),
    maxStandardInputOperationCost: Math.max(
      ...templateStandardOutcomes.map((outcome) => outcome.operationCost),
    ),
    allConsensusInputsAccepted: templateConsensusOutcomes.every((outcome) => outcome.accepted),
    allStandardInputsAccepted: templateStandardOutcomes.every((outcome) => outcome.accepted),
    wholeConsensusVerified: templateWholeConsensusVerified,
    wholeStandardVerified: templateWholeStandardVerified,
    standardRelaySize: templateWireBytes <= 100_000,
  }, null, 2)}\n`);
  process.exit(0);
}

const replacePayload = (input, payload) => ({
  ...input,
  payload,
  unlocking: input.evaluation === null
    ? concat(encodeDataPush(payload), encodeDataPush(input.redeem))
    : concat(
      encodeDataPush(payload),
      encodeDataPush(input.evaluation),
      encodeDataPush(input.redeem),
    ),
});
const replaceEvaluation = (input, evaluation) => ({
  ...input,
  evaluation,
  unlocking: concat(
    encodeDataPush(input.payload),
    encodeDataPush(evaluation),
    encodeDataPush(input.redeem),
  ),
});
const replaceLimb = (bytes, offset, value, width = W) => {
  const changed = Uint8Array.from(bytes);
  changed.set(serializeUnsignedLe(value, width), offset);
  return changed;
};
const rejectionFixture = (name, targetInputIndices, mutate) => {
  const changed = inputs.map((input) => ({
    ...input,
    locking: Uint8Array.from(input.locking),
    unlocking: Uint8Array.from(input.unlocking),
    payload: input.payload === null ? null : Uint8Array.from(input.payload),
    evaluation: input.evaluation === null ? null : Uint8Array.from(input.evaluation),
  }));
  mutate(changed);
  const targetConsensus = targetInputIndices.map((index) => evaluateInput(changed, index, consensusVm));
  const targetStandard = targetInputIndices.map((index) => evaluateInput(changed, index, standardVm));
  const consensusRejected = consensusVm.verify(verificationData(changed)) !== true;
  const standardRejected = standardVm.verify(verificationData(changed)) !== true;
  assert(consensusRejected, `${name} was accepted by the consensus VM`);
  assert(standardRejected, `${name} was accepted by the standard VM`);
  assert(targetConsensus.some((outcome) => !outcome.accepted),
    `${name} did not fail its targeted consensus input`);
  assert(targetStandard.some((outcome) => !outcome.accepted),
    `${name} did not fail its targeted standard input`);
  return {
    name,
    consensusRejected,
    standardRejected,
    targetInputIndices,
    targetConsensusRejected: targetConsensus.map((outcome) => !outcome.accepted),
    targetStandardRejected: targetStandard.map((outcome) => !outcome.accepted),
    targetConsensusErrors: targetConsensus.map((outcome) => outcome.error),
    targetStandardErrors: targetStandard.map((outcome) => outcome.error),
  };
};

const rejections = [
  rejectionFixture('changed-order', [0, 1, 2], (changed) => {
    [changed[1], changed[2]] = [changed[2], changed[1]];
  }),
  rejectionFixture('extra-graph-input', [0], (changed) => {
    changed.push({ ...changed.at(-1) });
  }),
  rejectionFixture('missing-graph-input', [0], (changed) => {
    changed.pop();
  }),
  rejectionFixture('changed-sibling-locking', [0, 1], (changed) => {
    changed[1].locking[changed[1].locking.length - 1] ^= 1;
  }),
  rejectionFixture('changed-sibling-locking-length', [0, 1], (changed) => {
    changed[1].locking = changed[1].locking.slice(0, -1);
  }),
  rejectionFixture('changed-chart-flag', [1], (changed) => {
    const payload = Uint8Array.from(changed[1].payload);
    payload[blockRecords[0].layout.outputFlag] = 2;
    changed[1] = replacePayload(changed[1], payload);
  }),
  rejectionFixture('changed-chart-state', [1], (changed) => {
    const payload = Uint8Array.from(changed[1].payload);
    payload[blockRecords[0].layout.outputU + W] ^= 1;
    changed[1] = replacePayload(changed[1], payload);
  }),
  ...(INVERSE_RELATIONS ? [rejectionFixture('changed-selected-inverse', [1], (changed) => {
    const payload = Uint8Array.from(changed[1].payload);
    payload[blockRecords[0].layout.outputInverse] ^= 1;
    changed[1] = replacePayload(changed[1], payload);
  })] : []),
  rejectionFixture('changed-fixed-table', [1], (changed) => {
    const payload = Uint8Array.from(changed[1].payload);
    payload[blockRecords[0].layout.fixedCoefficients] ^= 1;
    changed[1] = replacePayload(changed[1], payload);
  }),
  rejectionFixture('changed-Q', [1 + blockPayloads.length], (changed) => {
    const inputIndex = 1 + blockPayloads.length;
    const payload = Uint8Array.from(changed[inputIndex].payload);
    payload[payload.length - 1] ^= 1;
    changed[inputIndex] = replacePayload(changed[inputIndex], payload);
  }),
  rejectionFixture('changed-evaluation-recurrence', [8, 9], (changed) => {
    const before = Uint8Array.from(changed[8].evaluation);
    const evaluation = Uint8Array.from(before);
    evaluation[0] ^= 1;
    assert(!equalBytes(before, evaluation), 'evaluation recurrence mutation was a no-op');
    changed[8] = replaceEvaluation(changed[8], evaluation);
  }),
  rejectionFixture('changed-transcript', [0], (changed) => {
    const header = Uint8Array.from(transcriptHeader);
    header[0] ^= 1;
    changed[0] = makeCoordinatorInput(header);
  }),
  rejectionFixture('changed-coordinator-locking', [0], (changed) => {
    changed[0].locking[changed[0].locking.length - 1] ^= 1;
  }),
  rejectionFixture('changed-statement-length', [0], (changed) => {
    changed[0] = makeCoordinatorInput(transcriptHeader, statementBytes.slice(0, -1));
  }),
  rejectionFixture('changed-statement-B-range', [0], (changed) => {
    changed[0] = makeCoordinatorInput(
      transcriptHeader,
      replaceLimb(statementBytes, statementLayout[statementIndex.effectiveBxa].offset, P),
    );
  }),
  rejectionFixture('changed-public-input-range', [0], (changed) => {
    changed[0] = makeCoordinatorInput(
      transcriptHeader,
      replaceLimb(
        statementBytes,
        statementLayout[statementIndex.public0].offset,
        SCALAR_ORDER,
        statementLayout[statementIndex.public0].width,
      ),
    );
  }),
  rejectionFixture('changed-residue-root-range', [0], (changed) => {
    changed[0] = makeCoordinatorInput(
      transcriptHeader,
      replaceLimb(statementBytes, statementLayout[statementIndex.root0].offset, P),
    );
  }),
  rejectionFixture('changed-A-unit-equation', [0], (changed) => {
    const changedU = mod(units[0] + 1n);
    assert(!unitCurveHolds(changedU, units[1]), 'A unit mutation remained on curve');
    changed[0] = makeCoordinatorInput(
      transcriptHeader,
      replaceLimb(statementBytes, statementLayout[statementIndex.p0u].offset, changedU),
    );
  }),
  rejectionFixture('changed-C-unit-equation', [0], (changed) => {
    const changedU = mod(units.at(-2) + 1n);
    assert(!unitCurveHolds(changedU, units.at(-1)), 'C unit mutation remained on curve');
    changed[0] = makeCoordinatorInput(
      transcriptHeader,
      replaceLimb(statementBytes, statementLayout[statementIndex.p3u].offset, changedU),
    );
  }),
  ...(!SKIP_GAMMA ? [rejectionFixture('changed-MSM-unit-equation', [0], (changed) => {
    const changedU = mod(units[2] + 1n);
    assert(!unitCurveHolds(changedU, units[3]), 'MSM unit mutation remained on curve');
    changed[0] = makeCoordinatorInput(
      transcriptHeader,
      replaceLimb(statementBytes, statementLayout[statementIndex.p2u].offset, changedU),
    );
  })] : []),
  rejectionFixture('changed-prior-payload-length', [1, 2], (changed) => {
    changed[1] = replacePayload(changed[1], changed[1].payload.slice(0, -1));
  }),
  rejectionFixture('changed-prior-payload-range', [1, 2], (changed) => {
    changed[1] = replacePayload(
      changed[1],
      replaceLimb(changed[1].payload, blockRecords[0].layout.outputU, P),
    );
  }),
  rejectionFixture('changed-prior-evaluation-length', [1, 2], (changed) => {
    changed[1] = replaceEvaluation(changed[1], changed[1].evaluation.slice(0, -1));
  }),
  rejectionFixture('changed-prior-evaluation-range', [1, 2], (changed) => {
    changed[1] = replaceEvaluation(changed[1], replaceLimb(changed[1].evaluation, 0, P));
  }),
  rejectionFixture('changed-root-header-push', [0], (changed) => {
    changed[0] = {
      ...changed[0],
      unlocking: concat(
        Uint8Array.of(0x4d),
        numberToBinUint16LE(transcriptHeader.length),
        transcriptHeader,
        encodeDataPush(statementBytes),
        encodeDataPush(coordinatorRedeem),
      ),
    };
  }),
  rejectionFixture('changed-prior-payload-push', [1, 0], (changed) => {
    changed[1] = {
      ...changed[1],
      unlocking: concat(
        Uint8Array.of(0x4e),
        u32(changed[1].payload.length),
        changed[1].payload,
        encodeDataPush(changed[1].evaluation),
        encodeDataPush(changed[1].redeem),
      ),
    };
  }),
  rejectionFixture('changed-prior-evaluation-push', [1, 0], (changed) => {
    changed[1] = {
      ...changed[1],
      unlocking: concat(
        encodeDataPush(changed[1].payload),
        Uint8Array.of(0x4d),
        numberToBinUint16LE(changed[1].evaluation.length),
        changed[1].evaluation,
        encodeDataPush(changed[1].redeem),
      ),
    };
  }),
];

[
  'changed-statement-length',
  'changed-statement-B-range',
  'changed-public-input-range',
  'changed-residue-root-range',
  'changed-A-unit-equation',
  'changed-C-unit-equation',
  ...(!SKIP_GAMMA ? ['changed-MSM-unit-equation'] : []),
  'changed-prior-payload-length',
  'changed-prior-payload-range',
  'changed-prior-evaluation-length',
  'changed-prior-evaluation-range',
  'changed-root-header-push',
  'changed-prior-payload-push',
  'changed-prior-evaluation-push',
].forEach((name) => {
  const fixture = rejections.find((item) => item.name === name);
  assert(
    fixture.targetConsensusRejected[0] && fixture.targetStandardRejected[0],
    `${name} passed its designated owning validator`,
  );
});

const rows = inputs.map((input, index) => ({
  index,
  role: input.role,
  payloadBytes: input.payload?.length ?? statementBytes.length + transcriptHeader.length,
  evaluationBytes: input.evaluation?.length ?? 0,
  redeemBytes: input.redeem.length,
  lockingBytes: input.locking.length,
  unlockingBytes: input.unlocking.length,
  consensusOperationCost: consensusOutcomes[index].operationCost,
  standardOperationCost: standardOutcomes[index].operationCost,
}));
const totalSourceSatoshis = validData.sourceOutputs.reduce(
  (total, output) => total + output.valueSatoshis,
  0n,
);
const totalOutputSatoshis = validData.transaction.outputs.reduce(
  (total, output) => total + output.valueSatoshis,
  0n,
);
const sourceLockingBytes = sum(rows, (row) => row.lockingBytes);
const scriptBytes = sum(rows, (row) => row.lockingBytes + row.unlockingBytes);
const redeemBytes = sum(rows, (row) => row.redeemBytes);
const unlockingBytes = sum(rows, (row) => row.unlockingBytes);
const consensusOperationCost = sum(rows, (row) => row.consensusOperationCost);
const standardOperationCost = sum(rows, (row) => row.standardOperationCost);
const transactionShellBytes = wireBytes - sum(rows, (row) => 43 + row.unlockingBytes);
assert(transactionShellBytes === 20, 'transaction shell accounting changed');

const blockRows = rows.slice(1, 1 + blockPayloads.length);
const quotientRows = rows.slice(1 + blockPayloads.length);
const baselineMeasurements = {
  wireBytes: 163_436,
  scriptBytes: 163_216,
  redeemBytes: 103_387,
  consensusOperationCost: 66_576_716,
  standardOperationCost: 66_969_804,
};
const report = {
  construction: {
    scope: `compiled depth-3 canonical two-chart quotient-torus Miller relation construction (${INVERSE_RELATIONS ? 'inverse-backed' : 'universal-nonzero-factor'} mode)`,
    completeVerifier: false,
    fixedSetupScalarRelationsUsed: false,
    binaryRounds: squareIndices.length,
    binaryAdditions: ATE_LOOP_DIGITS.filter((digit) => digit !== 0).length,
    fusedOperations: trace.ops.length,
    runtimeLines: 68,
    fixedVkLines: 68,
    fixedFoldCount: 1,
    blockCount: blockPayloads.length,
    quotientCarrierCount: quotientPayloads.length,
    totalInputCount: inputs.length,
    modulus: 'Y^6 - 2*Y^3 + 2',
    quotientCoefficientCeiling: QUOTIENT_COEFFICIENTS,
    quotientBytes: quotientBytes.length,
    relationCount: relationRecords.length,
    equationsCompiled: [
      'input-0 canonical statement ranges and identity-complete unit-G1 curve equations',
      'all genuine square and normalized direct8 factor evaluations',
      'all 68 runtime affine-G2 slope and endpoint equations',
      'all 68 fixed delta lines plus 32 authenticated public-input GT factors derived from the public VK',
      'canonical chart flag domain and chart-1 u=0 rule',
      INVERSE_RELATIONS
        ? 'cross relation and selected-scale inverse relation at every block'
        : 'cross relation at every block, with selected-scale nonzero implied by the certified field/product chain',
      'transaction-wide beta-power and relation-sum recurrence',
      `${QUOTIENT_COEFFICIENTS}-coefficient combined-Q Horner evaluation`,
      'fixed alpha/beta plus IC0 quotient fold',
      INVERSE_RELATIONS
        ? 'six-limb residue-root Frobenius terminal cross and selected-scale inverse relation'
        : 'six-limb residue-root Frobenius terminal cross relation',
      'all 32 public-input-indexed GT factors authenticated against the fixed v4 window roots',
      'runtime effective-B on-curve check plus terminal psi subgroup endpoint comparison',
    ],
    omittedChecks: [
      'independent multi-proof fixture suite and benchmark-vector generation',
      'full-verifier B-identity fixture using the fixed affine trace substitute',
    ],
  },
  statementEncoding: {
    bytes: statementBytes.length,
    limbBytes: W,
    orderedFields: statementFields.map(([name, , upperBound]) => ({
      name,
      upperBound: upperBound === P ? 'base-field-p' : 'scalar-field-r',
    })),
    proofA: 'p0=(u,v) is the canonical identity-complete encoding of -A; no raw affine A copy exists',
    proofB: 'Bidentity plus four effective affine Fp limbs; flag 0 is canonical nonzero proof B, flag 1 is semantic identity using the fixed certified trace substitute',
    proofC: 'p3=(u,v) is the canonical identity-complete encoding of C; no raw affine C copy exists',
    unitEquation: 'v = 4*u^3 + 16*v^3 (mod p), with (0,0) the unique identity encoding',
    unitEquationsCheckedAtRoot: ['p0 (-A)', 'p3 (C)'],
    publicInputLinkComplete: PIC32_RECORDS,
    publicInputLink: 'little-endian public-scalar bytes select authenticated v4 public-vk GT factors',
  },
  deferredG2Completion: {
    integrated: true,
    runtimeEndpoint: 'block 20 outputR is the affine [|x|]B endpoint after all 63 binary rounds',
    blsParameter: 'x = -0xd201000000010000',
    subgroupCriterion: 'psi(B) = [x]B, equivalently [|x|]B = -psi(B)',
    psi: '(PSI_X * conjugate(B.x), PSI_Y * conjugate(B.y)) over Fp2',
    affineComparison: 'outputR.x = psi(B).x and outputR.y = -psi(B).y',
    collapseSemantics:
      'the affine tangent/chord denominator checks reject a walk that reaches the identity, including the certified order-13 case; there is no projective zero comparison',
    identitySemantics:
      'Bidentity=1 is semantic identity, requires the fixed certified substitute coordinates, and zeroes the paired G1 unit; a full valid identity-proof fixture remains required',
    references: [
      'qsplit_psi_degeneracy_test.mjs affine denominator and endpoint certificate',
      '_pairingmath.mjs and _residuemath.mjs qsplit affine/direct8 trace',
      'singleton/bls12-381/lib/G2Check.cash psi constants and formula',
      'gen_g2check.mjs subgroup sign and comparison',
    ],
  },
  charts: {
    chart0: '1 + u*W whenever c0 != 0',
    chart1: 'W only (flag=1 requires all six u coefficients equal zero)',
    completeCoverage: true,
    overlapRemoved: true,
    flagDomainCompiled: [0, 1],
    selectedScaleInverseWitnessBytes: INVERSE_RELATIONS ? (blockPayloads.length + 1) * 6 * W : 0,
    fixtureBoundaryFlags: boundaryCharts.map((item) => item.flag),
    zeroExcludedBy: INVERSE_RELATIONS
      ? 'selected(alpha)*z(alpha)-1 is included in the same pre-beta polynomial identity'
      : 'prove_rpa_two_chart_binary.mjs certifies both field moduli and the universal nonzero product chain; a valid canonical cross identity therefore forces the selected chart scale nonzero',
  },
  quotientResidue: {
    serializedRootLimbs: 6,
    serializedRootBytes: 6 * W,
    inverseByNegation: true,
    correctionWVanishesInFp6Quotient: true,
    terminalMatchesFrobeniusClass: true,
    fixedFoldTorusLimbsHardcoded: fixedTorusFlat.length,
  },
  preparedFixedTable: {
    lineCount: 68,
    payloadBytes: sum(blockRecords, (record) => record.fixedCoefficients.length * W),
    commitmentsHardcodedInRedeems: true,
    blocks: blockRecords.map((record) => ({
      blockIndex: record.blockIndex,
      bytes: record.fixedCoefficients.length * W,
      commitment: hex(record.fixedCommitment),
    })),
  },
  transcript: {
    magic: Buffer.from(MAGIC).toString('ascii'),
    hash: 'SHA-256',
    statementBytes: statementBytes.length,
    blockPayloadBytes: sum(blockPayloads, (payload) => payload.length),
    blockEvaluationBytes: sum(blockEvaluationPayloads, (payload) => payload.length),
    blockPayloadLengths: blockPayloads.map((payload) => payload.length),
    quotientBytes: quotientBytes.length,
    quotientPayloadLengths: quotientPayloads.map((payload) => payload.length),
    quotientEvaluationBytes: quotientPayloads.length === 1
      ? 0
      : sum(quotientEvaluationPayloads, (payload) => payload.length),
    headerBytes: transcriptHeader.length,
    commitmentRoot: binToHex(commitmentRoot),
    quotientRoot: binToHex(quotientRoot),
    betaDigest: binToHex(betaDigest),
    alphaDigest: binToHex(alphaDigest),
    rootsRecomputed: equalBytes(commitmentRoot, treeFor(commitmentPayloads)) &&
      equalBytes(quotientRoot, treeFor(
        quotientPayloads,
        quotientPayloads.map(() => quotientBytes.length),
      )),
    preBetaCommitted: [
      'statement, root, unit-G1 values',
      'every chart state and flag',
      ...(INVERSE_RELATIONS ? ['every selected-scale inverse polynomial'] : []),
      'every runtime affine endpoint and slope',
      'every fixed line coefficient',
    ],
    postBetaPreAlphaCommitted: ['combined quotient coefficients'],
    postAlphaDeterministic: ['block recurrence evaluations', 'Q Horner accumulators'],
  },
  graphAuthentication: {
    rootInputIndex: 0,
    exactInputCount: BASELINE_TOTAL_INPUTS,
    siblingLockingEncoding:
      `fixed-width 35-byte complete locking bytecodes, inputs 1..${BASELINE_TOTAL_INPUTS - 1} in order`,
    siblingLockingDigest: hex(siblingLockingDigest),
    digestHardcodedInRootRedeem: true,
    siblingLengthChecksCompiled: true,
    siblingProgramsDependOnRootLocking: false,
    circularLockDependency: false,
  },
  validationHoisting: {
    validationScope: `the complete ${BASELINE_TOTAL_INPUTS}-input transaction rooted at active input 0`,
    standaloneSuffixInputClaim: false,
    rootValidatedOnce: [
      'exact input count, output shape, sibling order, sibling locking lengths, and sibling locking digest',
      'exact 128-byte transcript header and transcript hash derivations',
      'beta is nonzero; alpha and beta are SHA-256 digests, hence both are below p because 2^256 < p',
      'exact 17-limb/737-byte statement layout',
      'B, residue-root, and unit-coordinate base-field ranges',
      'both public inputs are canonical scalar-field values',
      'identity-complete unit-curve equations for -A and C',
    ],
    consensusSerializationPremise:
      'BCH2026 consensus requires minimal data-push encodings; focused non-minimal header, payload, and evaluation fixtures are rejected by the consensus VM',
    removedFromEveryBlock: [
      'transcript-header length and alpha/beta range checks: implied by successful input 0',
      'statement length and immutable B/root/unit range checks: implied by successful input 0',
      'immutable unit-coordinate ranges: implied by successful input 0',
    ],
    removedFromConsumerBlocks: [
      'previous payload length: consensus-minimal push layout plus the producing block own payload check fixes the consumer view',
      'previous output ranges, chart flag domain, and chart-1 zero rule: checked by the producing block',
      'previous evaluation length and recurrence-value ranges: consensus-minimal push layout plus the producing block checks fixes these values',
    ],
    removedFromQuotientConsumers: [
      ...(quotientPayloads.length === 1 ? [] : [
        'previous quotient evaluation length/range: checked by the preceding quotient input',
      ]),
      'final block evaluation length/range: checked by the final block input',
    ],
    retainedPerBlock: [
      'active input index and exact transaction input count',
      'own payload and evaluation lengths',
      'all own proof-dependent output ranges and chart-domain checks',
      'fixed-VK blob hash binding',
      'all transition, affine-G2, relation, recurrence, and terminal equations',
    ],
    retainedPerQuotientCarrier: [
      'active input index and exact transaction input count',
      quotientPayloads.length === 1
        ? 'own payload length and coefficient ranges'
        : 'own payload/evaluation lengths and coefficient ranges',
      quotientPayloads.length === 1
        ? 'full Horner evaluation and final quotient identity'
        : 'Horner recurrence, expected accumulator, and final quotient identity',
    ],
  },
  baselineComparison: {
    baseline: baselineMeasurements,
    current: {
      wireBytes,
      scriptBytes,
      redeemBytes,
      consensusOperationCost,
      standardOperationCost,
    },
    delta: {
      wireBytes: wireBytes - baselineMeasurements.wireBytes,
      scriptBytes: scriptBytes - baselineMeasurements.scriptBytes,
      redeemBytes: redeemBytes - baselineMeasurements.redeemBytes,
      consensusOperationCost: consensusOperationCost - baselineMeasurements.consensusOperationCost,
      standardOperationCost: standardOperationCost - baselineMeasurements.standardOperationCost,
    },
  },
  measurements: {
    wireBytes,
    wirePlusSourceLockingBytes: wireBytes + sourceLockingBytes,
    scriptBytes,
    sourceLockingBytes,
    redeemBytes,
    unlockingBytes,
    consensusOperationCost,
    standardOperationCost,
    maxConsensusInputOperationCost: Math.max(...rows.map((row) => row.consensusOperationCost)),
    maxStandardInputOperationCost: Math.max(...rows.map((row) => row.standardOperationCost)),
    maxRedeemBytes: Math.max(...rows.map((row) => row.redeemBytes)),
    maxUnlockingBytes: Math.max(...rows.map((row) => row.unlockingBytes)),
    wholeConsensusVerified,
    wholeStandardVerified,
    standardRelaySize: wireBytes <= 100_000,
    exactOneSatPerByteFee: totalSourceSatoshis - totalOutputSatoshis === BigInt(wireBytes),
    allPerInputBudgetsFit: rows.every((row) =>
      row.lockingBytes <= 10_000 && row.unlockingBytes <= 10_000 &&
      row.consensusOperationCost <= OP_BUDGET && row.standardOperationCost <= OP_BUDGET),
  },
  coordinator: rows[0],
  blocks: {
    payloadBytes: sum(blockRows, (row) => row.payloadBytes),
    evaluationBytes: sum(blockRows, (row) => row.evaluationBytes),
    redeemBytes: {
      min: Math.min(...blockRows.map((row) => row.redeemBytes)),
      max: Math.max(...blockRows.map((row) => row.redeemBytes)),
      total: sum(blockRows, (row) => row.redeemBytes),
    },
    unlockingBytes: {
      min: Math.min(...blockRows.map((row) => row.unlockingBytes)),
      max: Math.max(...blockRows.map((row) => row.unlockingBytes)),
      total: sum(blockRows, (row) => row.unlockingBytes),
    },
    standardOperationCost: {
      min: Math.min(...blockRows.map((row) => row.standardOperationCost)),
      max: Math.max(...blockRows.map((row) => row.standardOperationCost)),
      total: sum(blockRows, (row) => row.standardOperationCost),
    },
    diagnostics: blockRecords.map((record, index) => ({
      blockIndex: record.blockIndex,
      rounds: record.roundHi - record.roundLo,
      operations: record.operations.length,
      runtimeLines: record.runtimeOps.length,
      fixedLines: record.fixedOps.length,
      componentDegrees: record.componentDegrees,
      crossQuotientCoefficients: record.relation.crossQuotient.length,
      inverseQuotientCoefficients: INVERSE_RELATIONS ? record.relation.inverseQuotient.length : null,
      payloadBytes: record.payload.length,
      redeemBytes: blockRows[index].redeemBytes,
      unlockingBytes: blockRows[index].unlockingBytes,
      standardOperationCost: blockRows[index].standardOperationCost,
    })),
  },
  quotientCarriers: quotientRows,
  changedFieldCases: rejections,
  rows,
};

const summary = {
  construction: report.construction,
  statementEncoding: report.statementEncoding,
  deferredG2Completion: report.deferredG2Completion,
  charts: report.charts,
  quotientResidue: report.quotientResidue,
  preparedFixedTable: {
    lineCount: report.preparedFixedTable.lineCount,
    payloadBytes: report.preparedFixedTable.payloadBytes,
    commitmentsHardcodedInRedeems: report.preparedFixedTable.commitmentsHardcodedInRedeems,
  },
  transcript: {
    statementBytes: report.transcript.statementBytes,
    blockPayloadBytes: report.transcript.blockPayloadBytes,
    blockEvaluationBytes: report.transcript.blockEvaluationBytes,
    blockPayloadLengths: report.transcript.blockPayloadLengths,
    quotientBytes: report.transcript.quotientBytes,
    quotientPayloadLengths: report.transcript.quotientPayloadLengths,
    quotientEvaluationBytes: report.transcript.quotientEvaluationBytes,
    rootsRecomputed: report.transcript.rootsRecomputed,
  },
  graphAuthentication: report.graphAuthentication,
  validationHoisting: report.validationHoisting,
  baselineComparison: report.baselineComparison,
  measurements: report.measurements,
  coordinator: report.coordinator,
  blocks: report.blocks,
  quotientCarriers: report.quotientCarriers,
  changedFieldCases: report.changedFieldCases,
};
console.log(JSON.stringify(process.env.RPA_SUMMARY === '1' ? summary : report, null, 2));

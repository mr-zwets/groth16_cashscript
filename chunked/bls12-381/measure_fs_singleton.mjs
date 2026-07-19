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

// ---- FS singleton fixed configuration (set before the shared prelude reads env).
// This file is a derived single-script variant of measure_d3_two_chart_binary.mjs:
// lines above/below the appended "FS singleton" section are the unmodified shared
// prelude of that source (same trace, payloads, relations, and transcript).
const { fileURLToPath: fsFileURLToPath } = await import('node:url');
process.env.RPA_INVERSES = 'off';
process.env.RPA_SKIP_GAMMA = '1';
process.env.RPA_PIC32 = '1';
process.env.RPA_PIC_LAYOUT = 'regular';
if (process.env.RPA_GT_CACHE === undefined) {
  process.env.RPA_GT_CACHE = fsFileURLToPath(
    new URL('../../bls-gt-merkle-w8-position-regular-flat-v1.json', import.meta.url));
}
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

// ===================== FS singleton (single-script oracle) =====================
// Everything below emits ONE contract that performs the complete qsplit tail-22
// verification in a single script: the Fiat-Shamir commitment roots and the
// beta/alpha challenges are recomputed in-script over the witness blobs, the
// 32 PIC GT-table Merkle authentications run inline against the baked window
// roots, and the 21 Miller blocks chain through locals instead of cross-input
// reads. Measured on the loosened BCH 2026 VM (the singleton oracle category,
// same harness shape as singleton/bls12-381/build_vectors_groth16_minop.mjs).

const {
  ConsensusBch2025,
  createTestAuthenticationProgramBch,
  ripemd160,
  secp256k1,
  sha1,
  sha256: libauthSha256,
} = await import('@bitauth/libauth');
const { writeFileSync: fsWriteFileSync } = await import('node:fs');

const FS_RESCHEDULE = process.env.FS_RESCHEDULE !== 'off';
const FS_EXPORT_VECTORS = process.env.FS_EXPORT_VECTORS === '1';
const hexByte = (value) => value.toString(16).padStart(2, '0');

const fsArgNames = [
  'bytes statementBlob',
  ...blockPayloads.map((_, index) => `bytes payload${index}`),
  'bytes quotientBlob',
];
const fs = [
  'contract Groth16FsSingleton() {',
  `    function spend(${fsArgNames.join(',')}) {`,
  `        require(statementBlob.length==${statementBytes.length});`,
];
blockPayloads.forEach((payload, index) => {
  fs.push(`        require(payload${index}.length==${payload.length});`);
});
fs.push(`        require(quotientBlob.length==${quotientBytes.length});`);

// Fiat-Shamir: rebuild the commitment tree over the witness blobs, then derive
// beta and alpha exactly as the transaction-wide transcript does.
const fsCommitmentSpecs = [
  {
    expression: 'statementBlob',
    payloadLength: statementBytes.length,
    metadataLength: statementBytes.length,
  },
  ...blockPayloads.map((payload, index) => ({
    expression: `payload${index}`,
    payloadLength: payload.length,
    metadataLength: payload.length,
  })),
];
const fsCommitmentRoot = appendTreeSource(fs, 'fsc', fsCommitmentSpecs);
fs.push(
  `        int beta=int(sha256(0x${prefixHex('beta', 36)}+` +
    `0x${binToHex(u32(blockPayloads.length))}+${fsCommitmentRoot})+0x00);`,
  '        require(beta!=0);',
);
const fsQuotientRoot = appendTreeSource(fs, 'fsq', [{
  expression: 'quotientBlob',
  payloadLength: quotientBytes.length,
  metadataLength: quotientBytes.length,
}]);
fs.push(
  `        int alpha=int(sha256(0x${prefixHex('alpha', 64)}+` +
    `${fsCommitmentRoot}+${fsQuotientRoot})+0x00);`,
);

// Statement parse + range checks (the coordinator's role).
statementFields.forEach(([name, , upperBound]) => {
  fs.push(
    `        int ${name}=${statementLimbExpression(statementIndex[name])};`,
    `        require(within(${name},0,${upperBound}));`,
  );
});
fs.push(
  '        int effectiveBSum=effectiveBxa+effectiveBxb+effectiveBya+effectiveByb;',
  '        if (Bidentity==1) {',
  `            require(effectiveBxa==${identitySubstituteB.x.c0});`,
  `            require(effectiveBxb==${identitySubstituteB.x.c1});`,
  `            require(effectiveBya==${identitySubstituteB.y.c0});`,
  `            require(effectiveByb==${identitySubstituteB.y.c1});`,
  '        } else {',
  '            require(effectiveBSum!=0);',
  '            (int bx2a,int bx2b)=r2Sqr(effectiveBxa,effectiveBxb);',
  '            (int bx3a,int bx3b)=r2Mul(bx2a,bx2b,effectiveBxa,effectiveBxb);',
  '            (int by2a,int by2b)=r2Sqr(effectiveBya,effectiveByb);',
  '            require(by2a==mAdd(bx3a,4)); require(by2b==mAdd(bx3b,4));',
  '        }',
);
['p0', 'p3'].forEach((prefix) => {
  fs.push(
    `        int ${prefix}u2=mSqr(${prefix}u);`,
    `        int ${prefix}u3=mulFp(${prefix}u2,${prefix}u);`,
    `        int ${prefix}v2=mSqr(${prefix}v);`,
    `        int ${prefix}v3=mulFp(${prefix}v2,${prefix}v);`,
    `        require(${prefix}v==mAdd(mulFp(4,${prefix}u3),mulFp(16,${prefix}v3)));`,
  );
});
fs.push(
  '        int Bxa=effectiveBxa; int Bxb=effectiveBxb; int Bya=effectiveBya; int Byb=effectiveByb;',
  '        int bIdentity=Bidentity;',
  '        int pairP0u=p0u; int pairP0v=p0v;',
  '        if (bIdentity==1) { pairP0u=0; pairP0v=0; }',
  '        int alpha2=mulFp(alpha,alpha);',
  '        int alpha4=mulFp(alpha2,alpha2);',
  '        int alpha5=mulFp(alpha4,alpha);',
  '        int rootEval=eval6(root0,root1,root2,root3,root4,root5,alpha);',
);

// PIC GT-table authentication: all 32 windows inline, each leaf index bound to
// the committed public-input bytes and each path closing on the baked window root.
fs.push(
  `        bytes fsScalar0=statementBlob.split(${public0Offset + 32})[0].split(${public0Offset})[1];`,
  `        bytes fsScalar1=statementBlob.split(${public1Offset + 32})[0].split(${public1Offset})[1];`,
);
picCache.windowRoots.forEach((rootHex, window) => {
  const carrierBlock = regularPicWindowBlocks[window];
  const slot = window % 2;
  fs.push(
    `        bytes fsRec${window}=payload${carrierBlock}.split(${PIC_RECORD_REGION_OFFSET})[1]` +
      `.split(${PIC_RECORD_BYTES})[${slot}];`,
    `        bytes fsFac${window}=fsRec${window}.split(${PIC_FACTOR_BYTES})[0];`,
    `        bytes fsPath${window}=fsRec${window}.split(${PIC_FACTOR_BYTES})[1];`,
    `        bytes fsDig${window}=fsScalar0.split(${window + 1})[0].split(${window})[1]` +
      `+fsScalar1.split(${window + 1})[0].split(${window})[1];`,
    `        bytes fsNode${window}=sha256(0x${hex(PIC_LEAF_TAG)}${hexByte(carrierBlock)}` +
      `${hexByte(window)}+fsDig${window}+fsFac${window});`,
    `        int fsIdx${window}=int(fsDig${window}+0x${hexByte(window)}00);`,
    `        for (int fsLvl${window}=0;fsLvl${window}<16;fsLvl${window}=fsLvl${window}+1) {`,
    `            bytes fsSib${window}=fsPath${window}.split(32)[0];`,
    `            fsPath${window}=fsPath${window}.split(32)[1];`,
    `            int fsPar${window}=fsIdx${window}>>1;`,
    `            bytes fsPre${window}=0x${hex(PIC_NODE_TAG)}+toPaddedBytes(fsLvl${window}+1,1)` +
      `+toPaddedBytes(fsPar${window},4);`,
    `            if (fsIdx${window}%2==0) { fsNode${window}=sha256(fsPre${window}+fsNode${window}+fsSib${window}); }`,
    `            else { fsNode${window}=sha256(fsPre${window}+fsSib${window}+fsNode${window}); }`,
    `            fsIdx${window}=fsPar${window};`,
    '        }',
    `        require(fsIdx${window}==${window});`,
    `        require(fsNode${window}==0x${rootHex});`,
  );
});

// The 21 Miller blocks, chained through locals.
const emitFsBlock = (record) => {
  const B = record.blockIndex;
  const pv = `payload${B}`;
  const pfx = (name) => `fb${B}${name}`;
  const lines = [];
  Array.from({ length: 6 }, (_, index) =>
    declareLimb(lines, pfx(`outU${index}`), pv, record.layout.outputU + index * W));
  lines.push(
    `        int ${pfx('outFlag')} = ${byteExpression(pv, record.layout.outputFlag)};`,
    `        require(${pfx('outFlag')} == 0 || ${pfx('outFlag')} == 1);`,
    `        if (${pfx('outFlag')} == 1) {`,
  );
  Array.from({ length: 6 }, (_, index) =>
    lines.push(`            require(${pfx(`outU${index}`)} == 0);`));
  lines.push('        }');
  ['outRxa', 'outRxb', 'outRya', 'outRyb'].forEach((name, index) => {
    declareLimb(lines, pfx(name), pv, record.layout.outputR + index * W);
  });
  record.runtimeOps.forEach((_, index) => {
    declareLimb(lines, pfx(`s${index}a`), pv, record.layout.runtimeSlopes + index * 2 * W);
    declareLimb(lines, pfx(`s${index}b`), pv, record.layout.runtimeSlopes + (index * 2 + 1) * W);
  });
  record.fixedOps.forEach((_, index) => {
    ['d0a', 'd0b', 'ma', 'mb'].forEach((suffix, limbIndex) => {
      declareLimb(lines, pfx(`f${index}${suffix}`), pv,
        record.layout.fixedCoefficients + (index * 4 + limbIndex) * W, false);
    });
  });
  const fixedEnd = record.layout.fixedCoefficients + record.fixedCoefficients.length * W;
  lines.push(
    `        bytes ${pfx('fixedBlob')} = ${pv}.split(${fixedEnd})[0]` +
      `.split(${record.layout.fixedCoefficients})[1];`,
    `        require(sha256(${pfx('fixedBlob')}) == 0x${hex(record.fixedCommitment)});`,
  );
  let liftOffset = record.layout.liftRecords;
  record.liftRecords.forEach((liftRecord, factorIndex) => {
    Array.from({ length: 6 }, (_, limbIndex) => {
      declareLimb(lines, pfx(`lift${factorIndex}_${limbIndex}`), pv,
        liftOffset + limbIndex * W, !PIC32_RECORDS);
    });
    liftOffset += liftRecord.payload.length;
  });
  if (record.splitRelation !== undefined) {
    Array.from({ length: 6 }, (_, index) =>
      declareLimb(lines, pfx(`splitU${index}`), pv, record.layout.splitU + index * W));
    lines.push(
      `        int ${pfx('splitFlag')} = ${byteExpression(pv, record.layout.splitFlag)};`,
      `        require(${pfx('splitFlag')} == 0 || ${pfx('splitFlag')} == 1);`,
      `        if (${pfx('splitFlag')} == 1) {`,
    );
    Array.from({ length: 6 }, (_, index) =>
      lines.push(`            require(${pfx(`splitU${index}`)} == 0);`));
    lines.push('        }');
  }
  if (B === 0) {
    lines.push(
      '        int rXa=Bxa; int rXb=Bxb; int rYa=Bya; int rYb=Byb;',
      '        int relationPower=1; int relationTotal=0;',
      '        int state0=1; int state1=mSub(0,rootEval);',
    );
  } else {
    lines.push(
      '        state0=1; state1=fsChainEval;',
      '        if (fsChainFlag==1) { state0=fsChainEval; state1=1; }',
    );
  }
  let runtimeIndex = 0;
  let fixedIndex = 0;
  let operationIndex = 0;
  record.operations.forEach((op) => {
    if (op.t === 'sqr') {
      lines.push('        (state0,state1)=pairSquareEval(state0,state1,alpha);');
    } else if (op.t === 'cf') {
      lines.push(`        (state0,state1)=pairMulEval(state0,state1,` +
        `${op.neg ? 'rootEval' : 'mSub(0,rootEval)'},alpha);`);
    } else if (op.j === 0) {
      const s = pfx(`o${operationIndex}`);
      if (op.t === 'dl') {
        lines.push(
          `        (int ${s}da,int ${s}db,int ${s}nxa,int ${s}nxb,` +
            `int ${s}nya,int ${s}nyb)=pointDoubleAffine(` +
            `rXa,rXb,rYa,rYb,${pfx(`s${runtimeIndex}a`)},${pfx(`s${runtimeIndex}b`)});`,
        );
      } else {
        const qya = op.neg ? 'mSub(0,Bya)' : 'Bya';
        const qyb = op.neg ? 'mSub(0,Byb)' : 'Byb';
        lines.push(
          `        (int ${s}da,int ${s}db,int ${s}nxa,int ${s}nxb,` +
            `int ${s}nya,int ${s}nyb)=pointAddAffine(` +
            `rXa,rXb,rYa,rYb,Bxa,Bxb,${qya},${qyb},` +
            `${pfx(`s${runtimeIndex}a`)},${pfx(`s${runtimeIndex}b`)});`,
        );
      }
      lines.push(
        `        (state0,state1)=lineEval(state0,state1,${s}da,${s}db,` +
          `${pfx(`s${runtimeIndex}a`)},${pfx(`s${runtimeIndex}b`)},` +
          'pairP0u,pairP0v,alpha,alpha2,alpha4,alpha5);',
        `        rXa=${s}nxa; rXb=${s}nxb; rYa=${s}nya; rYb=${s}nyb;`,
      );
      runtimeIndex += 1;
    } else if (op.j === 2 || op.j === 3) {
      lines.push(
        `        (state0,state1)=lineEval(state0,state1,` +
          `${pfx(`f${fixedIndex}d0a`)},${pfx(`f${fixedIndex}d0b`)},` +
          `${pfx(`f${fixedIndex}ma`)},${pfx(`f${fixedIndex}mb`)},` +
          `p${op.j}u,p${op.j}v,alpha,alpha2,alpha4,alpha5);`,
      );
      fixedIndex += 1;
    } else {
      throw new Error(`unsupported operation ${op.t}/${op.j} in fs block ${B}`);
    }
    if (record.splitRelation?.operationCount === operationIndex + 1) {
      lines.push(
        `        int ${pfx('splitEval')}=eval6(${Array.from({ length: 6 },
    (_, index) => pfx(`splitU${index}`)).join(',')},alpha);`,
        `        int ${pfx('splitSelected')}=state0; int ${pfx('splitOther')}=state1;`,
        `        if (${pfx('splitFlag')} == 1) { ${pfx('splitSelected')}=state1; ` +
          `${pfx('splitOther')}=state0; }`,
        `        int ${pfx('splitResidual')}=mSub(${pfx('splitOther')},` +
          `mulFp(${pfx('splitSelected')},${pfx('splitEval')}));`,
        '        (relationPower,relationTotal)=absorbRelation(relationPower,' +
          `relationTotal,${pfx('splitResidual')},beta);`,
        `        state0=1; state1=${pfx('splitEval')};`,
        `        if (${pfx('splitFlag')} == 1) { state0=0; state1=1; }`,
      );
    }
    operationIndex += 1;
  });
  assert(runtimeIndex === record.runtimeOps.length, `fs block ${B} runtime count changed`);
  assert(fixedIndex === record.fixedOps.length, `fs block ${B} fixed count changed`);
  record.liftRecords.forEach((_, factorIndex) => {
    lines.push(
      `        int ${pfx(`liftEval${factorIndex}`)}=eval6(${Array.from({ length: 6 },
    (__, limbIndex) => pfx(`lift${factorIndex}_${limbIndex}`)).join(',')},alpha);`,
      `        (state0,state1)=pairMulEval(state0,state1,${pfx(`liftEval${factorIndex}`)},alpha);`,
    );
  });
  lines.push(
    `        require(rXa==${pfx('outRxa')}); require(rXb==${pfx('outRxb')});`,
    `        require(rYa==${pfx('outRya')}); require(rYb==${pfx('outRyb')});`,
    `        int ${pfx('outEval')}=eval6(${Array.from({ length: 6 },
    (_, index) => pfx(`outU${index}`)).join(',')},alpha);`,
    `        int ${pfx('selected')}=state0; int ${pfx('other')}=state1;`,
    `        if (${pfx('outFlag')} == 1) { ${pfx('selected')}=state1; ${pfx('other')}=state0; }`,
    `        int ${pfx('crossResidual')}=mSub(${pfx('other')},` +
      `mulFp(${pfx('selected')},${pfx('outEval')}));`,
    '        (relationPower,relationTotal)=absorbRelation(relationPower,' +
      `relationTotal,${pfx('crossResidual')},beta);`,
  );
  lines.push(B === 0
    ? `        int fsChainEval=${pfx('outEval')}; int fsChainFlag=${pfx('outFlag')};`
    : `        fsChainEval=${pfx('outEval')}; fsChainFlag=${pfx('outFlag')};`);
  if (record.terminalRelation !== undefined) {
    lines.push(
      '        int conjugateBxb=mSub(0,Bxb); int conjugateByb=mSub(0,Byb);',
      '        (int psiBxa,int psiBxb)=r2Mul(0,' +
        '4002409555221667392624310435006688643935503118305586438271171395842971157480381377015405980053539358417135540939437,' +
        'Bxa,conjugateBxb);',
      '        (int psiBya,int psiByb)=r2Mul(' +
        '2973677408986561043442465346520108879172042883009249989176415018091420807192182638567116318576472649347015917690530,' +
        '1028732146235106349975324479215795277384839936929757896155643118032610843298655225875571310552543014690878354869257,' +
        'Bya,conjugateByb);',
      `        require(${pfx('outRxa')}==psiBxa); require(${pfx('outRxb')}==psiBxb);`,
      `        require(${pfx('outRya')}==mSub(0,psiBya)); require(${pfx('outRyb')}==mSub(0,psiByb));`,
      `        state0=1; state1=${pfx('outEval')};`,
      `        if (${pfx('outFlag')} == 1) { state0=0; state1=1; }`,
      `        int fixedEval=eval6(${fixedTorusFlat.join(',')},alpha);`,
      '        (state0,state1)=pairMulEval(state0,state1,fixedEval,alpha);',
      '        (int frob0,int frob1,int frob2,int frob3,int frob4,int frob5)=' +
        'torusFrobFlat(root0,root1,root2,root3,root4,root5);',
      '        int frobEval=eval6(frob0,frob1,frob2,frob3,frob4,frob5,alpha);',
      '        int terminalCross=mSub(state1,mulFp(state0,frobEval));',
      '        (relationPower,relationTotal)=absorbRelation(relationPower,' +
        'relationTotal,terminalCross,beta);',
    );
  }
  return lines;
};
blockRecords.forEach((record) => fs.push(...emitFsBlock(record)));

// Combined quotient: Horner over the single logical q132 blob, then the
// terminal identity sum(beta^k r_k)(alpha) == q(alpha) * m(alpha).
fs.push(
  '        bytes fsRemaining=quotientBlob;',
  '        int fsAcc=0;',
  `        for (int fsQi=0;fsQi<${QUOTIENT_COEFFICIENTS};fsQi=fsQi+1) {`,
  '            bytes fsCoefBytes=fsRemaining.split(48)[0];',
  '            fsRemaining=fsRemaining.split(48)[1];',
  '            int fsCoef=int(fsCoefBytes+0x00);',
  `            require(fsCoef<${P});`,
  `            fsAcc=(fsAcc*alpha+fsCoef)%${P};`,
  '        }',
  '        int fsAlpha3=mulFp(alpha2,alpha);',
  '        int fsModulus=mAdd(mSub(mulFp(fsAlpha3,fsAlpha3),mulFp(2,fsAlpha3)),2);',
  '        require(mulFp(fsAcc,fsModulus)==relationTotal);',
  '    }',
  '}',
);
const fsSource = `${COMMON_SOURCE}${fs.join('\n')}\n`;
if (process.env.FS_SOURCE_OUT !== undefined) fsWriteFileSync(process.env.FS_SOURCE_OUT, fsSource);

const fsCompileStarted = Date.now();
const fsRedeem = compileNamed(fsSource, 'fs singleton',
  FS_RESCHEDULE ? { rescheduleStacks: true } : { rescheduleStacks: false });
const fsCompileMs = Date.now() - fsCompileStarted;

// Witness and measurement on the loosened BCH 2026 VM.
const fsArgs = [statementBytes, ...blockPayloads, quotientBytes];
assert(fsArgs.length === fsArgNames.length, 'fs singleton arg shape changed');
const fsUnlockingFor = (args) => concat(...args.slice().reverse().map(
  (arg) => encodeDataPush(arg),
));
const HUGE = Number.MAX_SAFE_INTEGER;
const fsLoosenedConsensus = {
  ...ConsensusBch2025,
  baseInstructionCost: 100,
  maximumFunctionIdentifierLength: 7,
  maximumMemorySlots: HUGE,
  maximumStandardLockingBytecodeLength: -1,
  maximumStandardUnlockingBytecodeLength: HUGE,
  maximumTokenCommitmentLength: 128,
  operationCostBudgetPerByte: HUGE,
  maximumStackItemLength: HUGE,
  maximumVmNumberByteLength: HUGE,
  maximumStackDepth: HUGE,
  maximumControlStackDepth: HUGE,
  maximumBytecodeLength: HUGE,
  maximumOperationCount: HUGE,
};
const fsVm = createVirtualMachine(createInstructionSetBch2026(false, {
  consensus: fsLoosenedConsensus, ripemd160, secp256k1, sha1, sha256: libauthSha256,
}));
const fsEvaluate = (unlocking) => {
  const program = createTestAuthenticationProgramBch({
    lockingBytecode: fsRedeem,
    unlockingBytecode: unlocking,
    valueSatoshis: 1000n,
  });
  const state = fsVm.evaluate(program);
  const top = state.stack[state.stack.length - 1];
  const accepted = state.error === undefined && state.stack.length === 1 &&
    top !== undefined && top.length === 1 && top[0] === 1;
  return {
    accepted,
    error: state.error ?? null,
    operationCost: Number(state.metrics.operationCost),
    hashDigestIterations: Number(state.metrics.hashDigestIterations ?? 0),
  };
};
const fsValidUnlocking = fsUnlockingFor(fsArgs);
const fsValid = fsEvaluate(fsValidUnlocking);
assert(fsValid.accepted, `fs singleton rejected the valid ${activeFixtureName} fixture: ${fsValid.error}`);

const fsMutated = (argIndex, transform) => {
  const args = fsArgs.map((arg) => Uint8Array.from(arg));
  transform(args[argIndex], args);
  return fsUnlockingFor(args);
};
const STATEMENT_ARG = 0;
const QUOTIENT_ARG = fsArgs.length - 1;
const fsRejections = [
  ['changed-public-input', fsMutated(STATEMENT_ARG, (blob) => {
    blob[statementLayout[statementIndex.public0].offset] ^= 1;
  })],
  ['changed-proof-B-coordinate', fsMutated(STATEMENT_ARG, (blob) => {
    blob[statementLayout[statementIndex.effectiveBxa].offset] ^= 1;
  })],
  ['changed-B-identity-flag', fsMutated(STATEMENT_ARG, (blob) => {
    blob[statementLayout[statementIndex.Bidentity].offset] ^= 1;
  })],
  ['changed-residue-root', fsMutated(STATEMENT_ARG, (blob) => {
    blob[statementLayout[statementIndex.root0].offset] ^= 1;
  })],
  ['changed-proof-A-unit', fsMutated(STATEMENT_ARG, (blob) => {
    blob[statementLayout[statementIndex.p0u].offset] ^= 1;
  })],
  ['changed-runtime-slope', fsMutated(1 + 3, (blob) => {
    blob[blockRecords[3].layout.runtimeSlopes] ^= 1;
  })],
  ['changed-chart-output', fsMutated(1 + 7, (blob) => {
    blob[blockRecords[7].layout.outputU] ^= 1;
  })],
  ['changed-authenticated-PIC-factor', fsMutated(1 + 2, (blob) => {
    blob[PIC_RECORD_REGION_OFFSET] ^= 1;
  })],
  ['changed-authenticated-PIC-path', fsMutated(1 + 2, (blob) => {
    blob[PIC_RECORD_REGION_OFFSET + PIC_FACTOR_BYTES] ^= 1;
  })],
  ['changed-q132-coefficient', fsMutated(QUOTIENT_ARG, (blob) => {
    blob[blob.length - 1] ^= 1;
  })],
  ['truncated-q132-payload', fsUnlockingFor(fsArgs.map((arg, index) =>
    index === QUOTIENT_ARG ? arg.slice(0, arg.length - W) : arg))],
  ['swapped-block-payloads', fsUnlockingFor((() => {
    const args = fsArgs.map((arg) => Uint8Array.from(arg));
    [args[1 + 2], args[1 + 3]] = [args[1 + 3], args[1 + 2]];
    return args;
  })())],
].map(([name, unlocking]) => {
  const result = fsEvaluate(unlocking);
  assert(!result.accepted, `fs singleton accepted changed-field fixture ${name}`);
  return FS_EXPORT_VECTORS
    ? { name, rejected: !result.accepted, unlocking: hex(unlocking) }
    : { name, rejected: !result.accepted };
});

console.log(JSON.stringify({
  construction: 'fs singleton: whole qsplit tail-22 verification in one script',
  fixture: activeFixtureName,
  publicInputs: activePublicInputs.map(String),
  bIdentity,
  compilerRescheduleStacks: FS_RESCHEDULE,
  compileMs: fsCompileMs,
  sourceLines: fsSource.split('\n').length,
  sourceSha256: hex(sha256(Uint8Array.from(Buffer.from(fsSource, 'utf8')))),
  lockingBytes: fsRedeem.length,
  unlockingBytes: fsValidUnlocking.length,
  totalBytes: fsRedeem.length + fsValidUnlocking.length,
  operationCost: fsValid.operationCost,
  hashDigestIterations: fsValid.hashDigestIterations,
  accepted: fsValid.accepted,
  rejectionFixtures: fsRejections,
  cacheGlobalRoot: picCache.globalRoot,
  ...(FS_EXPORT_VECTORS ? {
    lockingHex: hex(fsRedeem),
    unlockingHex: hex(fsValidUnlocking),
  } : {}),
}, null, 2));

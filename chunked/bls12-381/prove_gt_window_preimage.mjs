// Algebra and representation certificate for the public-VK-derived authenticated
// GT preimages used in place of the runtime vk_x/gamma Miller pair.
import { createHash } from 'node:crypto';
import { writeFileSync } from 'node:fs';

import { P, bls12_381, le48, vk } from './_vkxmath.mjs';
import { Fp6, Fp12, qsplitSinglePairMiller as singlePairMiller } from './_pairingmath.mjs';

const R = bls12_381.fields.Fr.ORDER;
const H = (P ** 12n - 1n) / R;
// Noble's BLS12-381 optimized finalExponentiate implements 3H for this
// pairing convention. Its restriction to GT is therefore exponent N mod r.
const N = 3n * H;
const WINDOWS = 32;
const DIGIT_LIMIT = 256;
const POINTS = WINDOWS * DIGIT_LIMIT * DIGIT_LIMIT;
const CARRIER_BLOCKS = [2, 3, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 16, 17, 18, 19];
const WINDOW_BLOCKS = CARRIER_BLOCKS.flatMap((block) => [block, block]);
const WINDOW_REMAINING_SQUARES = WINDOW_BLOCKS.map((block) => 3 * (20 - block));
const FLAT_CONJUGATE = process.env.GT_CACHE_ENCODING === 'flat-conjugate';
const CACHE_PATH = process.env.GT_CACHE_PATH ?? (FLAT_CONJUGATE
  ? 'bls-gt-merkle-w8-position-regular-flat-v1.json'
  : 'bls-gt-merkle-w8-position-regular-v1.json');
const MERKLE_DOMAIN = Uint8Array.from(Buffer.from(FLAT_CONJUGATE ? 'BLSGTF1' : 'BLSGTR1', 'ascii'));

const fail = (message) => { throw new Error(message); };
const assert = (condition, message) => { if (!condition) fail(message); };
const sha256 = (bytes) => new Uint8Array(createHash('sha256').update(bytes).digest());
const concatenate = (...arrays) => Uint8Array.from(arrays.flatMap((array) => [...array]));
const toLe = (value, width) => {
  let remaining = BigInt(value);
  const output = new Uint8Array(width);
  for (let index = 0; index < width; index += 1) {
    output[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  assert(remaining === 0n, `value does not fit ${width} bytes`);
  return output;
};
const merkleLeaf = (block, window, index, encoded) => sha256(concatenate(
  MERKLE_DOMAIN, Uint8Array.of(0x4c, block, window), toLe(index, 2), encoded,
));
const merkleNode = (level, index, left, right) => sha256(concatenate(
  MERKLE_DOMAIN, Uint8Array.of(0x4e, level), toLe(index, 4), left, right,
));
const gcd = (left, right) => {
  let a = left;
  let b = right;
  while (b !== 0n) [a, b] = [b, a % b];
  return a;
};
const inverseMod = (value, modulus) => {
  let oldR = value;
  let r = modulus;
  let oldS = 1n;
  let s = 0n;
  while (r !== 0n) {
    const quotient = oldR / r;
    [oldR, r] = [r, oldR - quotient * r];
    [oldS, s] = [s, oldS - quotient * s];
  }
  assert(oldR === 1n, 'modular inverse does not exist');
  return ((oldS % modulus) + modulus) % modulus;
};
const limbs6 = (value) => [
  value.c0.c0, value.c0.c1,
  value.c1.c0, value.c1.c1,
  value.c2.c0, value.c2.c1,
];
const modP = (value) => ((value % P) + P) % P;
const flat6 = (value) => {
  const limbs = limbs6(value);
  return [
    limbs[0] - limbs[1], limbs[2] - limbs[3], limbs[4] - limbs[5],
    limbs[1], limbs[3], limbs[5],
  ].map(modP);
};
const fp6FromFlat = (flat) => Fp6.fromBigSix([
  modP(flat[0] + flat[3]), flat[3],
  modP(flat[1] + flat[4]), flat[4],
  modP(flat[2] + flat[5]), flat[5],
]);
const torus = (u) => Fp12.create({ c0: Fp6.ONE, c1: u });
const digitIndex = (inputs, window) =>
  Number((inputs[0] >> BigInt(8 * window)) & 0xffn) +
  DIGIT_LIMIT * Number((inputs[1] >> BigInt(8 * window)) & 0xffn);
const directMsm = (inputs) => {
  let point = bls12_381.G1.Point.ZERO;
  if (inputs[0] !== 0n) point = point.add(vk.ic[1].multiply(inputs[0]));
  if (inputs[1] !== 0n) point = point.add(vk.ic[2].multiply(inputs[1]));
  return point;
};

assert(gcd(N, R) === 1n, 'implemented final exponent is not invertible modulo r');
const inverseN = inverseMod(N % R, R);
assert((N * inverseN) % R === 1n, 'inverse implemented-final-exponent congruence failed');

const pairingBases = [vk.ic[1], vk.ic[2]].map((point) => bls12_381.pairing(point, vk.gamma));
const preimageBases = pairingBases.map((pairing) => Fp12.pow(pairing, inverseN));
preimageBases.forEach((preimage, index) => {
  assert(Fp12.eql(Fp12.finalExponentiate(preimage), pairingBases[index]),
    `base ${index} final-exponent preimage failed`);
  assert(Fp12.eql(Fp12.pow(preimage, R), Fp12.ONE),
    `base ${index} preimage is outside GT`);
});

const identityBalancedInputs = [0n, ((-29n * inverseMod(42n, R)) % R + R) % R];
assert((29n + 28n * identityBalancedInputs[0] + 42n * identityBalancedInputs[1]) % R === 0n,
  'identity-balanced public inputs changed');
const fixtures = [
  ['committed', [123n, 456n]],
  ['proof1', [135208n, 67633n]],
  ['dense-worst', [
    40792793307691160132937706698213704133054528069427933762012433436987942497952n,
    20976222017425405296340351928930328963278634447870202382235661951061637561134n,
  ]],
  ['zero', [0n, 0n]],
  ['max-canonical', [R - 1n, R - 1n]],
  ['msm-identity', [3n, R - 2n]],
  ['identity-balanced', identityBalancedInputs],
  ['deterministic-dense', [0, 1].map((side) =>
    BigInt(`0x${createHash('sha256').update(`bls-merkle-dense-${side}`).digest('hex')}`) % R)],
];
const selected = Object.fromEntries(fixtures.map(([name]) => [name, []]));
const records = Object.fromEntries(fixtures.map(([name]) => [name, []]));
const tableHash = createHash('sha256');
const k1Roots = [];
const windowRoots = [];
const certificate = {
  entries: 0,
  finiteCharts: 0,
  exceptionalCharts: 0,
  inverseChecks: 0,
  canonicalLimbChecks: 0,
  projectiveDifferentials: 0,
  adjustedBaseSubgroupChecks: 0,
  selectedEntrySubgroupChecks: 0,
  selectedPositionRestorationChecks: 0,
  selectedTerminalChartChecks: 0,
  conjugatedFlatDifferentials: 0,
  interleavedReplayChecks: 0,
};

for (let window = 0; window < WINDOWS; window += 1) {
  const carrierBlock = WINDOW_BLOCKS[window];
  const remainingSquares = WINDOW_REMAINING_SQUARES[window];
  const terminalScale = (1n << BigInt(8 * window)) % R;
  const squareUndo = inverseMod((1n << BigInt(remainingSquares)) % R, R);
  const scale = (terminalScale * squareUndo) % R;
  const bases = preimageBases.map((base) => Fp12.pow(base, scale));
  bases.forEach((base, index) => {
    assert(Fp12.eql(Fp12.pow(base, R), Fp12.ONE),
      `window ${window} adjusted base ${index} is outside GT`);
    certificate.adjustedBaseSubgroupChecks += 1;
  });
  const multiples = bases.map((base) => {
    const output = [Fp12.ONE];
    for (let digit = 1; digit < DIGIT_LIMIT; digit += 1) {
      output.push(Fp12.mul(output[digit - 1], base));
    }
    return output;
  });
  const entries = new Array(DIGIT_LIMIT * DIGIT_LIMIT);
  for (let digit1 = 0; digit1 < DIGIT_LIMIT; digit1 += 1) {
    for (let digit0 = 0; digit0 < DIGIT_LIMIT; digit0 += 1) {
      entries[digit0 + DIGIT_LIMIT * digit1] = Fp12.mul(multiples[0][digit0], multiples[1][digit1]);
    }
  }
  const c0Inverses = Fp6.invertBatch(entries.map((entry) => entry.c0));
  const leaves = new Array(entries.length);
  entries.forEach((entry, index) => {
    certificate.entries += 1;
    const c0Inverse = c0Inverses[index];
    if (c0Inverse === undefined) {
      certificate.exceptionalCharts += 1;
      return;
    }
    certificate.finiteCharts += 1;
    assert(Fp6.eql(Fp6.mul(entry.c0, c0Inverse), Fp6.ONE),
      `window ${window} entry ${index} Fp6 inverse failed`);
    certificate.inverseChecks += 1;
    const u = Fp6.mul(entry.c1, c0Inverse);
    const limbs = limbs6(u);
    assert(limbs.every((limb) => limb >= 0n && limb < P),
      `window ${window} entry ${index} torus limb is non-canonical`);
    certificate.canonicalLimbChecks += 1;
    assert(Fp6.eql(Fp6.mul(u, entry.c0), entry.c1),
      `window ${window} entry ${index} projective torus differential failed`);
    certificate.projectiveDifferentials += 1;
    const authenticatedLimbs = FLAT_CONJUGATE ? flat6(Fp6.neg(u)) : limbs;
    assert(authenticatedLimbs.every((limb) => limb >= 0n && limb < P),
      `window ${window} entry ${index} authenticated limb is non-canonical`);
    if (FLAT_CONJUGATE) {
      assert(Fp6.eql(fp6FromFlat(authenticatedLimbs), Fp6.neg(u)),
        `window ${window} entry ${index} conjugated flat differential failed`);
      certificate.conjugatedFlatDifferentials += 1;
    }
    const encoded = Buffer.concat(authenticatedLimbs.map((limb) => Buffer.from(le48(limb))));
    tableHash.update(encoded);
    leaves[index] = merkleLeaf(carrierBlock, window, index, encoded);
    fixtures.forEach(([name, inputs]) => {
      if (digitIndex(inputs, window) !== index) return;
      assert(Fp12.eql(Fp12.pow(entry, R), Fp12.ONE),
        `window ${window} ${name} selected entry is outside GT`);
      certificate.selectedEntrySubgroupChecks += 1;
      const terminalEntry = Fp12.pow(entry, 1n << BigInt(remainingSquares));
      const digit0 = index & 0xff;
      const digit1 = index >> 8;
      const expectedTerminalEntry = Fp12.mul(
        Fp12.pow(preimageBases[0], terminalScale * BigInt(digit0)),
        Fp12.pow(preimageBases[1], terminalScale * BigInt(digit1)),
      );
      assert(Fp12.eql(terminalEntry, expectedTerminalEntry),
        `window ${window} ${name} position adjustment did not restore the terminal entry`);
      certificate.selectedPositionRestorationChecks += 1;
      assert(!Fp6.eql(terminalEntry.c0, Fp6.ZERO),
        `window ${window} ${name} terminal entry has no finite torus chart`);
      const terminalU = Fp6.mul(terminalEntry.c1, Fp6.inv(terminalEntry.c0));
      assert(limbs6(terminalU).every((limb) => limb >= 0n && limb < P),
        `window ${window} ${name} terminal torus limb is non-canonical`);
      certificate.selectedTerminalChartChecks += 1;
      selected[name].push({
        entry,
        u,
        terminalEntry,
        terminalU,
        carrierBlock,
        remainingSquares,
      });
    });
  });
  const levels = [leaves];
  for (let level = 0; level < 16; level += 1) {
    const previous = levels[level];
    const next = new Array(previous.length / 2);
    for (let index = 0; index < next.length; index += 1) {
      const globalNodeIndex = window * (DIGIT_LIMIT * DIGIT_LIMIT >> (level + 1)) + index;
      next[index] = merkleNode(
        level + 1,
        globalNodeIndex,
        previous[2 * index],
        previous[2 * index + 1],
      );
    }
    levels.push(next);
  }
  assert(levels[15].length === 2 && levels[16].length === 1,
    `window ${window} Merkle tree shape changed`);
  k1Roots.push(...levels[15]);
  windowRoots.push(levels[16][0]);
  fixtures.forEach(([name, inputs]) => {
    const index = digitIndex(inputs, window);
    let cursor = index;
    const siblings = [];
    for (let level = 0; level < 16; level += 1) {
      siblings.push(levels[level][cursor ^ 1]);
      cursor >>= 1;
    }
    const selectedRecord = selected[name][window];
    const record = {
      index,
      carrierBlock,
      remainingSquares,
      path: Buffer.from(concatenate(...siblings)).toString('hex'),
    };
    if (FLAT_CONJUGATE) {
      record.factor = flat6(Fp6.neg(selectedRecord.u)).map(String);
      record.terminalFactor = flat6(Fp6.neg(selectedRecord.terminalU)).map(String);
    } else {
      record.u = limbs6(selectedRecord.u).map(String);
      record.terminalU = limbs6(selectedRecord.terminalU).map(String);
    }
    records[name].push(record);
  });
  process.stderr.write(`  certified GT window ${window + 1}/${WINDOWS}\n`);
}

assert(certificate.entries === POINTS, 'GT table certificate entry count mismatch');
assert(certificate.exceptionalCharts === 0, 'GT table has an exceptional torus chart');
assert(certificate.finiteCharts === POINTS &&
  certificate.inverseChecks === POINTS &&
  certificate.canonicalLimbChecks === POINTS &&
  certificate.projectiveDifferentials === POINTS,
'GT table certificate coverage mismatch');
assert(certificate.conjugatedFlatDifferentials === (FLAT_CONJUGATE ? POINTS : 0),
  'conjugated flat differential coverage mismatch');
assert(certificate.adjustedBaseSubgroupChecks === 2 * WINDOWS,
  'position-adjusted base subgroup coverage mismatch');
assert(certificate.selectedEntrySubgroupChecks === fixtures.length * WINDOWS &&
  certificate.selectedPositionRestorationChecks === fixtures.length * WINDOWS &&
  certificate.selectedTerminalChartChecks === fixtures.length * WINDOWS,
'selected position-adjustment coverage mismatch');

const fixtureResults = fixtures.map(([name, inputs]) => {
  assert(selected[name].length === WINDOWS, `${name} selected factor count mismatch`);
  let exactProduct = Fp12.ONE;
  let torusProduct = Fp12.ONE;
  selected[name].forEach(({ terminalEntry, terminalU }) => {
    exactProduct = Fp12.mul(exactProduct, terminalEntry);
    torusProduct = Fp12.mul(torusProduct, torus(terminalU));
  });
  let interleavedProduct = Fp12.ONE;
  for (let block = 0; block < 21; block += 1) {
    interleavedProduct = Fp12.pow(interleavedProduct, 8n);
    selected[name].forEach((record) => {
      if (record.carrierBlock === block) {
        interleavedProduct = Fp12.mul(interleavedProduct, torus(record.u));
      }
    });
  }
  assert(Fp6.eql(
    Fp6.mul(interleavedProduct.c0, torusProduct.c1),
    Fp6.mul(interleavedProduct.c1, torusProduct.c0),
  ), `${name} position-adjusted block replay changed the terminal quotient class`);
  assert(Fp6.eql(
    Fp6.mul(Fp12.conjugate(interleavedProduct).c0, Fp12.conjugate(torusProduct).c1),
    Fp6.mul(Fp12.conjugate(interleavedProduct).c1, Fp12.conjugate(torusProduct).c0),
  ), `${name} pre-conjugation block replay changed the terminal quotient class`);
  certificate.interleavedReplayChecks += 1;
  const msm = directMsm(inputs);
  const expected = msm.equals(bls12_381.G1.Point.ZERO)
    ? Fp12.ONE
    : bls12_381.pairing(msm, vk.gamma);
  assert(Fp12.eql(Fp12.finalExponentiate(exactProduct), expected),
    `${name} exact GT preimages do not reconstruct the public-input pairing`);
  assert(Fp12.eql(Fp12.finalExponentiate(torusProduct), expected),
    `${name} torus representatives do not reconstruct the public-input pairing`);
  const miller = msm.equals(bls12_381.G1.Point.ZERO) ? Fp12.ONE : singlePairMiller({ P: msm, Q: vk.gamma }).f;
  assert(Fp12.eql(Fp12.finalExponentiate(miller), expected),
    `${name} direct Miller differential failed`);
  const preConjugationFactor = Fp12.conjugate(interleavedProduct);
  assert(Fp12.eql(Fp12.finalExponentiate(Fp12.conjugate(preConjugationFactor)), expected),
    `${name} prepared-boundary conjugation orientation failed`);
  return {
    name,
    publicInputs: inputs.map(String),
    selectedFactors: selected[name].length,
    carrierBlocks: CARRIER_BLOCKS,
    positionAdjustedReplay: true,
    directMsmIdentity: msm.equals(bls12_381.G1.Point.ZERO),
  };
});

let globalLevel = windowRoots;
let globalTreeLevel = 16;
while (globalLevel.length > 1) {
  assert(globalLevel.length % 2 === 0, 'global Merkle level is not binary');
  globalTreeLevel += 1;
  globalLevel = Array.from({ length: globalLevel.length / 2 }, (_, index) =>
    merkleNode(globalTreeLevel, index, globalLevel[2 * index], globalLevel[2 * index + 1]));
}
const tableTorusSha256 = tableHash.digest('hex');
assert(certificate.interleavedReplayChecks === fixtures.length,
  'position-adjusted block replay coverage mismatch');
const k1RootBlob = concatenate(...k1Roots);
const globalRoot = globalLevel[0];
const cache = {
  version: FLAT_CONJUGATE ? 4 : 3,
  construction: 'public-vk-gt-position-adjusted-preimages-window8',
  layout: 'uniform-regular',
  recordEncoding: FLAT_CONJUGATE ? 'canonical-conjugated-flat-fp6' : 'canonical-standard-fp6',
  carrierBlocks: CARRIER_BLOCKS,
  windowBlocks: WINDOW_BLOCKS,
  windowRemainingSquares: WINDOW_REMAINING_SQUARES,
  merkleDomain: Buffer.from(MERKLE_DOMAIN).toString('ascii'),
  merkleLeaf: FLAT_CONJUGATE
    ? 'SHA256(BLSGTF1 || L || carrier-block:u8 || window:u8 || index:u16le || adjusted-conjugated-flat-factor:288B)'
    : 'SHA256(BLSGTR1 || L || carrier-block:u8 || window:u8 || index:u16le || adjusted-canonical-u:288B)',
  merkleNode: `SHA256(${FLAT_CONJUGATE ? 'BLSGTF1' : 'BLSGTR1'} || N || level:u8 || global-node-index:u32le || left || right)`,
  tableTorusSha256,
  certificate,
  k1Roots: k1Roots.map((root) => Buffer.from(root).toString('hex')),
  k1RootBlobSha256: createHash('sha256').update(k1RootBlob).digest('hex'),
  windowRoots: windowRoots.map((root) => Buffer.from(root).toString('hex')),
  globalRoot: Buffer.from(globalRoot).toString('hex'),
  records,
};
writeFileSync(CACHE_PATH, `${JSON.stringify(cache)}\n`);

console.log(JSON.stringify({
  construction: 'public-vk-gt-position-adjusted-preimages-window8',
  equation: 'after block-position squarings, nobleFinalExponent(product_j hAdjusted(j,d)^2^s(j)) = e(in0*IC1 + in1*IC2, gamma)',
  derivation: 'hAdjusted = e(256^j*(d0*IC1+d1*IC2), gamma)^((N*2^s)^-1 mod r), N=3*(p^12-1)/r',
  preConjugationFactor: 'each block folds conjugate(hAdjusted), implemented as the negative authenticated torus coordinate',
  layout: 'uniform-regular',
  recordEncoding: FLAT_CONJUGATE ? 'canonical-conjugated-flat-fp6' : 'canonical-standard-fp6',
  carrierBlocks: CARRIER_BLOCKS,
  windowBlocks: WINDOW_BLOCKS,
  windowRemainingSquares: WINDOW_REMAINING_SQUARES,
  noDiscreteLog: true,
  literalFinalExponentModR: (H % R).toString(),
  implementedFinalExponentModR: (N % R).toString(),
  implementedExponentMatchesThreeHOnGt: preimageBases.every((base) =>
    Fp12.eql(Fp12.finalExponentiate(base), Fp12.pow(base, N))),
  finalExponentGcd: gcd(N, R).toString(),
  inverseFinalExponentModR: inverseN.toString(),
  torusEntryBytes: 6 * 48,
  fullFp12EntryBytes: 12 * 48,
  k1PathBytesPerWindow: 15 * 32,
  k1TorusRecordBytesPerWindow: 6 * 48 + 15 * 32,
  k1TorusAuthenticationBytes: WINDOWS * (6 * 48 + 15 * 32),
  k1RootBytes: WINDOWS * 2 * 32,
  sha256Invocations: WINDOWS * 16,
  tableTorusBytes: POINTS * 6 * 48,
  tableTorusSha256,
  merkleCachePath: CACHE_PATH,
  k1RootBlobSha256: cache.k1RootBlobSha256,
  globalRoot: cache.globalRoot,
  certificate,
  fixtureResults,
  comparison: {
    currentG1MsmWireBytes: 26478,
    currentG1AuthenticationBytes: 18432,
    preparedPair2CoefficientBytes: 13056,
    torusAuthenticationBytes: WINDOWS * (6 * 48 + 15 * 32),
    grossBytesRemovedBeforeTorusFoldCode: 26478 + 13056 - WINDOWS * (6 * 48 + 15 * 32),
  },
}, null, 2));

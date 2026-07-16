// Executable equivalence and range checks for the grouped BN254 GLV schedule.
//
// The current schedule evaluates two 64-bit groups together, using fixed tables
// for P and [2^64]P. These checks cover every scalar basis position,
// every serialized table entry, the exact integer inequalities used by the
// constructive <2^128 decomposition bound, and the non-grouped generator output.
import { createHash } from 'node:crypto';
import { bn254, vec, vk } from './_millermath.mjs';
import {
  GLV_BASIS, GLV_LAMBDA, GLV_R, GLV_SPLIT_TABLE_HEX,
  VKXGLV_SPLIT_GROUPS, VKXGLV_SPLIT_ITERS,
  genCash, glvDecompose, glvDecomposeJoint, vkxGlvSplitStateAt, vkxGlvStateAt,
} from './gen_vkx_glv.mjs';

const BOUND = 1n << 128n;
const MASK64 = (1n << 64n) - 1n;
const TABLE_ENTRIES = 15;
const TABLE_ENTRY_BYTES = 64;
const Fp = bn254.fields.Fp;
const G1 = bn254.G1.Point;
const assert = (condition, message) => { if (!condition) throw new Error(message); };
const digest = (source) => createHash('sha256').update(source).digest('hex');
const abs = (value) => value < 0n ? -value : value;

// Pin every non-grouped generator form. Update these hashes only for an intentional
// change to the legacy/non-grouped output, never for a grouped-schedule-only edit.
const defaultCodegen = [
  ['plain', genCash(0, 1, false, false),
    '05df3ba57d3191fcf27a1565c997f93c11877d6afe62839ffce66781e5ca0cf3'],
  ['stage', genCash(0, 43, true, false, true),
    '656fba8a59ab8d1a4242151f809c1c7659f5f45eabeb18d0c6d8a477e5236bdd'],
  ['shared mid', genCash(43, 86, false, false, true, { inputIndex: 2, dataOffset: 233 }),
    '3229b58e2cea1ff7322511631e18b18a8ac498c021ec6cadcf0bfc0fcad178f4'],
  ['shared final', genCash(86, 128, false, true, true, { inputIndex: 2, dataOffset: 233 }),
    'b1c0ba31ef5495d2bc15940635f596c37f3b63b88e766808c86e559a29705544'],
  ['covenant first', genCash(0, 43, true, false, true, null, true),
    '03161408ebf4581ca4e18fcb3bbcb0724410fc8ea4ea574f3e2d595caea1c169'],
  ['covenant final', genCash(86, 128, false, true, true, null, true),
    'ac893e9d2eb22eaeb34a368f4321e212076b1ec697ab0e34142d6a78cf80311c'],
];
defaultCodegen.forEach(([label, source, expected]) => {
  assert(digest(source) === expected, `${label} default GLV codegen changed`);
});

const pointFromJacobian = ([x, y, z]) => {
  if (z === 0n) return G1.ZERO;
  const zInv = Fp.inv(z);
  const zInv2 = Fp.sqr(zInv);
  return G1.fromAffine({
    x: Fp.mul(x, zInv2),
    y: Fp.mul(y, Fp.mul(zInv2, zInv)),
  });
};
const inputsFor = ([k10, k20, k11, k21]) => [
  (k10 + k20 * GLV_LAMBDA) % GLV_R,
  (k11 + k21 * GLV_LAMBDA) % GLV_R,
];

// glvDecompose's nearest-plane rounding leaves a residual in the centered
// parallelogram: 2|x| <= |a1|+|a2| and 2|y| <= |b1|+|b2|. If y<0, subtract v1;
// then, if x<0, add v2. These exact inequalities prove that this choice is in
// [0, 2^128)^2 for every canonical scalar, so the generator's {-1,0,1} search
// always contains a bounded non-negative representative.
const { a1, b1, a2, b2 } = GLV_BASIS;
assert(a1 * b2 - a2 * b1 === GLV_R, 'GLV lattice determinant orientation mismatch');
assert((a1 + b1 * GLV_LAMBDA) % GLV_R === 0n, 'first GLV basis vector is not in the kernel');
assert((a2 + b2 * GLV_LAMBDA) % GLV_R === 0n, 'second GLV basis vector is not in the kernel');
assert(a1 > 0n && b1 < 0n && -b1 > b2 && a2 > 3n * a1 && b2 > 0n,
  'GLV basis signs do not satisfy the constructive quadrant map');
assert(a2 < BOUND, 'x correction can exceed the witness bound');
assert(-b1 + b2 < BOUND, 'y correction can exceed the witness bound');
assert((abs(b1) + b2 + 1n) / 2n + b2 < BOUND,
  'uncorrected y residual can exceed the witness bound');

const fromLe = (bytes) => {
  let value = 0n;
  for (let index = bytes.length - 1; index >= 0; index--) value = value << 8n | BigInt(bytes[index]);
  return value;
};
const serializedTable = Buffer.from(GLV_SPLIT_TABLE_HEX.slice(2), 'hex');
assert(serializedTable.length === VKXGLV_SPLIT_GROUPS * TABLE_ENTRIES * TABLE_ENTRY_BYTES,
  'serialized GLV table length mismatch');
const lanePoints = [
  vk.ic[1],
  vk.ic[1].multiplyUnsafe(GLV_LAMBDA),
  vk.ic[2],
  vk.ic[2].multiplyUnsafe(GLV_LAMBDA),
];
for (let group = 0; group < VKXGLV_SPLIT_GROUPS; group++) {
  const scale = 1n << BigInt(group * VKXGLV_SPLIT_ITERS);
  for (let mask = 1; mask <= TABLE_ENTRIES; mask++) {
    let expected = G1.ZERO;
    for (let lane = 0; lane < lanePoints.length; lane++) {
      if (mask & (1 << lane)) expected = expected.add(lanePoints[lane].multiplyUnsafe(scale));
    }
    const offset = (group * TABLE_ENTRIES + mask - 1) * TABLE_ENTRY_BYTES;
    const encoded = G1.fromAffine({
      x: fromLe(serializedTable.subarray(offset, offset + 32)),
      y: fromLe(serializedTable.subarray(offset + 32, offset + 64)),
    });
    assert(encoded.equals(expected), `serialized table mismatch at group ${group}, mask ${mask}`);
  }
}
const directMsm = (inputs) => {
  let point = G1.ZERO;
  inputs.forEach((scalar, index) => {
    if (scalar !== 0n) point = point.add(vk.ic[index + 1].multiplyUnsafe(scalar));
  });
  return point;
};
const popcount = (value) => value.toString(2).replaceAll('0', '').length;
let checkedWitnesses = 0;
const checkWitness = (label, scalars) => {
  assert(scalars.length === 4, `${label}: expected four GLV scalars`);
  scalars.forEach((scalar) => {
    assert(scalar >= 0n && scalar < BOUND, `${label}: scalar is out of range`);
  });
  const original = pointFromJacobian(vkxGlvStateAt(...scalars, 128));
  const split = pointFromJacobian(vkxGlvSplitStateAt(...scalars, VKXGLV_SPLIT_ITERS));
  const direct = directMsm(inputsFor(scalars));
  assert(split.equals(original), `${label}: split and original schedules disagree`);
  assert(split.equals(direct), `${label}: split schedule disagrees with direct multiplication`);
  checkedWitnesses++;
};

for (let scalarIndex = 0; scalarIndex < 4; scalarIndex++) {
  for (let bit = 0; bit < 128; bit++) {
    const scalars = [0n, 0n, 0n, 0n];
    scalars[scalarIndex] = 1n << BigInt(bit);
    checkWitness(`basis ${scalarIndex}:${bit}`, scalars);
  }
}

const allOnes = BOUND - 1n;
checkWitness('all-ones bounded witness', [allOnes, allOnes, allOnes, allOnes]);

// Highest union density found in the deterministic 1,000,000-input search used to audit
// the split window floor (122 set positions across the four jointly selected witnesses).
const millionSampleWitness = [
  58869595584251123824260557674473605772n,
  294579931659366149749946767356432579780n,
  258987715660709833546510488003751644954n,
  278774411461145272927829562468311967153n,
];
assert(popcount(millionSampleWitness.reduce((union, scalar) => union | scalar, 0n)) === 122,
  'million-sample witness density changed');
checkWitness('million-sample bounded witness', millionSampleWitness);

let randomState = 0x9e3779b97f4a7c15n;
const next64 = () => {
  randomState ^= randomState << 13n;
  randomState ^= randomState >> 7n;
  randomState ^= randomState << 17n;
  randomState &= MASK64;
  return randomState;
};
const next128 = () => (next64() << 64n) | next64();
const nextCanonical = () => ((next128() << 128n) | next128()) % GLV_R;
for (let sample = 0; sample < 256; sample++) {
  checkWitness(`bounded random ${sample}`, [next128(), next128(), next128(), next128()]);
}

const canonicalCases = [
  [0n, 0n],
  [1n, GLV_R - 1n],
  [GLV_R - 1n, GLV_R - 1n],
  vec.publicInputs.map(BigInt),
];
for (let sample = 0; sample < 256; sample++) {
  canonicalCases.push([nextCanonical(), nextCanonical()]);
}
canonicalCases.forEach(([in0, in1], index) => {
  const scalars = glvDecomposeJoint(in0, in1);
  assert(inputsFor(scalars)[0] === in0 && inputsFor(scalars)[1] === in1,
    `canonical ${index}: joint decomposition does not reconstruct its inputs`);
  const legacy = [...glvDecompose(in0), ...glvDecompose(in1)];
  const jointDensity = popcount(scalars.reduce((union, scalar) => union | scalar, 0n));
  const legacyDensity = popcount(legacy.reduce((union, scalar) => union | scalar, 0n));
  assert(jointDensity <= legacyDensity, `canonical ${index}: joint selection increased additions`);
  checkWitness(`canonical ${index}`, scalars);
});

console.log(`proved ${VKXGLV_SPLIT_GROUPS}x${VKXGLV_SPLIT_ITERS} GLV equivalence for ${checkedWitnesses} bounded witnesses`);
console.log(`verified ${VKXGLV_SPLIT_GROUPS * TABLE_ENTRIES} serialized table entries and the constructive witness bound`);
console.log(`pinned ${defaultCodegen.length} non-split generator forms byte-for-byte`);

import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '../..');
const resourcePath = resolve(process.env.QSPLIT_RESOURCE_PATH ??
  resolve(root, 'qsplit-tail22-final-resource-bytecodes.json'));
const resultPath = resolve(process.env.QSPLIT_RESULT_PATH ??
  resolve(root, 'qsplit-tail22-final-results.json'));
const outputPath = resolve(process.env.QSPLIT_BENCHMARK_VECTOR_PATH ??
  resolve(root, 'qsplit-tail22-benchmark-vectors.json'));

const resourceBytes = readFileSync(resourcePath);
const resource = JSON.parse(resourceBytes);
const results = JSON.parse(readFileSync(resultPath));
const byName = new Map(resource.fixtures.map((fixture) => [fixture.fixture, fixture]));
const required = [
  'committed',
  'proof1',
  'dense',
  'zero',
  'max',
  'msm-identity',
  'b-identity',
  'a-identity',
  'c-identity',
  'all-identity',
];
if (byName.size !== required.length ||
  !required.every((name) => byName.has(name))) {
  throw new Error('resource export does not contain the exact ten-fixture corpus');
}

const committed = byName.get('committed');
if (committed.inputs.length !== 22 ||
  resource.fixtures.some((fixture) => fixture.inputs.length !== committed.inputs.length)) {
  throw new Error('tail-22 transaction shape changed');
}
const lockingSet = JSON.stringify(committed.inputs.map(({ locking }) => locking));
if (resource.fixtures.some((fixture) =>
  JSON.stringify(fixture.inputs.map(({ locking }) => locking)) !== lockingSet)) {
  throw new Error('proof fixtures do not share one locking set');
}
if (resource.fixtures.some((fixture) => fixture.lockingSetSha256 !==
  results.lockingSetSha256)) {
  throw new Error('locking-set hash changed');
}
if (results.lockingSetSha256 !==
  '4cd6f93829da3708513aa61d408c0b2bd4bba851ba31abefaad573b82c1d0284' ||
  !results.strictCurrentBch || results.fixtureCount !== required.length ||
  results.maximumWireBytes !== 89_553 ||
  results.maximumStandardOperationCost !== 70_171_351 ||
  !results.fixtures.every((fixture) => fixture.wholeConsensusVerified &&
    fixture.wholeStandardVerified && fixture.allConsensusInputsAccepted &&
    fixture.allStandardInputsAccepted && fixture.standardRelaySize &&
    fixture.exactOneSatPerByteFee)) {
  throw new Error('certified result summary changed');
}

const toSteps = (fixture) => fixture.inputs.map((input, index) => ({
  label: `input ${index}: ${results.perInputWorst[index].role}`,
  locking: input.locking,
  unlocking: input.unlocking,
}));
const extraNames = required.filter((name) =>
  name !== 'committed' && name !== 'dense');
const tamperUnlocking = (hex) => {
  const script = Buffer.from(hex, 'hex');
  const ranges = [];
  for (let offset = 0; offset < script.length;) {
    const opcode = script[offset];
    offset += 1;
    let length = -1;
    if (opcode >= 0x01 && opcode <= 0x4b) length = opcode;
    else if (opcode === 0x4c) {
      length = script[offset];
      offset += 1;
    } else if (opcode === 0x4d) {
      length = script.readUInt16LE(offset);
      offset += 2;
    } else if (opcode === 0x4e) {
      length = script.readUInt32LE(offset);
      offset += 4;
    } else {
      continue;
    }
    if (length > 0) ranges.push([offset, offset + length]);
    offset += length;
  }
  ranges.sort((left, right) =>
    (right[1] - right[0]) - (left[1] - left[0]));
  const target = ranges[0];
  if (target === undefined) throw new Error('unlocking bytecode has no data push to change');
  script[target[0] + Math.floor((target[1] - target[0]) / 2)] ^= 1;
  return script.toString('hex');
};
const vectors = {
  description:
    'One current-BCH standard transaction containing the complete BLS12-381 Groth16 verifier. ' +
    'The q132 quotient is committed as one logical transcript leaf and carried as an exact ' +
    '110-coefficient head plus 22-coefficient tail. All fixtures use the same 22 P2SH32 lockings.',
  curve: 'BLS12-381',
  deployment: 'single current-BCH standard transaction',
  method: 'two-chart quotient-torus, authenticated public-VK contribution, residue verdict, q132 physical split',
  proofBinding: 'runtime',
  sourcePath: resource.sourcePath,
  sourceSha256: resource.sourceSha256,
  resourceArtifactSha256: createHash('sha256').update(resourceBytes).digest('hex'),
  lockingSetSha256: committed.lockingSetSha256,
  numInputs: committed.inputs.length,
  challengeScore: results.maximumWireBytes + 35 * committed.inputs.length,
  maximumWireBytes: results.maximumWireBytes,
  maximumStandardOperationCost: results.maximumStandardOperationCost,
  steps: toSteps(committed),
  extraValidProofs: extraNames.map((name) => toSteps(byName.get(name))),
  worstCaseProof: toSteps(byName.get('dense')),
  invalid: committed.inputs.map((_, target) => toSteps({
    inputs: committed.inputs.map((input, index) => index === target
      ? { ...input, unlocking: tamperUnlocking(input.unlocking) }
      : input),
  })),
};
const serialized = `${JSON.stringify(vectors, null, 2)}\n`;
writeFileSync(outputPath, serialized);
console.log(JSON.stringify({
  outputPath,
  sha256: createHash('sha256').update(serialized).digest('hex'),
  challengeScore: vectors.challengeScore,
  inputCount: vectors.numInputs,
  invalidRuns: vectors.invalid.length,
  extraValidProofs: vectors.extraValidProofs.length,
}));

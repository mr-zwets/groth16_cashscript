import assert from 'node:assert/strict';
import {readFileSync,writeFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {resolve,join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {program} from './compact.mjs';

assert(process.argv[2], 'usage: node export.mjs /absolute/candidate-benchmark');
const benchmark = resolve(process.argv[2]);
const source = fileURLToPath(new URL('../../../', import.meta.url));
assert.equal(execFileSync('git', ['-C', source, 'status', '--porcelain'], {encoding: 'utf8'}), '',
  'commit the reviewed source before exporting its exact revision');
const sourceRevision = execFileSync('git', ['-C', source, 'rev-parse', 'HEAD'], {encoding: 'utf8'}).trim();
// accepted baselines: the official vectors (3,425-byte leader) or the compact-identifier export
// (3,415 bytes) that the range-checked export replaces; witnesses are identical in both
const files = [
  ['groth16-bls12381-singleton-genpow-vectors.json', ['0c1d47ee3772c3d4bf1cf7c69f5ff1678200cb71dcf4814f9487a9f0c6e059a8', '6bb11665750ee24b383ba4a92eb0d07c82c633b9dd3903e7f4ca25bc3f1196f0']],
  ['groth16-bls12381-singleton-genpow-multiproof-vectors.json', ['294a5cb74cc3ef8389bfb2738de77d2c830d215dc1b7105396aba316993df3a8', 'e12fe62c2a4d421b7c5b3433e5be3b21e333070e52939e08c0a6b2becab8912e']],
];
const inputs = files.map(([name, hashes]) => {
  const path = join(benchmark, 'src/bch', name);
  const bytes = readFileSync(path);
  const hash = createHash('sha256').update(bytes).digest('hex');
  assert(hashes.includes(hash), `unexpected baseline: ${name}`);
  const {provenance, ...data} = JSON.parse(bytes);
  return {name, path, data, originalSha256: provenance?.baselineVectorSha256 ?? hash};
});
assert.equal(inputs[0].data.lockingOK, inputs[1].data.lockingOK);
assert(['44d79298047a012b2a1d132949f55c1bbd1c803d28197b2e63366eb54614e4c1', 'b982a3db459ec4bbb0a9742b54c2181919881af4d3af24b456e5b5825ba85558']
  .includes(createHash('sha256').update(Buffer.from(inputs[0].data.lockingOK, 'hex')).digest('hex')));
const committed = inputs[1].data.proofs.filter(p => p.committed);
assert.equal(committed.length, 1);
assert.equal(committed[0].unlocking, inputs[0].data.unlocking);
const sourceFiles = Object.fromEntries(['program.mjs', 'field.mjs', 'build.mjs', 'compact.mjs', 'export.mjs']
  .map(name => [name, createHash('sha256').update(readFileSync(new URL(name, import.meta.url))).digest('hex')]));
const provenance = {
  source: 'singleton/bls12-381/leader-recovered/program.mjs', sourceRevision, sourceFiles,
  recoveredProgramSource: true, originalCompilerAndSearchPipelineRecovered: false,
  change: 'function identifiers fieldPrime 1 to 0, fp6Add 17 to 1, fp6Mul 18 to -1; main prefixed with the public-input range check 0 <= n0, n1 < r (compact.mjs)',
  witnessPolicy: 'all supplied witness/public-input data retained byte-for-byte from the pinned official vectors',
  lockingSha256: createHash('sha256').update(program.bytecode).digest('hex'),
};
assert.equal(provenance.lockingSha256, 'b994fd7c4646465636bb88a9ff0f4437bb744758d94fd734b90e2b9429d34e46');
const outputs = inputs.map(input => {
  const data = {...input.data, contract: 'leader-recovered/program.mjs (full genpow, compact function IDs, range-checked public inputs)',
    lockingOK: Buffer.from(program.bytecode).toString('hex'),
    provenance: {...provenance, baselineVectorSha256: input.originalSha256}};
  if (input.data.proofs) assert.deepEqual(data.proofs, input.data.proofs);
  else {
    assert.equal(data.unlocking, input.data.unlocking);
    assert.equal(data.invalidUnlocking, input.data.invalidUnlocking);
  }
  return {...input, bytes: JSON.stringify(data, null, 2) + '\n'};
});
for (const output of outputs) writeFileSync(output.path, output.bytes);
console.log(JSON.stringify({sourceRevision, lockingBytes: program.bytecode.length,
  lockingSha256: provenance.lockingSha256,
  outputs: outputs.map(o => ({file: o.name, sha256: createHash('sha256').update(o.bytes).digest('hex')})),
  witnessBytesChanged: false, originalPipelineRecovered: false}, null, 2));

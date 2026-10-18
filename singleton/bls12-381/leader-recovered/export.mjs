import assert from 'node:assert/strict';
import {readFileSync,writeFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {resolve,join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {inlinedFunctions, outlinedFunction, outlinedOccurrences, outlinedSequence,
  outlinedExtraFunction, outlinedExtraOccurrences,
  outlinedThirdFunction, outlinedThirdOccurrences, outlinedThirdSequence,
  outlinedFourthFunction, outlinedFourthOccurrences, outlinedFourthSequence,
  outlinedStackSequences, program} from './compact.mjs';

const benchmarkArg = process.argv[2];
assert(benchmarkArg, 'usage: node export.mjs /absolute/candidate-benchmark');
const benchmark = resolve(benchmarkArg);
const source = fileURLToPath(new URL('../../../', import.meta.url));
assert.equal(execFileSync('git', ['-C', source, 'status', '--porcelain'], {encoding: 'utf8'}), '',
  'commit the reviewed source before exporting its exact revision');
const sourceRevision = execFileSync('git', ['-C', source, 'rev-parse', 'HEAD'], {encoding: 'utf8'}).trim();
// accepted baselines: the official vectors, compact/SZ/SX/SM/SV/TB/TJ/TR published vectors; witnesses are identical in all
const files = [
  ['groth16-bls12381-singleton-genpow-vectors.json', ['0c1d47ee3772c3d4bf1cf7c69f5ff1678200cb71dcf4814f9487a9f0c6e059a8', '6bb11665750ee24b383ba4a92eb0d07c82c633b9dd3903e7f4ca25bc3f1196f0', '67818aa4189195183d5cb1bd9349f2b746e8aba6d314532343957e07929e2bee', '160ef41128b09c3e6bce23ddf58ae37ea1ec5f53cc8abfae15bf29d29e758023', 'f9fce5647702fe7b514b27acbeca57f1455c4dbc06821d414e7948b0291f14af', '73a70c14b6b90feac414a17f384f12c589811a0fc29de7e45cf1a22030e01431', '8cb68f07b7a7825f415b302989a7376f08d807d2e7c949f722d4f3165154af4b', '0386735950884a07061a2a578570c355f17b38c670bf518f5a3acd741d20544c', '3f832a9db9c796cf4ff45b53edd0761213ba2f07652dc4b086b0dc675b2be88d', 'd821f4201985f530e00b23fef1ff68eb123f30d52946656218da99213d8f8c56', '9564d8c386cf16deef4f18248c8570afcec449bc843e3f34c02f8302df38b450', '072a0a04eb36dce03fccee9f4304ebfb4d9eed0a2ce7bf1be8f9905b5c215b3b']],
  ['groth16-bls12381-singleton-genpow-multiproof-vectors.json', ['294a5cb74cc3ef8389bfb2738de77d2c830d215dc1b7105396aba316993df3a8', 'e12fe62c2a4d421b7c5b3433e5be3b21e333070e52939e08c0a6b2becab8912e', 'a873b017d6ddd3d73c99fe5717f69daa3bb3f9ba68c667108947f1f2d9508cc9', '21566c1a91e359334b405b529994776b666e9f78a51ec670300097fd8a6aef50', '98bf887f43c410759860d66ee8bf2e0c04ba9c5462454301c135127927cf1ab2', '087eaf111cfdd34fb7f9b63788518e383db492ef81a8ee9f46743eb3bc1e55eb', '653f5ec381d19cc0b7d0efc6cab4475e1ca6b137ddc9ea5ac85de2666a425f40', 'd101f4cce8d13f2ec0af13a83b5985b52ab619376724b68cff56a0e1f1cf9d0b', '9d6cd5c900e5bf706e5c664d7c00506b76299231f99a5e5c3959eaaba2c00cb0', '2d6158ab1184af57acf7fb0ed7679e902d87555ccabc87b2f957239e40e17233', 'bb10b05c20113ac775d4283a62c7f3d1b7d19e835342ed94b3f9f659102a648c', 'ddc65f8853eeb33cb3d8b657fb7ddb954a467c4811ee894b208ef10a36e540df']],
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
assert(['44d79298047a012b2a1d132949f55c1bbd1c803d28197b2e63366eb54614e4c1', 'b982a3db459ec4bbb0a9742b54c2181919881af4d3af24b456e5b5825ba85558', 'b994fd7c4646465636bb88a9ff0f4437bb744758d94fd734b90e2b9429d34e46']
  .concat(['24c86240f9b4721d699ae7b76938b0b03bd1b80061d48e52b2374a7a4a5b6d34', 'f765c89b1e98342ab58bdb80eb36b643c972346fe98c11cb36d45bd2242f8eaa', '5863870d053b3ba98bf14798227baaa6d48cbd72084498a6a97b12b3e8af5ccb', 'd0dc12d1b7ac3d50c0ba0b07462ec8b63cf9f813d0107b3c0102f5c81f695118'])
  .concat(['5a3f91a1d952faee50eef13401fcdeb46b2bbe7bd88c15379013cdbade30cad0', '167e1ab1647f8b41b12bcde2cbf17068671192d56a11be68d105254a4a28515a', 'ed8909fd0ed4f6ca058eb0144eac660741bea1e5b55d0f97b6506bfe44212eaf', '85669084e36988ea5e35db6f95e3cc7eb64bd429de38b93f66f29c026eb509f3', '24f462b2345f79354be7ea5aa0ec70deb28282001eb6efe53fd7e955accdf360'])
  .includes(createHash('sha256').update(Buffer.from(inputs[0].data.lockingOK, 'hex')).digest('hex')));
const committed = inputs[1].data.proofs.filter(p => p.committed);
assert.equal(committed.length, 1);
assert.equal(committed[0].unlocking, inputs[0].data.unlocking);
const sourceFiles = Object.fromEntries(['program.mjs', 'field.mjs', 'build.mjs', 'compact.mjs', 'export.mjs']
  .map(name => [name, createHash('sha256').update(readFileSync(new URL(name, import.meta.url))).digest('hex')]));
const provenance = {
  source: 'singleton/bls12-381/leader-recovered/program.mjs', sourceRevision, sourceFiles,
  recoveredProgramSource: true, originalCompilerAndSearchPipelineRecovered: false,
  change: 'function identifiers fieldPrime 1 to 0, fp6Add 17 to 1, fp6Mul 18 to -1; main prefixed with the public-input range check 0 <= n0, n1 < r; SZ-a1 inlines stackSequence33, negFp, inverseFp, fp2Sqr; SM-a2 outlines six two-roll stack sequences into stackSequence52; SV-a2 swaps stackSequence52 and decompressG2 IDs; TB-a3 outlines 41 OP_MUL/CALL fieldPrime/OP_MOD sequences as mulFp and swaps mulFp with fp6Add (1 to 18); TJ-a2 outlines ten OP_7/OP_ROLL/OP_7/OP_ROLL sequences as stackSequence53=-1 and moves fp6Mul to 19; TR-a2 outlines nine OP_6/OP_ROLL/OP_7/OP_ROLL sequences as stackSequence54=14 and moves fp2Scale to 31; TW-a1 through TW-a4 apply four measured static outlines and their scoped ID packing; UE-a1 adds stackSequence59 for four 0x37 two-roll sites; UE-a2 adds stackSequence60 for two guarded g1Add stack sequences; UE-a3 adds stackSequence61 for three fp2Mul/swap/fp2Add sequences; UR-a1 adds stackSequence62=57 at two decompressG2 sites and stackSequence63=58 at two main sites, producing the 3,308-byte candidate with depth 12 (compact.mjs)',
  witnessPolicy: 'all supplied witness/public-input data retained byte-for-byte from the pinned official vectors',
  lockingSha256: createHash('sha256').update(program.bytecode).digest('hex'),
  functionCount: program.declarations.length,
  candidateMode: true,
  inlinedFunctions,
  outlinedFunction,
  outlinedOccurrences,
  outlinedSequence,
  outlinedExtraFunction,
  outlinedExtraOccurrences,
  shortIdSwap: {function: 'fp6Add', before: 1, after: 18, helper: 'mulFp', helperId: 1},
  outlinedThirdFunction,
  outlinedThirdOccurrences,
  outlinedThirdSequence,
  thirdOutlineIdSwap: {function: 'fp6Mul', before: -1, after: 19, helper: 'stackSequence53', helperId: -1},
  outlinedFourthFunction,
  outlinedFourthOccurrences,
  outlinedFourthSequence,
  fourthOutlineIdSwap: {function: 'fp2Scale', before: 14, after: 31, helper: 'stackSequence54', helperId: 14},
  stackOutlines: outlinedStackSequences,
};
assert.equal(provenance.lockingSha256, '3ef0a31623a2322afed809f40ee4245365b8f5f10c86142853408b27edacd4d1');
const outputs = inputs.map(input => {
  const data = {...input.data, contract: 'leader-recovered/program.mjs (full genpow, compact function IDs, range-checked public inputs, SZ-a1 inlining, SM/TB/TJ/TR/TW/UE/UR static outlines and ID packing)',
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
console.log(JSON.stringify({sourceRevision, candidateMode: true, lockingBytes: program.bytecode.length,
  lockingSha256: provenance.lockingSha256,
  outputs: outputs.map(o => ({file: o.name, sha256: createHash('sha256').update(o.bytes).digest('hex')})),
  witnessBytesChanged: false, originalPipelineRecovered: false}, null, 2));

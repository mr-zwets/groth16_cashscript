import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const sourceDir = dirname(fileURLToPath(import.meta.url));
const benchmarkDir = resolve(
  process.argv[2] ?? join(sourceDir, '../../../../benchmark-repo/artifacts/pr6-grouped-affine-reference'),
);

const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const read = name => readFileSync(join(sourceDir, name));
const readJson = name => JSON.parse(read(name));
const hashFile = path => sha256(readFileSync(path));
const hexBytes = (name, expectedBytes) => {
  const text = readFileSync(join(benchmarkDir, name), 'utf8').trim();
  assert.match(text, /^(?:[0-9a-f]{2})+$/i, `${name} must contain only even-length hex`);
  const bytes = Buffer.from(text, 'hex');
  assert.equal(bytes.length, expectedBytes, `${name} byte length`);
  return bytes;
};

const qualification = readJson('qualification.json');
const scope = readJson('mathematical-scope.json');
const artifacts = JSON.parse(readFileSync(join(benchmarkDir, 'artifact-manifest.json')));
const privatePath = new RegExp(String.raw`/(?:Users|private)/`);

const publicFiles = [
  'qualification.json',
  'mathematical-scope.json',
  'exact-repair.patch',
  'repaired-generic-affine-0.cash',
  'repaired-generic-affine-1.cash',
];
for (const name of publicFiles) {
  const text = readFileSync(join(sourceDir, name), 'utf8');
  assert(!privatePath.test(text), `${name} contains a private absolute path`);
}

assert.equal(qualification.source.originalPublishedHead, '0b5b2240cbb2f723a87dce2f43b92fc6f38e4b4d');
assert.equal(qualification.source.patchedGeneratorSha256, 'c80b81a733b302f338a1a5a1b4b6ef2074515979a99eeaef03975527fc58848b');
assert.equal(qualification.source.currentHelperRevision, '76f85727b1b91688b981239d5f7bbcc8cdf66330');
assert.equal(hashFile(resolve(sourceDir, '../gen_vkx_glv.mjs')), qualification.source.currentHelperSha256);
assert.equal(read('exact-repair.patch').length, 1128);
assert.equal(sha256(read('exact-repair.patch')), qualification.source.repairPatch.sha256);

for (const entry of qualification.source.cash) {
  const bytes = read(entry.file);
  assert.equal(bytes.length, entry.bytes, `${entry.file} source size`);
  assert.equal(sha256(bytes), entry.sha256, `${entry.file} source hash`);
}

assert.equal(qualification.compiler.head, '1c707c1dbf87396b30ba5e0704b1db44475ce893');
assert.equal(qualification.compiler.package, 'cashc');
assert.equal(qualification.compiler.version, '0.14.0-next.1');
assert.deepEqual(qualification.compiler.fixedFlags.compileString, { rescheduleStacks: true });
assert.equal(qualification.compiler.fixedFlags.programPrefix, '75');
assert.equal(qualification.compiler.fixedFlags.co8, false);
assert.equal(scope.abi.firstWindow.call, 'spend(bytes inBlob)');
assert.equal(scope.abi.finalWindow.call, 'spend(int zInv, bytes glvTable, bytes inBlob)');
assert.deepEqual(scope.abi.successor, { payloadBytes: 704, coordinateOffset: 384, coordinateBytes: 64 });
assert.equal(scope.fixedParameters.tableSha256, '4dedc6a77ffe1f14a1faa12a533a2975e8d7304c8e740a82d8a5c9c41e490028');

for (const entry of artifacts.programs) {
  const bytes = hexBytes(entry.file, entry.bytes);
  assert.equal(sha256(bytes), entry.sha256, `${entry.file} program hash`);
}
assert.deepEqual(
  artifacts.programs.map(({ sha256 }) => sha256),
  qualification.programs.map(({ sha256 }) => sha256),
);
assert.equal(qualification.proofBoundary.proofBytes, false);
assert.equal(qualification.proofBoundary.witnessBytes, false);
assert.equal(qualification.proofBoundary.archivedVmClaim, false);

console.log(JSON.stringify({
  status: 'PASS_PINNED_GROUPED_AFFINE_REFERENCE',
  source: qualification.source.cash.map(({ file, sha256, bytes }) => ({ file, sha256, bytes })),
  programs: artifacts.programs,
  scope: 'metadata and byte pins only; no theorem, proof, witness, producer, or VM claim',
}));

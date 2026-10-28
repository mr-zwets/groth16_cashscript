import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const sourceDir = dirname(fileURLToPath(import.meta.url));
const argument = name => {
  const prefix = `--${name}=`;
  const value = process.argv.find(item => item.startsWith(prefix));
  return value?.slice(prefix.length);
};
const compilerRootArg = argument('compiler-root');
const benchmarkDir = resolve(argument('benchmark-dir') ?? join(sourceDir, '../../../../benchmark-repo/artifacts/pr6-grouped-affine-reference'));
assert(compilerRootArg, 'usage: node rebuild.mjs --compiler-root=/path/to/cashscript [--benchmark-dir=/path/to/artifacts]');
const compilerRoot = resolve(compilerRootArg);
const compilerHead = execFileSync('git', ['-C', compilerRoot, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
assert.equal(compilerHead, '1c707c1dbf87396b30ba5e0704b1db44475ce893', 'unexpected compiler checkout');
const packageJson = JSON.parse(readFileSync(join(compilerRoot, 'packages/cashc/package.json')));
assert.equal(packageJson.name, 'cashc');
assert.equal(packageJson.version, '0.14.0-next.1');
const compilerEntry = join(compilerRoot, 'packages/cashc/dist/index.js');
const compilerEntrySha256 = sha256(readFileSync(compilerEntry));
const qualification = JSON.parse(readFileSync(join(sourceDir, 'qualification.json')));
assert.equal(compilerEntrySha256, qualification.compiler.entrySha256, 'unexpected compiler entry hash');
const compiler = await import(pathToFileURL(compilerEntry).href);
const cases = [
  ['repaired-generic-affine-0.cash', 'repaired-generic-affine-0.hex', 2244, '976d70be87b1f3f52076eda7cf38e6f53c299480a81c44fc19dec9886d3c521f'],
  ['repaired-generic-affine-1.cash', 'repaired-generic-affine-1.hex', 2179, 'd807841a5ae74baa0347348e53402968b42eb24ec437ed83345007b40980dc3d'],
];
const rows = cases.map(([cash, hex, expectedBytes, expectedHash]) => {
  const source = readFileSync(join(sourceDir, cash), 'utf8');
  const expected = Buffer.from(readFileSync(join(benchmarkDir, hex), 'utf8').trim(), 'hex');
  const compiled = compiler.compileString(source, { rescheduleStacks: true });
  const actual = Buffer.concat([Buffer.from([0x75]), compiler.utils.asmToBytecode(compiled.bytecode)]);
  assert.equal(actual.length, expectedBytes, `${cash} byte length`);
  assert.equal(sha256(actual), expectedHash, `${cash} program hash`);
  assert(actual.equals(expected), `${cash} differs from the pinned program bytes`);
  return { cash, bytes: actual.length, sha256: sha256(actual), byteIdentical: true };
});

console.log(JSON.stringify({
  status: 'PASS_EXACT_PINNED_COMPILER_BYTE_IDENTITY',
  compiler: { head: compilerHead, package: `${packageJson.name}@${packageJson.version}`, entrySha256: compilerEntrySha256 },
  flags: { rescheduleStacks: true, programPrefix: '75' },
  writes: 0,
  rows,
}));

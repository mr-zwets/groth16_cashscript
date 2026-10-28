import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

// This is the reviewed source-local assemble() owner from the candidate-v3
// path, reduced to deterministic DSL -> bytecode projection. It does not
// select variants, generate proofs, build fixtures, or optimize bytecode.
const [benchmarkRepo, artifactDirectory] = process.argv.slice(2);
if (!benchmarkRepo || !artifactDirectory) {
  throw new Error('usage: node local-build.mjs <benchmark-repo> <artifact-directory>');
}

const require = createRequire(resolve(benchmarkRepo, 'package.json'));
const libauthEntry = require.resolve('@bitauth/libauth');
const libauthPackage = require.resolve('@bitauth/libauth/package.json');
const { OpcodesBCH: O, encodeDataPush, bigIntToVmNumber } = await import(pathToFileURL(libauthEntry));
const sha = value => createHash('sha256').update(value).digest('hex');
const sourcePath = new URL('./verifier.asm', import.meta.url);
const sourceBytes = readFileSync(sourcePath);
const source = sourceBytes.toString('utf8');

const constants = {
  P: 21888242871839275222246405745257275088696311157297823662689037894645226208583n,
  BN_X: 4965661367192848881n,
  G2_SUBGROUP_SCALAR: 147946756881789318990833708069417712966n,
};
assert.equal(constants.G2_SUBGROUP_SCALAR, 6n * constants.BN_X ** 2n);
const push = value => Buffer.from(encodeDataPush(value));
const integer = value => push(bigIntToVmNumber(BigInt(value)));

const assemble = assembly => {
  const functions = new Map();
  let main;
  let current;
  for (const [index, raw] of assembly.split('\n').entries()) {
    const line = raw.split('#')[0].trim();
    if (!line) continue;
    const [command, ...args] = line.split(/\s+/);
    const where = `assembly line ${index + 1}`;
    if (command === 'function') {
      assert(!current && !main && args.length === 2, where);
      const [name, encodedId] = args;
      assert(/^[a-z][a-z0-9_]*$/.test(name) && /^\d+$/.test(encodedId), where);
      const id = Number(encodedId);
      assert(Number.isSafeInteger(id) && id <= 255 && !functions.has(name), where);
      assert(![...functions.values()].some(fn => fn.id === id), where);
      current = { id, lines: [] };
      functions.set(name, current);
    } else if (command === 'main') {
      assert(!current && !main && args.length === 0, where);
      main = { lines: [] };
      current = main;
    } else if (command === 'end') {
      assert(current && args.length === 0, where);
      current = undefined;
    } else {
      assert(current, where);
      current.lines.push({ command, args, where });
    }
  }
  assert(main && !current && functions.size > 0, 'complete assembly required');
  const compile = lines => Buffer.concat(lines.flatMap(({ command, args, where }) => {
    if (command === 'call') {
      assert(args.length === 1 && functions.has(args[0]), where);
      return [integer(functions.get(args[0]).id), Buffer.from([O.OP_INVOKE])];
    }
    if (command === 'constant') {
      assert(args.length === 1 && Object.hasOwn(constants, args[0]), where);
      return [integer(constants[args[0]])];
    }
    if (command === 'push') {
      assert(args.length === 1 && /^(?:[0-9a-f]{2})+$/.test(args[0]), where);
      return [push(Buffer.from(args[0], 'hex'))];
    }
    assert(args.length === 0 && /^OP_[A-Z0-9_]+$/.test(command) && Number.isInteger(O[command]), where);
    assert(command === 'OP_0' || (O[command] > O.OP_PUSHDATA_4 && ![O.OP_DEFINE, O.OP_INVOKE].includes(O[command])), where);
    return [Buffer.from([O[command]])];
  }));
  const bodies = [...functions].map(([name, fn]) => ({ name, id: fn.id, bytecode: compile(fn.lines) }));
  const bytecode = Buffer.concat([
    ...bodies.flatMap(fn => [push(fn.bytecode), integer(fn.id), Buffer.from([O.OP_DEFINE])]),
    compile(main.lines),
  ]);
  return { bytecode, bodies };
};

const { bytecode, bodies } = assemble(source);
assert.equal(bytecode.length, 4681);
assert.equal(sha(bytecode), 'dc2b929c5645d3baaac4fb544ba7565bf54c34156532a715053432d4f9913782');
const output = resolve(artifactDirectory);
mkdirSync(output, { recursive: true });
writeFileSync(resolve(output, 'verifier-4681.hex'), `${bytecode.toString('hex')}\n`, { flag: 'wx' });
const qualification = {
  schema: 'source15-full-coordinate-local-rebuild/v1',
  status: 'PASS_DETERMINISTIC_LOCAL_REBUILD_EXACT_4681',
  source: {
    path: 'singleton/bn254/pr15-full-coordinate-reference/verifier.asm',
    bytes: sourceBytes.length,
    sha256: sha(sourceBytes),
    originalSourceRevision: '1e7c52ab3b6af132c3f3f87effd38821828c874d',
  },
  sourceHelper: {
    reviewedOwner: 'singleton/bn254/genpow-reconstructed/build.mjs',
    sha256: 'f64f587523365c6a057263dfc71ccac258c75e22c736599ae8bbdd4677ddad04',
    localBuildSha256: sha(readFileSync(fileURLToPath(import.meta.url))),
  },
  libauth: {
    packageVersion: '3.1.0-next.8',
    packageSha256: sha(readFileSync(libauthPackage)),
    entrySha256: sha(readFileSync(libauthEntry)),
  },
  compiledArtifact: {
    path: 'artifacts/bn254-pr15-full-coordinate-reference/verifier-4681.hex',
    bytes: bytecode.length,
    sha256: sha(bytecode),
    functionCount: bodies.length,
  },
  pairedArtifactDirectory: 'artifacts/bn254-pr15-full-coordinate-reference',
  scope: 'Exact function/call/end DSL projection for the reviewed BN254 full-coordinate candidate. No variant selection, proof generation, fixture production, or optimization.',
};
writeFileSync(resolve(output, 'rebuild-qualification.json'), `${JSON.stringify(qualification, null, 2)}\n`, { flag: 'wx' });
console.log(JSON.stringify({ status: qualification.status, bytes: bytecode.length, sha256: sha(bytecode) }));

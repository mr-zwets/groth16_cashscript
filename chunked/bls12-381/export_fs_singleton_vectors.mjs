// Assemble the zk-verifier-bench vector file for bch-groth16-bls12381-singleton-fs:
// run measure_fs_singleton.mjs once per corpus fixture (FS_EXPORT_VECTORS=1), check
// that every fixture produces the identical proof-independent locking bytecode, and
// write one vectors JSON with the ten valid unlockings, the worst-case run, and the
// committed fixture's twelve changed-field unlockings.
//
//   node chunked/bls12-381/export_fs_singleton_vectors.mjs
//   FS_VECTORS_PATH=... to override the ../verifier/src/bch/ output path.
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '../..');
const measure = resolve(here, 'measure_fs_singleton.mjs');
const outputPath = process.env.FS_VECTORS_PATH ?? resolve(
  root,
  '../verifier/src/bch/groth16-bls12381-singleton-fs-vectors.json',
);
const fixtures = [
  'committed', 'proof1', 'dense', 'zero', 'max',
  'msm-identity', 'b-identity', 'a-identity', 'c-identity', 'all-identity',
];
const expectedRejections = 12;

const runs = fixtures.map((fixture) => {
  process.stderr.write(`  measuring ${fixture}\n`);
  const child = spawnSync(process.execPath, [measure], {
    cwd: root,
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
    env: { ...process.env, FS_EXPORT_VECTORS: '1', RPA_PROOF_FIXTURE: fixture },
  });
  if (child.status !== 0) {
    throw new Error(`${fixture} fs singleton run failed:\n${child.stderr}\n${child.stdout}`);
  }
  const run = JSON.parse(child.stdout);
  if (!run.accepted || !run.rejectionFixtures.every((item) => item.rejected) ||
    run.rejectionFixtures.length !== expectedRejections) {
    throw new Error(`${fixture} did not pass every fs singleton gate`);
  }
  return run;
});

const locking = runs[0].lockingHex;
runs.forEach((run) => {
  if (run.lockingHex !== locking || run.sourceSha256 !== runs[0].sourceSha256) {
    throw new Error(`${run.fixture} produced a different locking bytecode`);
  }
});
const worst = runs.reduce((best, run) => (run.operationCost > best.operationCost ? run : best));
const committed = runs.find((run) => run.fixture === 'committed');

const vectors = {
  construction: 'bch-groth16-bls12381-singleton-fs: single-script qsplit tail-22 ' +
    '(Fiat-Shamir PIT), loosened-VM singleton oracle',
  sourcePath: 'chunked/bls12-381/measure_fs_singleton.mjs',
  sourceSha256: runs[0].sourceSha256,
  compilerRescheduleStacks: runs[0].compilerRescheduleStacks,
  lockingBytes: locking.length / 2,
  maxOperationCost: worst.operationCost,
  lockingOK: locking,
  proofs: runs.map((run) => ({
    fixture: run.fixture,
    publicInputs: run.publicInputs,
    bIdentity: run.bIdentity,
    operationCost: run.operationCost,
    committed: run.fixture === 'committed',
    unlocking: run.unlockingHex,
  })),
  worstCaseProof: { fixture: worst.fixture, unlocking: worst.unlockingHex },
  invalidUnlockings: committed.rejectionFixtures.map(({ name, unlocking }) => ({
    label: name,
    unlocking,
  })),
};
const serialized = `${JSON.stringify(vectors, null, 2)}\n`;
writeFileSync(outputPath, serialized);
console.log(JSON.stringify({
  outputPath,
  sha256: createHash('sha256').update(serialized).digest('hex'),
  lockingBytes: locking.length / 2,
  maxOperationCost: worst.operationCost,
  worstFixture: worst.fixture,
  proofs: vectors.proofs.length,
  invalid: vectors.invalidUnlockings.length,
}, null, 2));

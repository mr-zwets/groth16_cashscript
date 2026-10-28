// Export a frozen successor-lock catalog from an existing positive benchmark
// fixture. This is an artifact adapter only: it does not compile CashScript,
// invoke a prover/builder, or create proof/negative cases.
import { readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join } from 'node:path';
import { binToHex, hexToBin } from '@bitauth/libauth';
import { buildSuccessorLockings } from './successor-lock.mjs';

const [benchmarkDir, outputPath] = process.argv.slice(2);
if (!benchmarkDir || !outputPath || process.argv.length !== 4) {
  throw new Error('usage: node export_successor_catalog.mjs benchmark-dir catalog.json');
}
const fixturePath = join(benchmarkDir, 'src/bch/vkx-bls12381-chunked-covenant-vectors.json');
const fixtureBytes = readFileSync(fixturePath);
const fixture = JSON.parse(fixtureBytes);
const bareLockings = fixture.steps.map(step => hexToBin(step.locking));
const selectedLockings = buildSuccessorLockings(bareLockings);
const catalog = {
  schema: 'bls-vkx-successor-lock-catalog-v1',
  sourceOwner: 'chunked/bls12-381/successor-lock.mjs',
  sourceOwnerSha256: createHash('sha256').update(readFileSync(new URL('./successor-lock.mjs', import.meta.url))).digest('hex'),
  fixture: {
    path: 'src/bch/vkx-bls12381-chunked-covenant-vectors.json',
    originalSha256: createHash('sha256').update(fixtureBytes).digest('hex'),
    bytes: fixtureBytes.length,
    steps: fixture.steps.length,
  },
  selectedLockings: selectedLockings.map(binToHex),
  originalLockings: bareLockings.map(binToHex),
  vmExecutions: 0,
  scope: 'Selected locking bytes only; existing fixture payloads and original unlockings are retained byte-for-byte.',
};
writeFileSync(outputPath, JSON.stringify(catalog, null, 2) + '\n', { flag: 'wx' });

// Static export over pinned, existing positive fixtures. No proof producer or VM.
import assert from 'node:assert/strict';
import {readFileSync, writeFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {join} from 'node:path';
import {decodeAuthenticationInstructions} from '@bitauth/libauth';
import {repairExistingPositives} from './repair.mjs';

const [benchmark, output] = process.argv.slice(2);
assert(benchmark && output && process.argv.length === 4,
  'usage: node chunked/bn254/checked-legacy/export.mjs benchmark-dir new-catalog.json');
const manifest = JSON.parse(readFileSync(new URL('./profiles.json', import.meta.url)));
const ownerFiles = ['guard.mjs', 'repair.mjs', 'profiles.json', 'export.mjs'].map(file => ({
  file, sha256: createHash('sha256').update(readFileSync(new URL(file, import.meta.url))).digest('hex'),
}));
const profiles = manifest.profiles.map(profile => {
  const artifactBytes = readFileSync(join(benchmark, 'src/bch', profile.file));
  const repaired = repairExistingPositives(artifactBytes, profile);
  const original = JSON.parse(artifactBytes).steps;
  return {...profile, ...repaired.catalog,
    originalPrograms: original.map(step => Buffer.from(decodeAuthenticationInstructions(
      Buffer.from(step.unlocking, 'hex')).at(-1).data).toString('hex')),
    originalLockings: original.map(step => step.locking),
  };
});
writeFileSync(output, JSON.stringify({
  schema: 'bn254-legacy-equation-checked-static-code/v1',
  benchmarkBase: manifest.benchmarkBase, ownerFiles, profiles,
  nativeResourceAdmission: 'HOLD',
  qualification: 'The mandatory copied fixed-key checker owns the equation. Legacy auxiliary checks only restrict acceptance. Canonical push-only frames, pinned graph ancestry, field and pairing assumptions remain explicit; no universal completeness, arbitrary-key, native-resource or relay claim.',
}, null, 2) + '\n', {flag: 'wx'});

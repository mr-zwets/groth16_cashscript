// One-command regeneration of the chunked-pairing artifacts (all git-ignored,
// written to ./generated/) and the benchmark vectors.
//
//   node generate.mjs
//
// Steps:
//   1. gen_miller.mjs    -> batched 4-pair Miller chunks (shared fp12Sqr; no combine)
//   2. gen_finalexp.mjs  -> final exponentiation chunks
//   3. gen_vkx.mjs       -> vk_x chunks (worst-case / full-width)
//   4. build_vectors.mjs -> ../../verifier/src/bch/{pairing,groth16,vkx}-chunked-vectors.json
//
// Everything is derived from the committed instance (verifier's
// pairing-vectors.json) via the singleton oracle math, so this is fully
// reproducible. Takes a few minutes (each chunk is sized by measuring real-VM op-cost).
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const run = (script, args = []) => new Promise((resolve, reject) => {
  const p = spawn('node', [join(here, script), ...args], { stdio: 'inherit' });
  p.on('exit', (code) => (code === 0 ? resolve() : reject(new Error(`${script} ${args.join(' ')} exited ${code}`))));
});

console.log('[1/4] generating batched 4-pair Miller chunks...');
await run('gen_miller.mjs');
console.log('[2/4] generating final-exponentiation chunks...');
await run('gen_finalexp.mjs');
console.log('[3/4] generating vk_x chunks (pairing instance)...');
await run('gen_vkx.mjs');
console.log('[4/4] building benchmark vectors (pairing + full groth16)...');
await run('build_vectors.mjs');
console.log('done — generated/ populated, verifier vectors written.');

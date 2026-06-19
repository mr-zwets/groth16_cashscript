// One-command regeneration of the chunked-pairing artifacts (all git-ignored,
// written to ./generated/) and the benchmark vectors.
//
//   node generate.mjs
//
// Steps:
//   1. gen_miller.mjs 0..3   -> generated/miller_pI_NN.cash + manifest_pI.json   (parallel)
//   2. gen_combine.mjs       -> generated/combine.cash + manifest_combine.json
//   3. build_vectors.mjs     -> ../../verifier/src/bch/pairing-chunked-vectors.json
//
// Everything is derived from the committed instance (verifier's
// pairing-vectors.json) via the singleton oracle math, so this is fully
// reproducible. Takes a few minutes (each pair plans ~33 chunks by measuring
// real-VM op-cost; the 4 pairs run concurrently).
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const run = (script, args = []) => new Promise((resolve, reject) => {
  const p = spawn('node', [join(here, script), ...args], { stdio: 'inherit' });
  p.on('exit', (code) => (code === 0 ? resolve() : reject(new Error(`${script} ${args.join(' ')} exited ${code}`))));
});

console.log('[1/3] generating 4 single-pair Miller chains (parallel)...');
await Promise.all([0, 1, 2, 3].map((i) => run('gen_miller.mjs', [String(i)])));
console.log('[2/4] generating combine chunk...');
await run('gen_combine.mjs');
console.log('[3/5] generating final-exponentiation chunks...');
await run('gen_finalexp.mjs');
console.log('[4/5] generating vk_x chunks (pairing instance)...');
await run('gen_vkx.mjs');
console.log('[5/5] building benchmark vectors (pairing + full groth16)...');
await run('build_vectors.mjs');
console.log('done — generated/ populated, verifier vectors written.');

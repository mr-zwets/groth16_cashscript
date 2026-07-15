// One-command regeneration of the chunked-pairing artifacts (all git-ignored,
// written to ./generated/) and the benchmark vectors.
//
//   node generate.mjs
//
// Steps:
//   1. gen_miller.mjs    -> prepared batched Miller chunks (fixed pair folded once)
//   2. gen_finalexp.mjs  -> final exponentiation chunks
//   3. gen_vkx.mjs       -> standalone + full-stage vk_x chunks
//   4. gen_g2check.mjs   -> stage-bound G2 input-validation chunks
//   5. build_vectors.mjs -> ../../verifier/src/bch/{pairing,groth16,vkx}-chunked-vectors.json
//
// Everything is derived from the committed instance (verifier's
// pairing-vectors.json) via the singleton oracle math, so this is fully
// reproducible. Takes a few minutes (each chunk is sized by measuring real-VM op-cost).
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const run = (script, args = [], env = {}) => new Promise((resolve, reject) => {
  const p = spawn('node', [join(here, script), ...args], { stdio: 'inherit', env: { ...process.env, ...env } });
  p.on('exit', (code) => (code === 0 ? resolve() : reject(new Error(`${script} ${args.join(' ')} exited ${code}`))));
});

console.log('[1/5] generating prepared batched Miller chunks...');
await run('gen_miller.mjs', [], { STAGE_BOUND_LAYOUT: '1' });
console.log('[2/5] generating final-exponentiation chunks...');
await run('gen_finalexp.mjs');
console.log('[3/5] generating vk_x chunks (pairing instance)...');
await run('gen_vkx.mjs');
await run('gen_vkx.mjs', ['full']);
console.log('[4/5] generating G2 input-validation (EIP-197 subgroup) chunks...');
await run('gen_g2check.mjs', [], { STAGE_BOUND_LAYOUT: '1', G2_CARRIES_VKX: '1' });
await run('gen_g2check.mjs', [], { STAGE_BOUND_LAYOUT: '1' });
console.log('[5/5] building benchmark vectors (pairing + full groth16)...');
await run('build_vectors.mjs');
console.log('done — generated/ populated, verifier vectors written.');

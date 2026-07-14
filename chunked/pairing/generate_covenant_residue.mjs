// One-command reproduction of the BN254 covenant-residue benchmark vectors.
// Usage:
//   VERIFIER_DIR=/path/to/zk-verifier-bench node chunked/pairing/generate_covenant_residue.mjs
import { spawn } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
if (!process.env.VERIFIER_DIR) throw new Error('VERIFIER_DIR must point to the zk-verifier-bench checkout');

const run = (script, env = {}) => new Promise((resolve, reject) => {
  const child = spawn(process.execPath, [join(here, script)], {
    stdio: 'inherit',
    env: { ...process.env, ...env },
  });
  child.on('error', reject);
  child.on('exit', (code) => code === 0 ? resolve() : reject(new Error(`${script} exited ${code}`)));
});

console.log('[1/4] fast G2 validation (stage-bound)...');
await run('gen_g2check.mjs', { STAGE_BOUND_LAYOUT: '1' });
console.log('[2/4] GLV vk_x (validated-proof bridge)...');
await run('gen_vkx_glv.mjs', {
  STAGE_BOUND_LAYOUT: '1',
  COVENANT_RESIDUE_LAYOUT: '1',
  OP_COST_TARGET: '7680000',
});
console.log('[3/4] fused Miller + terminal residue verdict...');
await run('gen_miller_residue.mjs', {
  STAGE_BOUND_LAYOUT: '1',
  COVENANT_RESIDUE_LAYOUT: '1',
  FUSE_TAIL: '1',
});
console.log('[4/4] assemble, validate, and write benchmark vectors...');
await run('build_vectors_covenant_residue.mjs');
console.log('done');

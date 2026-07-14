// One-command reproduction of the BLS12-381 covenant-residue benchmark vectors.
// Usage:
//   VERIFIER_DIR=/path/to/zk-verifier-bench node chunked/bls12-381/generate_covenant_residue.mjs
import { spawn } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
if (!process.env.VERIFIER_DIR) throw new Error('VERIFIER_DIR must point to the zk-verifier-bench checkout');
const standardEnvironment = {
  BCH_VM: '',
  BYTE_BUDGET: '9700',
  COVENANT_RESIDUE_LAYOUT: '',
  FUSE_FINAL: '0',
  OP_COST_TARGET: '7880000',
  RESCHEDULE: 'on',
  STAGE_BOUND_LAYOUT: '',
  TARGET_UNLOCK: '10000',
};

const run = (script, env = {}) => new Promise((resolve, reject) => {
  const child = spawn(process.execPath, [join(here, script)], {
    stdio: 'inherit',
    env: { ...process.env, ...standardEnvironment, ...env },
  });
  child.on('error', reject);
  child.on('exit', (code) => code === 0 ? resolve() : reject(new Error(`${script} exited ${code}`)));
});

console.log('[1/3] stage-bound fused Miller with input validation...');
await run('gen_miller_residue.mjs', {
  STAGE_BOUND_LAYOUT: '1',
  COVENANT_RESIDUE_LAYOUT: '1',
});
console.log('[2/3] current residue walk and terminal verdict...');
await run('gen_finalexp_residue.mjs', { COVENANT_RESIDUE_LAYOUT: '1' });
console.log('[3/3] assemble, validate, and write benchmark vectors...');
await run('build_vectors_covenant_residue.mjs');
console.log('done');

// One-command reproduction of the BN254 covenant-residue benchmark vectors.
// Usage:
//   VERIFIER_DIR=/path/to/zk-verifier-bench node chunked/pairing/generate_covenant_residue.mjs
import { spawn } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
if (!process.env.VERIFIER_DIR) throw new Error('VERIFIER_DIR must point to the zk-verifier-bench checkout');
const MILLER_TORUS = process.env.MILLER_TORUS === '1';
const torusEnv = {
  STAGE_BOUND_LAYOUT: '1',
  COVENANT_RESIDUE_LAYOUT: '1',
  FUSE_G2_ENDPOINT: '1',
  MILLER_AFFINE_G2: '1',
  MILLER_UNIT_LINES: '1',
  MILLER_TORUS: '1',
  MILLER_LINKED_LAYOUT: '1',
  MILLER_LINKED_CUTS: '38,76,114,153,190,229,267,304,342',
  COVENANT_TOKEN_CHAIN: '1',
  OP_COST_TARGET: '7700000',
  BYTE_BUDGET: '9700',
};

const run = (script, env = {}) => new Promise((resolve, reject) => {
  const child = spawn(process.execPath, [join(here, script)], {
    stdio: 'inherit',
    env: { ...process.env, ...env },
  });
  child.on('error', reject);
  child.on('exit', (code) => code === 0 ? resolve() : reject(new Error(`${script} exited ${code}`)));
});

if (!MILLER_TORUS) {
  console.log('[1/4] fast G2 validation (stage-bound)...');
  await run('gen_g2check.mjs', { STAGE_BOUND_LAYOUT: '1' });
}
console.log(`[${MILLER_TORUS ? '1/8' : '2/4'}] GLV vk_x (proof bridge)...`);
await run('gen_vkx_glv.mjs', {
  STAGE_BOUND_LAYOUT: '1',
  COVENANT_RESIDUE_LAYOUT: '1',
  OP_COST_TARGET: '7680000',
});
console.log(`[${MILLER_TORUS ? '2/8' : '3/4'}] fused Miller + terminal residue verdict...`);
await run('gen_miller_residue.mjs', {
  STAGE_BOUND_LAYOUT: '1',
  COVENANT_RESIDUE_LAYOUT: '1',
  ...(MILLER_TORUS ? torusEnv : { FUSE_TAIL: '1' }),
});
if (MILLER_TORUS) {
  console.log('[3/8] prove affine Miller-step equivalence...');
  await run('prove_miller_affine.mjs', torusEnv);
  console.log('[4/8] prove normalized Miller-line equivalence...');
  await run('prove_miller_unit_lines.mjs', torusEnv);
  console.log('[5/8] prove specialized integer bounds...');
  await run('unit_line_bound_analysis.mjs', torusEnv);
  console.log('[6/8] prove endpoint subgroup equivalence...');
  await run('prove_miller_endpoint_subgroup.mjs', torusEnv);
  console.log('[7/8] prove quotient-torus algebra...');
  await run('prove_miller_torus.mjs', torusEnv);
}
console.log(`[${MILLER_TORUS ? '8/8' : '4/4'}] assemble, validate, and write benchmark vectors...`);
await run('build_vectors_covenant_residue.mjs', { MILLER_TORUS: MILLER_TORUS ? '1' : '0' });
console.log('done');

// One-command reproduction of the BN254 covenant-residue benchmark vectors.
// Usage:
//   VERIFIER_DIR=/path/to/zk-verifier-bench node chunked/pairing/generate_covenant_residue.mjs
import { spawn } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
if (!process.env.VERIFIER_DIR) throw new Error('VERIFIER_DIR must point to the zk-verifier-bench checkout');
const MILLER_TORUS = process.env.MILLER_TORUS === '1';
const stageCount = MILLER_TORUS ? 10 : 4;
const torusEnv = {
  STAGE_BOUND_LAYOUT: '1',
  COVENANT_RESIDUE_LAYOUT: '1',
  FUSE_G2_ENDPOINT: '1',
  MILLER_AFFINE_G2: '1',
  MILLER_UNIT_LINES: '1',
  MILLER_TORUS: '1',
  MILLER_PROJECTIVE_VKX: '0',
  MILLER_NORMALIZED_PROOF_POINTS: '0',
  MILLER_RAW_B_INFINITY: '0',
  MILLER_LINKED_LAYOUT: '1',
  MILLER_LINKED_CUTS: '24,65,106,148,189,232,273,313,348',
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
console.log(`[${MILLER_TORUS ? 1 : 2}/${stageCount}] GLV vk_x (proof bridge)...`);
await run('gen_vkx_glv.mjs', {
  STAGE_BOUND_LAYOUT: '1',
  COVENANT_RESIDUE_LAYOUT: '1',
  COVENANT_TOKEN_CHAIN: MILLER_TORUS ? '1' : '0',
  MILLER_PROJECTIVE_VKX: '0',
  MILLER_NORMALIZED_PROOF_POINTS: '0',
  MILLER_RAW_B_INFINITY: '0',
  OP_COST_TARGET: '7680000',
});
console.log(`[${MILLER_TORUS ? 2 : 3}/${stageCount}] fused Miller + terminal residue verdict...`);
await run('gen_miller_residue.mjs', {
  STAGE_BOUND_LAYOUT: '1',
  COVENANT_RESIDUE_LAYOUT: '1',
  ...(MILLER_TORUS ? torusEnv : { FUSE_TAIL: '1' }),
});
if (MILLER_TORUS) {
  console.log(`[3/${stageCount}] fuse the GLV terminal with the Miller prefix...`);
  await run('gen_vkx_miller_fused.mjs', torusEnv);
  console.log(`[4/${stageCount}] prove affine Miller-step equivalence...`);
  await run('prove_miller_affine.mjs', torusEnv);
  console.log(`[5/${stageCount}] prove and execute raw affine formulas and integer bounds...`);
  await run('prove_miller_affine_raw.mjs', torusEnv);
  await run('../../singleton/bn254/test_affine_kernels.mjs', torusEnv);
  console.log(`[6/${stageCount}] prove normalized Miller-line equivalence...`);
  await run('prove_miller_unit_lines.mjs', torusEnv);
  console.log(`[7/${stageCount}] prove specialized integer bounds...`);
  await run('unit_line_bound_analysis.mjs', torusEnv);
  console.log(`[8/${stageCount}] prove endpoint subgroup equivalence...`);
  await run('prove_miller_endpoint_subgroup.mjs', torusEnv);
  console.log(`[9/${stageCount}] prove quotient-torus algebra...`);
  await run('prove_miller_torus.mjs', torusEnv);
}
console.log(`[${MILLER_TORUS ? 10 : 4}/${stageCount}] assemble, validate, and write benchmark vectors...`);
await run('build_vectors_covenant_residue.mjs', { MILLER_TORUS: MILLER_TORUS ? '1' : '0' });
console.log('done');

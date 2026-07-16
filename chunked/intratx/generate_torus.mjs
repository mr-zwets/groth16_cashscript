// One-command reproduction of the current-BCH BN254 quotient-torus frontier.
//
//   VERIFIER_DIR=/path/to/zk-verifier-bench pnpm vectors:intratx:torus
import { spawn } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
if (!process.env.VERIFIER_DIR) {
  throw new Error('VERIFIER_DIR must point to the zk-verifier-bench checkout');
}
const stageCount = 13;

const torusEnv = {
  FUSE_G2_ENDPOINT: '1',
  MILLER_AFFINE_G2: '1',
  MILLER_UNIT_LINES: '1',
  MILLER_TORUS: '1',
  MILLER_PROJECTIVE_VKX: '1',
  MILLER_NORMALIZED_PROOF_POINTS: '1',
  MILLER_RAW_B_INFINITY: '1',
  STAGE_BOUND_LAYOUT: '1',
  COVENANT_RESIDUE_LAYOUT: '1',
  MILLER_LINKED_LAYOUT: '1',
  MILLER_LINKED_CUTS: '40,78,114,158,200,238,277,316',
  OP_COST_TARGET: '7950000',
  BYTE_BUDGET: '9700',
  RESCHEDULE: 'on',
  INTRATX_BARE: '0',
};
const run = (script) => new Promise((resolve, reject) => {
  const child = spawn(process.execPath, [join(root, script)], {
    cwd: root,
    stdio: 'inherit',
    env: { ...process.env, ...torusEnv },
  });
  child.on('error', reject);
  child.on('exit', (code) => code === 0
    ? resolve()
    : reject(new Error(`${script} exited ${code}`)));
});

console.log(`[1/${stageCount}] generate quotient-torus Miller chunks...`);
await run('chunked/pairing/gen_miller_residue.mjs');
console.log(`[2/${stageCount}] prove grouped 3x43 GLV equivalence...`);
await run('chunked/pairing/prove_vkx_glv_split.mjs');
console.log(`[3/${stageCount}] prove grouped GLV resource bound...`);
await run('chunked/pairing/prove_vkx_glv_resource_bound.mjs');
console.log(`[4/${stageCount}] prove affine Miller-step equivalence...`);
await run('chunked/pairing/prove_miller_affine.mjs');
console.log(`[5/${stageCount}] prove and execute raw affine formulas and integer bounds...`);
await run('chunked/pairing/prove_miller_affine_raw.mjs');
await run('singleton/bn254/test_affine_kernels.mjs');
console.log(`[6/${stageCount}] prove normalized Miller-line equivalence...`);
await run('chunked/pairing/prove_miller_unit_lines.mjs');
console.log(`[7/${stageCount}] prove specialized integer bounds...`);
await run('chunked/pairing/unit_line_bound_analysis.mjs');
console.log(`[8/${stageCount}] check signed fp12 square against the canonical BCH implementation...`);
await run('singleton/bn254/test_fp12sqr_differential.mjs');
console.log(`[9/${stageCount}] prove endpoint subgroup equivalence...`);
await run('chunked/pairing/prove_miller_endpoint_subgroup.mjs');
console.log(`[10/${stageCount}] prove quotient-torus algebra and short signed Frobenius formulas...`);
await run('chunked/pairing/prove_miller_torus.mjs');
console.log(`[11/${stageCount}] prove universal grouped-GLV Y invariant and projective vk_x handoff...`);
await run('chunked/pairing/prove_projective_vkx.mjs');
console.log(`[12/${stageCount}] assemble and verify the whole transaction...`);
await run('chunked/intratx/build_vectors_residue.mjs');
console.log(`[13/${stageCount}] certify the proof-independent BCH relay encoding...`);
await run('chunked/intratx/prove_resource_ceiling.mjs');

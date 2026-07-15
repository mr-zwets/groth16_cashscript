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

const torusEnv = {
  FUSE_G2_ENDPOINT: '1',
  MILLER_AFFINE_G2: '1',
  MILLER_UNIT_LINES: '1',
  MILLER_TORUS: '1',
  STAGE_BOUND_LAYOUT: '1',
  COVENANT_RESIDUE_LAYOUT: '1',
  MILLER_LINKED_LAYOUT: '1',
  MILLER_LINKED_CUTS: '38,76,114,153,190,229,267,304,342',
  OP_COST_TARGET: '7700000',
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

console.log('[1/7] generate quotient-torus Miller chunks...');
await run('chunked/pairing/gen_miller_residue.mjs');
console.log('[2/7] prove affine Miller-step equivalence...');
await run('chunked/pairing/prove_miller_affine.mjs');
console.log('[3/7] prove normalized Miller-line equivalence...');
await run('chunked/pairing/prove_miller_unit_lines.mjs');
console.log('[4/7] prove specialized integer bounds...');
await run('chunked/pairing/unit_line_bound_analysis.mjs');
console.log('[5/7] prove endpoint subgroup equivalence...');
await run('chunked/pairing/prove_miller_endpoint_subgroup.mjs');
console.log('[6/7] prove quotient-torus algebra...');
await run('chunked/pairing/prove_miller_torus.mjs');
console.log('[7/7] assemble and verify the whole transaction...');
await run('chunked/intratx/build_vectors_residue.mjs');

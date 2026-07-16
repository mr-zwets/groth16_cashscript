// One-command reproduction of the ordinary-preparation current-BCH BLS12-381 quotient-torus
// verifier. The fixed verification-key Miller factors remain separate; no setup-scalar relation
// is used to collapse the four-pair equation.
//
//   VERIFIER_DIR=/path/to/zk-verifier-bench pnpm vectors:intratx:torus:bls
import { spawn } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
if (!process.env.VERIFIER_DIR) {
  throw new Error('VERIFIER_DIR must point to the zk-verifier-bench checkout');
}

const torusEnv = {
  BLS_QUOTIENT_TORUS: '1',
  BLS_PIN_LINKED_TORUS: '1',
  BLS_REPLAN_LINKED: '0',
  BCH_VM: '2026',
  RESCHEDULE: 'on',
  INTRATX_BARE: '0',
  TARGET_UNLOCK: '10000',
};
const run = (script, args = []) => new Promise((resolve, reject) => {
  const env = { ...process.env, ...torusEnv };
  delete env.OP_COST_TARGET;
  delete env.BYTE_BUDGET;
  delete env.STAGE_BOUND_LAYOUT;
  delete env.COVENANT_RESIDUE_LAYOUT;
  const child = spawn(process.execPath, [join(root, script), ...args], {
    cwd: root,
    stdio: 'inherit',
    env,
  });
  child.on('error', reject);
  child.on('exit', (code) => code === 0
    ? resolve()
    : reject(new Error(`${script} exited ${code}`)));
});

console.log('[1/4] generate the shared-table GLV stage...');
await run('chunked/bls12-381/gen_vkx_glv.mjs');
console.log('[2/4] plan the linked quotient-torus Miller stage...');
await run('chunked/bls12-381/gen_miller_residue.mjs', ['linked']);
console.log('[3/4] prove the quotient-torus algebra and three complete traces...');
await run('chunked/bls12-381/prove_miller_torus.mjs');
console.log('[4/4] assemble and dual-VM verify the whole transaction...');
await run('chunked/intratx/build_vectors_residue_bls.mjs');

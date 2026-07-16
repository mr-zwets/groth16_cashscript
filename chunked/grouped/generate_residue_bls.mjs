// One-command reproduction of the current-BCH grouped BLS12-381 residue verifier.
//
//   VERIFIER_DIR=/path/to/zk-verifier-bench pnpm vectors:grouped:residue:bls
//   VERIFIER_DIR=/path/to/zk-verifier-bench BLS_QUOTIENT_TORUS=1 pnpm vectors:grouped:residue:bls
import { spawn } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
if (!process.env.VERIFIER_DIR) {
  throw new Error('VERIFIER_DIR must point to the zk-verifier-bench checkout');
}
const quotientTorus = process.env.BLS_QUOTIENT_TORUS === '1';

const reproductionEnvironment = {
  BCH_VM: '2026',
  BLS_QUOTIENT_TORUS: quotientTorus ? '1' : '0',
  BLS_UNIT_G1: '1',
  INTRATX_BARE: '0',
  RESCHEDULE: 'on',
  TARGET_UNLOCK: '10000',
};
const run = (script, args = []) => new Promise((resolve, reject) => {
  const env = { ...process.env, ...reproductionEnvironment };
  delete env.BYTE_BUDGET;
  delete env.COVENANT_RESIDUE_LAYOUT;
  delete env.OP_COST_TARGET;
  delete env.STAGE_BOUND_LAYOUT;
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

console.log('generate the linked identity-complete Miller stage...');
await run('chunked/bls12-381/gen_miller_residue.mjs', ['linked']);
if (!quotientTorus) {
  console.log('generate the linked Fp6 residue verdict...');
  await run('chunked/bls12-381/gen_finalexp_residue.mjs', ['linked']);
}
console.log('prove the half-normalized Miller algebra and identity units...');
await run('chunked/bls12-381/prove_miller_unit_lines.mjs');
if (quotientTorus) {
  console.log('prove the quotient-torus algebra and complete traces...');
  await run('chunked/bls12-381/prove_miller_torus.mjs');
}
console.log('prove the lazy-integer bounds for both Miller line paths...');
await run('singleton/bls12-381/bound_analysis.mjs');
console.log('assemble and dual-VM verify the grouped verifier...');
await run('chunked/grouped/build_vectors_residue_bls.mjs');
console.log('done');

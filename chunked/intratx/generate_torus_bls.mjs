// One-command reproduction of the fixed-VK BLS12-381 quotient-torus verifier in one
// current-BCH consensus-valid and standard-policy transaction.
//
//   VERIFIER_DIR=/path/to/zk-verifier-bench pnpm vectors:intratx:torus:bls
import { execFileSync, spawn } from 'node:child_process';
import { realpathSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const expectedCompilerRevision = '1c707c1dbf87396b30ba5e0704b1db44475ce893';
const compilerPackageDirectory = dirname(realpathSync(fileURLToPath(import.meta.resolve('cashc'))));
const compilerRoot = execFileSync(
  'git', ['-C', compilerPackageDirectory, 'rev-parse', '--show-toplevel'], { encoding: 'utf8' },
).trim();
const compilerRevision = execFileSync(
  'git', ['-C', compilerRoot, 'rev-parse', 'HEAD'], { encoding: 'utf8' },
).trim();
if (compilerRevision !== expectedCompilerRevision) {
  throw new Error(`cashc revision ${compilerRevision} does not match ${expectedCompilerRevision}`);
}
const compilerChanges = execFileSync(
  'git', ['-C', compilerRoot, 'status', '--porcelain', '--untracked-files=no'], { encoding: 'utf8' },
).trim();
if (compilerChanges !== '') throw new Error('cashc worktree must be clean for byte-exact reproduction');
if (!process.env.VERIFIER_DIR) {
  throw new Error('VERIFIER_DIR must point to the zk-verifier-bench checkout');
}
console.log('rebuilding the pinned CashScript compiler...');
for (const packageName of ['utils', 'cashc']) {
  execFileSync('yarn', ['--cwd', join(compilerRoot, 'packages', packageName), 'build'], {
    cwd: compilerRoot,
    stdio: 'inherit',
  });
}

const reproductionEnvironment = {
  BCH_VM: '2026',
  BLS_UNIT_G1: '1',
  BLS_FIXED_VK_COLLAPSE: '1',
  BLS_FIXED_COMB_WIDTH: '6',
  BLS_AFFINE_G2: '1',
  BLS_QUOTIENT_TORUS: '1',
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

console.log('[1/6] generate the collapsed quotient-torus Miller stage...');
await run('chunked/bls12-381/gen_miller_residue.mjs', ['linked']);
console.log('[2/6] prove the quotient-torus algebra and complete traces...');
await run('chunked/bls12-381/prove_miller_torus.mjs');
console.log('[3/6] prove the half-normalized line algebra and identity cases...');
await run('chunked/bls12-381/prove_miller_unit_lines.mjs');
console.log('[4/6] prove the lazy-integer bounds for both Miller line paths...');
await run('singleton/bls12-381/bound_analysis.mjs');
console.log('[5/6] assemble and dual-VM verify the whole transaction...');
await run('chunked/intratx/build_vectors_residue_bls.mjs');
console.log('[6/6] certify proof-independent one-transaction resource bounds...');
await run('chunked/bls12-381/prove_resource_bounds.mjs');
console.log('done');

// Deterministically sweep linked BN254 Miller cut targets against every fixture enforced by
// build_vectors_residue.mjs. The lowest-byte passing target is regenerated last, so generated/
// and the benchmark vector are left in the selected state.
//
//   VERIFIER_DIR=/path/to/zk-verifier-bench node chunked/pairing/sweep_miller_residue.mjs
//   VERIFIER_DIR=/path/to/zk-verifier-bench node chunked/pairing/sweep_miller_residue.mjs 7800000 7900000
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const verifierDir = process.env.VERIFIER_DIR;
if (!verifierDir) throw new Error('VERIFIER_DIR must point to the zk-verifier-bench checkout');

const requestedTargets = process.argv.slice(2).map(Number);
const targets = requestedTargets.length > 0 ? requestedTargets : [7_700_000, 7_800_000, 7_900_000, 7_950_000];
if (targets.some((target) => !Number.isInteger(target) || target <= 0)) {
  throw new Error('cut targets must be positive integers');
}

const run = (script, extraEnv = {}) => spawnSync(process.execPath, [script], {
  cwd: root,
  env: { ...process.env, VERIFIER_DIR: verifierDir, ...extraEnv },
  encoding: 'utf8',
  maxBuffer: 64 * 1024 * 1024,
});
const requireSuccess = (result, label) => {
  if (result.status !== 0) {
    throw new Error(`${label} failed:\n${result.stderr || result.stdout}`);
  }
  return result.stderr;
};
const parseReport = (output, fixture) => {
  const match = output.match(new RegExp(
    `groth16-intratx-residue ${fixture}: (\\d+) inputs, accepted=true fits=true \\| ` +
    'totalBytes=([\\d,]+) totalOp=([\\d,]+) maxOp=([\\d,]+)',
  ));
  if (!match) throw new Error(`missing passing ${fixture} report`);
  return {
    inputs: Number(match[1]),
    bytes: Number(match[2].replaceAll(',', '')),
    operationCost: Number(match[3].replaceAll(',', '')),
    maxStepOperationCost: Number(match[4].replaceAll(',', '')),
  };
};

requireSuccess(run('chunked/pairing/gen_g2check.mjs', {
  STAGE_BOUND_LAYOUT: '1',
  G2_LINKED_LAYOUT: '1',
}), 'G2 generation');

const candidates = [];
for (const target of targets) {
  const generation = run('chunked/pairing/gen_miller_residue.mjs', {
    STAGE_BOUND_LAYOUT: '1',
    MILLER_LINKED_LAYOUT: '1',
    MILLER_LINKED_CUTS: 'auto',
    OP_COST_TARGET: String(target),
  });
  if (generation.status !== 0) {
    candidates.push({ target, passed: false, error: generation.stderr || generation.stdout });
    continue;
  }

  const manifest = JSON.parse(readFileSync(join(root, 'chunked', 'pairing', 'generated', 'manifest_millerres.json'), 'utf8'));
  const build = run('chunked/intratx/build_vectors_residue.mjs');
  if (build.status !== 0) {
    candidates.push({
      target,
      passed: false,
      millerInputs: manifest.numChunks,
      cuts: manifest.chunks.slice(0, -1).map((chunk) => chunk.opHi),
      error: build.stderr || build.stdout,
    });
    continue;
  }

  candidates.push({
    target,
    passed: true,
    millerInputs: manifest.numChunks,
    cuts: manifest.chunks.slice(0, -1).map((chunk) => chunk.opHi),
    committed: parseReport(build.stderr, 'committed'),
    proof1: parseReport(build.stderr, 'proof#1'),
    dense: parseReport(build.stderr, 'worst-case'),
  });
}

const passing = candidates.filter((candidate) => candidate.passed);
passing.sort((a, b) =>
  a.committed.bytes - b.committed.bytes ||
  a.committed.operationCost - b.committed.operationCost ||
  a.target - b.target);
if (passing.length === 0) {
  console.log(JSON.stringify({ candidates, selected: null }, null, 2));
  throw new Error('no linked Miller cut target passed every fixture');
}

const selected = passing[0];
requireSuccess(run('chunked/pairing/gen_miller_residue.mjs', {
  STAGE_BOUND_LAYOUT: '1',
  MILLER_LINKED_LAYOUT: '1',
  MILLER_LINKED_CUTS: 'auto',
  OP_COST_TARGET: String(selected.target),
}), 'selected Miller generation');
requireSuccess(run('chunked/intratx/build_vectors_residue.mjs'), 'selected vector build');

console.log(JSON.stringify({ candidates, selected }, null, 2));

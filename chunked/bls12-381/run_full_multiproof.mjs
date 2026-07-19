import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '../..');
const measure = resolve(here, 'measure_d3_two_chart_binary.mjs');
const cache = process.env.RPA_GT_CACHE ?? resolve(
  root,
  'bls-gt-merkle-w8-position-regular-flat-v1.json',
);
const resultPath = process.env.RPA_CORPUS_RESULT ?? resolve(
  root,
  'q132-q-split-template-extra-full-results.json',
);
const resourceExportPath = process.env.RPA_RESOURCE_EXPORT === undefined
  ? null
  : resolve(process.env.RPA_RESOURCE_EXPORT);
const expectedInputCount = 22;
const fixtures = (process.env.RPA_CORPUS ??
  'committed,proof1,dense,zero,max,msm-identity,b-identity,a-identity,c-identity,all-identity')
  .split(',')
  .map((name) => name.trim())
  .filter((name) => name.length > 0);
const regularDensityPadding = process.env.RPA_REGULAR_DENSITY_PADDING ?? JSON.stringify({
  3: 60,
  5: 36,
  6: 41,
  7: 49,
  8: 31,
  9: 39,
  10: 41,
  11: 49,
  12: 41,
  13: 49,
  14: 50,
  16: 26,
  17: 46,
  18: 47,
  19: 55,
});
const coordinatorDensityPadding = process.env.RPA_COORDINATOR_DENSITY_PADDING ?? '129';
const picBlock2DensityPadding = process.env.RPA_PIC_BLOCK2_DENSITY_PADDING ?? '116';
const picBlock4DensityPadding = process.env.RPA_PIC_BLOCK4_DENSITY_PADDING ?? '40';
const templateFactorDensityPadding =
  process.env.RPA_TEMPLATE_FACTOR_DENSITY_PADDING ?? '0';
const templateTailDensityPadding =
  process.env.RPA_TEMPLATE_TAIL_DENSITY_PADDING ?? '41';
const quotientTailCoefficients = process.env.RPA_Q_TAIL_COEFFICIENTS ?? '22';
const requiredFixtures = [
  'committed',
  'proof1',
  'dense',
  'zero',
  'max',
  'msm-identity',
  'b-identity',
  'a-identity',
  'c-identity',
  'all-identity',
];
if (fixtures.length !== requiredFixtures.length || new Set(fixtures).size !== fixtures.length ||
  !requiredFixtures.every((name) => fixtures.includes(name))) {
  throw new Error('the exact ten-fixture full-proof corpus is required');
}
const requiredRejectionFixtures = [
  'changed-template-common-helper-byte',
  'changed-template-extra-helper-byte',
  'changed-template-common-slice-start',
  'changed-template-common-slice-end',
  'changed-template-common-function-id',
  'changed-template-common-loader-source-input',
  'changed-template-extra-slice-start',
  'changed-template-extra-slice-end',
  'changed-template-extra-function-id',
  'changed-template-extra-loader-source-input',
  'changed-fixed-width-sibling-locking',
  'changed-fixed-width-sibling-locking-length',
  'changed-authenticated-PIC-path',
  'changed-public-input',
  'changed-proof-A-unit',
  'changed-proof-B-coordinate',
  'changed-B-identity-flag',
  'changed-proof-C-unit',
  'changed-evaluation-recurrence',
  'changed-split-payload-old-root',
  'nonzero-chart-1-split-U',
  'out-of-domain-split-flag',
  'changed-block15-split-payload-old-root',
  'nonzero-chart-1-block15-split-U',
  'out-of-domain-block15-split-flag',
  'changed-q132-coefficient-old-root',
  'changed-q132-root-old-alpha',
  'changed-q132-push-order',
  'truncated-q132-payload',
  'changed-q132-tail-chunk-old-root',
  'truncated-q132-tail-chunk',
  'swapped-q132-physical-chunks',
  'cross-carrier-q132-boundary-shift',
];
if (new Set(requiredRejectionFixtures).size !== requiredRejectionFixtures.length) {
  throw new Error('required changed-field fixture names are not unique');
}

const runs = fixtures.map((fixture) => {
  const child = spawnSync(process.execPath, [measure], {
    cwd: root,
    encoding: 'utf8',
    maxBuffer: 32 * 1024 * 1024,
    env: {
      ...process.env,
      RPA_INVERSES: 'off',
      RPA_SKIP_GAMMA: '1',
      RPA_PIC32: '1',
      RPA_GT_CACHE: cache,
      RPA_PIC_LAYOUT: 'regular',
      RPA_TEMPLATE_RUN: '1',
      RPA_EXPORT_RESOURCE_BYTECODES: resourceExportPath === null ? '0' : '1',
      RPA_COORDINATOR_DENSITY_PADDING: coordinatorDensityPadding,
      RPA_PIC_BLOCK2_DENSITY_PADDING: picBlock2DensityPadding,
      RPA_PIC_BLOCK4_DENSITY_PADDING: picBlock4DensityPadding,
      RPA_TEMPLATE_FACTOR_DENSITY_PADDING: templateFactorDensityPadding,
      RPA_TEMPLATE_TAIL_DENSITY_PADDING: templateTailDensityPadding,
      RPA_Q_TAIL_COEFFICIENTS: quotientTailCoefficients,
      RPA_REGULAR_DENSITY_PADDING: regularDensityPadding,
      RPA_PROOF_FIXTURE: fixture,
    },
  });
  if (child.status !== 0) {
    throw new Error(`${fixture} full-proof run failed:\n${child.stderr}\n${child.stdout}`);
  }
  const run = JSON.parse(child.stdout);
  const valid = run.completeVerifier && run.densityLimitsEnforced &&
    run.allConsensusInputsAccepted && run.allStandardInputsAccepted &&
    run.wholeConsensusVerified && run.wholeStandardVerified &&
    run.standardRelaySize && run.exactOneSatPerByteFee && run.wireBytes <= 100_000;
  if (!valid) throw new Error(`${fixture} did not pass every full-verifier gate`);
  if (run.inputs.length !== expectedInputCount ||
    run.lockingBytecodes.length !== expectedInputCount) {
    throw new Error(`${fixture} transaction shape changed`);
  }
  if (!run.rejectionFixtures.every((item) =>
    item.consensusRejected && item.standardRejected)) {
    throw new Error(`${fixture} did not reject every changed-field fixture`);
  }
  const rejectionNames = run.rejectionFixtures.map(({ name }) => name);
  if (new Set(rejectionNames).size !== rejectionNames.length) {
    throw new Error(`${fixture} reported duplicate changed-field fixtures`);
  }
  if (!requiredRejectionFixtures.every((name) => rejectionNames.includes(name))) {
    throw new Error(`${fixture} is missing a required changed-field fixture`);
  }
  if (resourceExportPath !== null &&
    (run.resourceBytecodes?.inputs.length !== expectedInputCount ||
      run.resourceBytecodes.inputs.some(({ locking, unlocking }) =>
        typeof locking !== 'string' || typeof unlocking !== 'string'))) {
    throw new Error(`${fixture} resource bytecode export is incomplete`);
  }
  return run;
});

const referenceLockings = JSON.stringify(runs[0].lockingBytecodes);
runs.forEach((run) => {
  if (JSON.stringify(run.lockingBytecodes) !== referenceLockings) {
    throw new Error(`${run.fixture} does not use the committed run's ` +
      `${expectedInputCount} locking bytecodes`);
  }
});
if (runs.find(({ fixture }) => fixture === 'proof1').regeneratedWitnesses.proofStatementSha256 ===
  runs.find(({ fixture }) => fixture === 'committed').regeneratedWitnesses.proofStatementSha256) {
  throw new Error('proof1 did not regenerate a distinct proof statement');
}
if (!runs.find(({ fixture }) => fixture === 'b-identity').identities.B) {
  throw new Error('the B-identity fixture did not use semantic B=O');
}

const perInputWorst = runs[0].inputs.map((row, index) => {
  const worstConsensus = runs.reduce((worst, run) =>
    run.inputs[index].consensusOperationCost > worst.operationCost
      ? { fixture: run.fixture, operationCost: run.inputs[index].consensusOperationCost }
      : worst,
  { fixture: runs[0].fixture, operationCost: row.consensusOperationCost });
  const worstStandard = runs.reduce((worst, run) =>
    run.inputs[index].standardOperationCost > worst.operationCost
      ? { fixture: run.fixture, operationCost: run.inputs[index].standardOperationCost }
      : worst,
  { fixture: runs[0].fixture, operationCost: row.standardOperationCost });
  const smallestDensityMargin = runs.reduce((worst, run) =>
    run.inputs[index].densityMargin < worst.margin
      ? { fixture: run.fixture, margin: run.inputs[index].densityMargin }
      : worst,
  { fixture: runs[0].fixture, margin: row.densityMargin });
  return {
    index,
    role: row.role,
    unlockingBytes: row.unlockingBytes,
    redeemBytes: row.redeemBytes,
    worstConsensus,
    worstStandard,
    smallestDensityMargin,
  };
});

const report = {
  construction: 'q132 tail22 physical quotient split and optimized density full10 corpus',
  strictCurrentBch: true,
  fixtureCount: runs.length,
  fixtures: runs.map((run) => ({
    fixture: run.fixture,
    cacheFixture: run.cacheFixture,
    publicInputs: run.publicInputs,
    proofScalars: run.proofScalars,
    identities: run.identities,
    inputCount: run.inputs.length,
    wireBytes: run.wireBytes,
    scriptBytes: run.scriptBytes,
    feeSatoshis: run.feeSatoshis,
    exactOneSatPerByteFee: run.exactOneSatPerByteFee,
    standardRelaySize: run.standardRelaySize,
    allConsensusInputsAccepted: run.allConsensusInputsAccepted,
    allStandardInputsAccepted: run.allStandardInputsAccepted,
    wholeConsensusVerified: run.wholeConsensusVerified,
    wholeStandardVerified: run.wholeStandardVerified,
    consensusOperationCost: run.consensusOperationCost,
    standardOperationCost: run.standardOperationCost,
    maxConsensusInputOperationCost: run.maxConsensusInputOperationCost,
    maxStandardInputOperationCost: run.maxStandardInputOperationCost,
    maxRedeemBytes: run.maxRedeemBytes,
    maxUnlockingBytes: run.maxUnlockingBytes,
    smallestDensityMargin: Math.min(...run.inputs.map((input) => input.densityMargin)),
    witnesses: run.regeneratedWitnesses,
    rejectionFixtures: run.rejectionFixtures,
  })),
  identicalLockingBytecodes: true,
  lockingBytecodeCount: runs[0].lockingBytecodes.length,
  lockingSetSha256: runs[0].lockingSetSha256,
  cacheSha256: runs[0].picAuthentication.cacheSha256,
  cacheGlobalRoot: runs[0].picAuthentication.globalRoot,
  regularDensityPadding: JSON.parse(regularDensityPadding),
  coordinatorDensityPadding: Number(coordinatorDensityPadding),
  picBlock2DensityPadding: Number(picBlock2DensityPadding),
  picBlock4DensityPadding: Number(picBlock4DensityPadding),
  templateFactorDensityPadding: Number(templateFactorDensityPadding),
  templateTailDensityPadding: Number(templateTailDensityPadding),
  quotientTailCoefficients: Number(quotientTailCoefficients),
  maximumWireBytes: Math.max(...runs.map((run) => run.wireBytes)),
  maximumScriptBytes: Math.max(...runs.map((run) => run.scriptBytes)),
  minimumRelayMarginBytes: Math.min(...runs.map((run) => 100_000 - run.wireBytes)),
  minimumDensityMargin: Math.min(...runs.flatMap(
    (run) => run.inputs.map((input) => input.densityMargin),
  )),
  maximumConsensusOperationCost: Math.max(...runs.map((run) => run.consensusOperationCost)),
  maximumStandardOperationCost: Math.max(...runs.map((run) => run.standardOperationCost)),
  maximumConsensusInputOperationCost: Math.max(
    ...runs.map((run) => run.maxConsensusInputOperationCost),
  ),
  maximumStandardInputOperationCost: Math.max(
    ...runs.map((run) => run.maxStandardInputOperationCost),
  ),
  maximumRedeemBytes: Math.max(...runs.map((run) => run.maxRedeemBytes)),
  maximumUnlockingBytes: Math.max(...runs.map((run) => run.maxUnlockingBytes)),
  perInputWorst,
};
const serialized = `${JSON.stringify(report, null, 2)}\n`;
writeFileSync(resultPath, serialized);
let resourceExport = null;
if (resourceExportPath !== null) {
  const sourceBytes = readFileSync(measure);
  const exportReport = {
    construction: 'exact input bytecodes for the q132 two-carrier resource certificate',
    sourcePath: 'chunked/bls12-381/measure_d3_two_chart_binary.mjs',
    sourceSha256: createHash('sha256').update(sourceBytes).digest('hex'),
    fixtures: runs.map((run) => ({
      fixture: run.fixture,
      wireBytes: run.wireBytes,
      lockingSetSha256: run.lockingSetSha256,
      inputs: run.resourceBytecodes.inputs,
    })),
  };
  const exportSerialized = `${JSON.stringify(exportReport, null, 2)}\n`;
  writeFileSync(resourceExportPath, exportSerialized);
  resourceExport = {
    path: resourceExportPath,
    sha256: createHash('sha256').update(exportSerialized).digest('hex'),
    sourceSha256: exportReport.sourceSha256,
  };
}
console.log(JSON.stringify({
  ...report,
  resultPath,
  resultSha256: createHash('sha256').update(serialized).digest('hex'),
  resourceExport,
}, null, 2));

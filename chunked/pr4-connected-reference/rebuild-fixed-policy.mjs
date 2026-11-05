#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve, relative } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const EXPECTED_HEAD = '1c707c1dbf87396b30ba5e0704b1db44475ce893';
const EXPECTED_VERSION = '0.14.0-next.1';
const EXPECTED_PACKAGE_SHA256 = '672de1d16406b72316157d2f3c34eca9e089960f8eeeae2432afd9cb24ea1c48';
const EXPECTED_ENTRY_SHA256 = '2ebf0b95e78a2b7dc12c4778a1ee2fcac258aa3244d9f3a6871d8000b2b3e6fc';
const EXPECTED_COMPILER_MODULE_SHA256 = '5e92acd05a37bea1d71e0a5ae35fe0d79d437229e1ef6e354d94147e7375bd70';
const EXPECTED_IMPLEMENTATION_SHA256 = 'df9c6967b8c2887de44ee6ee9486d804cdc1c1b80e6c733078ff4640c8a7af25';
// Frozen by the existing positive BLS materialization. These four stages were
// compiled with the raw policy; every other stage used stack rescheduling.
const BLS_RAW_INPUTS = new Set([79, 81, 83, 84]);

const arg = (name, fallback) => {
  const index = process.argv.indexOf(name);
  return index < 0 ? fallback : process.argv[index + 1];
};

const sourceRoot = resolve(arg('--source-root', HERE));
const catalogPath = resolve(arg('--catalog', resolve(HERE, '../public-artifact/compiled-catalog.json')));
const compilerRoot = resolve(arg('--compiler-root', resolve(HERE, '../../../../../../../../source/cashscript')));
const receiptPath = resolve(arg('--receipt', resolve(HERE, '../fixed-rebuild.json')));
const compilerPackagePath = resolve(compilerRoot, 'packages/cashc/package.json');
const compilerEntryPath = resolve(compilerRoot, 'packages/cashc/dist/index.js');
const compilerModulePath = resolve(compilerRoot, 'packages/cashc/dist/compiler.js');

const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const sha256File = (path) => sha256(readFileSync(path));
const fail = (message) => { throw new Error(message); };
const git = (...args) => execFileSync('git', ['-C', compilerRoot, ...args], { encoding: 'utf8' }).trim();
const fixedSourcePath = (profile, input) => profile === 'bn254'
  ? `generated-bn-v1/covenant_${String(input).padStart(2, '0')}.cash`
  : `source/chunked/bls12-381/generated-master-equivalence-v1/stage-${String(input).padStart(2, '0')}.cash`;

// All compiler identity checks happen before importing cashc. This prevents a
// changed compiler entry or implementation from participating in the rebuild.
if (git('rev-parse', 'HEAD') !== EXPECTED_HEAD) fail('compiler repository HEAD mismatch');
const packageJsonBytes = readFileSync(compilerPackagePath);
const packageJson = JSON.parse(packageJsonBytes);
if (packageJson.version !== EXPECTED_VERSION) fail('cashc package version mismatch');
if (sha256(packageJsonBytes) !== EXPECTED_PACKAGE_SHA256) fail('cashc package hash mismatch');
if (sha256File(compilerEntryPath) !== EXPECTED_ENTRY_SHA256) fail('cashc entry hash mismatch');
if (sha256File(compilerModulePath) !== EXPECTED_COMPILER_MODULE_SHA256) fail('cashc compiler module hash mismatch');
const implementationListing = git('ls-tree', '-r', '--format=%(objectname) %(path)', `${EXPECTED_HEAD}:packages/cashc/src`);
if (sha256(implementationListing) !== EXPECTED_IMPLEMENTATION_SHA256) fail('cashc implementation hash mismatch');

const { compileFile } = await import(pathToFileURL(compilerEntryPath).href);
const catalog = JSON.parse(readFileSync(catalogPath));
const sourceQualification = JSON.parse(readFileSync(resolve(sourceRoot, 'qualification.json')));
const profiles = Object.entries(catalog.profiles ?? {});
const rows = profiles.flatMap(([profile, value]) => value.programs.map((program) => ({ profile, program })));
const checks = [];
const missingCatalogBindings = [];
const compileFailures = [];

for (const { profile, program } of rows) {
  const sourcePath = (program.sourcePath ?? fixedSourcePath(profile, program.input)).replace(/^public-source\//, '');
  const absoluteSource = resolve(sourceRoot, sourcePath);
  const result = { profile, input: program.input, sourcePath, sourceSha256: false, programSha256: false, abi: null, successor: null };
  try {
    const expectedSourceHash = sourceQualification.sourceFiles[sourcePath];
    if (!expectedSourceHash) fail(`source qualification has no owner for ${sourcePath}`);
    result.sourceSha256 = sha256File(absoluteSource) === expectedSourceHash;
    result.sourceBinding = 'source-qualification-file-hash';
    const compilerVariant = program.compilerVariant ?? (profile === 'bls12-381' && BLS_RAW_INPUTS.has(program.input)
      ? 'raw'
      : 'rescheduleStacks');
    const compileOptions = compilerVariant === 'raw' ? {} : { rescheduleStacks: true };
    const artifact = compileFile(absoluteSource, compileOptions);
    result.compilerVariant = compilerVariant;
    const programHex = artifact.debug?.bytecode;
    result.actualProgramSha256 = typeof programHex === 'string' ? sha256(Buffer.from(programHex, 'hex')) : null;
    result.actualProgramBytes = typeof programHex === 'string' ? programHex.length / 2 : null;
    result.programSha256 = result.actualProgramSha256 === program.programSha256;
    const actualSpendParameters = artifact.abi?.[0]?.inputs?.map(({ type, name }) => `${type} ${name}`) ?? [];
    if (program.spendParameters) {
      const expectedSpendParameters = program.spendParameters.map((parameter) => {
        const tokens = parameter.split(/\s+/);
        return `${tokens[0]} ${tokens[tokens.length - 1]}`;
      });
      result.abi = JSON.stringify(actualSpendParameters) === JSON.stringify(expectedSpendParameters);
    } else if (program.abi) {
      result.abi = JSON.stringify(artifact.abi) === JSON.stringify(program.abi);
    } else {
      result.abi = null;
      missingCatalogBindings.push({ profile, input: program.input, missing: ['abi'] });
    }
    if (program.codec && program.successorLocking) {
      result.successor = program.codec.successor === program.successorLocking;
    } else if (program.codec) {
      result.successor = true;
    } else {
      result.successor = null;
      missingCatalogBindings.push({ profile, input: program.input, missing: ['codec.inNames ABI', 'codec.successor'] });
    }
  } catch (error) {
    compileFailures.push({ profile, input: program.input, sourcePath, error: String(error?.stack ?? error) });
  }
  checks.push(result);
}

for (const [profile, value] of profiles) {
  const programs = value.programs;
  for (let index = 0; index + 1 < programs.length; index += 1) {
    const current = programs[index];
    const next = programs[index + 1];
    if (current.codec) current.codec.successor === next.locking || fail(`${profile} successor locking mismatch at input ${current.input}`);
  }
}

const sourceAndBytecodeMatch = checks.length === 134 && checks.every((check) => check.sourceSha256 && check.programSha256);
const abiMatch = checks.every((check) => check.abi !== false);
const status = compileFailures.length > 0 || !sourceAndBytecodeMatch || !abiMatch
  ? 'FAIL_SOURCE_PROGRAM_OR_ABI_REBUILD'
  : missingCatalogBindings.length > 0
    ? 'HOLD_CATALOG_MISSING_BLS_ABI_AND_SUCCESSOR_BINDINGS'
    : 'PASS_EXACT_FIXED_POLICY_SOURCE_PROGRAM_ABI_SUCCESSOR_REBUILD';

const receipt = {
  schema: 'source4-fixed-policy-rebuild/v1',
  status,
  policy: {
    rescheduleStacks: true,
    frozenPerProgramVariants: { raw: [...BLS_RAW_INPUTS].sort((a, b) => a - b), rescheduleStacks: 130 },
    variants: 2,
    optimizationSelection: false,
    vmExecution: false,
    newProofs: 0,
    negativeCases: 0,
  },
  compiler: {
    repositoryHead: EXPECTED_HEAD,
    packageVersion: packageJson.version,
    packageSha256: EXPECTED_PACKAGE_SHA256,
    entrySha256: EXPECTED_ENTRY_SHA256,
    compilerModuleSha256: EXPECTED_COMPILER_MODULE_SHA256,
    implementationSha256: EXPECTED_IMPLEMENTATION_SHA256,
    checksBeforeImport: true,
  },
  source: { root: relative(dirname(receiptPath), sourceRoot), rows: rows.length, profiles: Object.fromEntries(profiles.map(([name, value]) => [name, value.programs.length])) },
  comparison: { sourceAndBytecodeMatch, abiMatch, checks, missingCatalogBindings, compileFailures },
  catalog: { path: relative(dirname(receiptPath), catalogPath), sha256: sha256File(catalogPath) },
};
writeFileSync(receiptPath, `${JSON.stringify(receipt, null, 2)}\n`, { flag: 'wx' });
console.log(JSON.stringify({ status, rows: rows.length, sourceAndBytecodeMatch, abiMatch, missingCatalogBindings: missingCatalogBindings.length, compileFailures: compileFailures.length }, null, 2));

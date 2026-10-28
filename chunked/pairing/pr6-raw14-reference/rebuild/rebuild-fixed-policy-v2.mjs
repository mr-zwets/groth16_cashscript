#!/usr/bin/env node
// Deterministic source-only rebuild check for the packaged repaired programs.
// It compiles the fixed source files under the pinned opcost/reschedule policy,
// compares bytes/ABIs to the saved catalog, and performs no VM/proof execution.
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

const [publicSourceDir, catalogPath, compilerRoot, outputPath, compilerPinPath] = process.argv.slice(2);
if (!publicSourceDir || !catalogPath || !compilerRoot || !outputPath || !compilerPinPath) throw new Error('usage: rebuild-fixed-policy-v2.mjs PUBLIC_SOURCE_DIR CATALOG COMPILER_ROOT OUTPUT COMPILER_PIN');
const sha = (bytes) => createHash('sha256').update(bytes).digest('hex');
const catalog = JSON.parse(readFileSync(catalogPath, 'utf8'));
const compilerPin = JSON.parse(readFileSync(compilerPinPath, 'utf8'));
const compilerEntry = join(compilerRoot, compilerPin.compilerEntry);
const compilerHead = execFileSync('git', ['-C', compilerRoot, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
if (compilerHead !== compilerPin.compilerHead) throw new Error('compiler head mismatch');
if (!existsSync(compilerEntry) || sha(readFileSync(compilerEntry)) !== compilerPin.compilerEntrySha256) throw new Error('compiler entry hash mismatch');
const C = await import(pathToFileURL(compilerEntry));
const rows = [];
for (let input = 0; input < 14; input += 1) {
  const expected = catalog.programs[input];
  const sourcePath = join(publicSourceDir, 'fixed-programs', 'stage-' + String(input).padStart(2, '0') + '.cash');
  const sourceBytes = readFileSync(sourcePath);
  const artifact = C.compileFile(sourcePath, { optimizeFor: 'opcost', rescheduleStacks: true });
  const body = C.utils.asmToBytecode(artifact.bytecode);
  const bodySha256 = sha(body);
  if (bodySha256 !== expected.programSha256 || body.length !== expected.programBytes) throw new Error(`rebuild mismatch at stage ${input}`);
  const parameters = artifact.abi?.find((entry) => entry.name === 'spend')?.inputs ?? [];
  if (JSON.stringify(parameters) !== JSON.stringify(expected.parameters.map((parameter) => { const parts = parameter.split(' '); return { name: parts.at(-1), type: parts[0] }; }))) throw new Error(`ABI mismatch at stage ${input}`);
  rows.push({ input, sourceBytes: sourceBytes.length, sourceSha256: sha(sourceBytes), compiledBytes: body.length, compiledSha256: bodySha256, compiler: artifact.compiler, abiInputCount: parameters.length });
}
const result = {
  schema: 'source6-raw14-fixed-policy-source-rebuild/v2',
  status: 'PASS_DETERMINISTIC_FIXED_POLICY_SOURCE_REBUILD',
  policy: { optimizeFor: 'opcost', rescheduleStacks: true, compilerExecuted: true, generatorImported: false, vmExecuted: false, proverExecuted: false, newProofGenerated: false, newFixtureGenerated: false, negativeCases: false },
  source: { programCount: rows.length, catalogSha256: sha(readFileSync(catalogPath)), compilerOwner: compilerPin.compilerOwner, compilerEntry: compilerPin.compilerEntry, compilerHead, compilerEntrySha256: compilerPin.compilerEntrySha256 },
  rows,
};
writeFileSync(outputPath, `${JSON.stringify(result, null, 2)}\n`, { flag: 'wx' });

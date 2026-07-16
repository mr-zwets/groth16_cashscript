import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  compileFileBytecode,
  compileFileBytecodeRaw,
  compileFileBytecodeSize,
} from './_millermath.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const generated = join(here, 'generated');
const glvManifest = JSON.parse(readFileSync(join(generated, 'manifest_vkxglv.json'), 'utf8'));
const millerManifest = JSON.parse(readFileSync(join(generated, 'manifest_millerres.json'), 'utf8'));
const glvChunk = glvManifest.chunks.at(-1);
const millerChunk = millerManifest.chunks[0];
if (glvManifest.numChunks !== 4 || glvChunk?.final !== true || glvChunk.hi !== glvManifest.iters ||
    millerManifest.quotientTorus !== true || millerChunk?.opLo !== 0 || millerChunk.opHi <= 0 ||
    millerChunk.final === true || millerChunk.tailFused === true) {
  throw new Error('GLV terminal and Miller prefix manifests are not fusion-compatible');
}
const glvPath = join(generated, `vkxglv_${String(glvChunk.idx).padStart(2, '0')}.cash`);
const millerPath = join(generated, `millerres_${String(millerChunk.idx).padStart(2, '0')}.cash`);
const outputPath = join(generated, 'vkxglv_miller_fused.cash');
const outputManifestPath = join(generated, 'manifest_vkxglv_miller_fused.json');

const parameterName = (parameter) => parameter.split(/\s+/).at(-1);
const replaceNames = (source, names) => Object.entries(names).reduce(
  (result, [from, to]) => result.replace(new RegExp(`\\b${from}\\b`, 'g'), to),
  source,
);

const glv = readFileSync(glvPath, 'utf8');
const miller = readFileSync(millerPath, 'utf8');
const glvLines = glv.trimEnd().split('\n');
const millerLines = miller.trimEnd().split('\n');
const glvSignatureIndex = glvLines.findIndex((line) => line.trimStart().startsWith('function spend('));
if (glvSignatureIndex < 0) throw new Error(`spend function not found in ${glvPath}`);
const glvSignatureMatch = glvLines[glvSignatureIndex].match(/^\s*function spend\((.*)\) \{$/);
if (glvSignatureMatch === null) throw new Error(`unsupported spend signature in ${glvPath}`);
const glvSignature = {
  index: glvSignatureIndex,
  parameters: glvSignatureMatch[1].split(',').map((parameter) => parameter.trim()),
};
const millerSignatureIndex = millerLines.findIndex((line) => line.trimStart().startsWith('function spend('));
if (millerSignatureIndex < 0) throw new Error(`spend function not found in ${millerPath}`);
const millerSignatureMatch = millerLines[millerSignatureIndex].match(/^\s*function spend\((.*)\) \{$/);
if (millerSignatureMatch === null) throw new Error(`unsupported spend signature in ${millerPath}`);
const millerSignature = {
  index: millerSignatureIndex,
  parameters: millerSignatureMatch[1].split(',').map((parameter) => parameter.trim()),
};

const glvContractIndex = glvLines.findIndex((line) => line === 'contract VkxGlvChunk() {');
if (glvContractIndex < 0) throw new Error(`contract declaration not found in ${glvPath}`);
const glvNames = {
  addFp: 'glvAddFp',
  subFp: 'glvSubFp',
  mulFp: 'glvMulFp',
  sqrFp: 'glvSqrFp',
  jacDouble: 'glvJacDouble',
  jacAddAffine: 'glvJacAddAffine',
  select16: 'glvSelect16',
};
const glvHelpers = replaceNames(glvLines.slice(2, glvContractIndex).join('\n'), glvNames);
const glvBodyLines = glvLines.slice(glvSignature.index + 1, -2);
const removedGlvOutputLines = glvBodyLines.filter((line) =>
  line.includes('tx.outputs[0].nftCommitment') || line.includes('tx.outputs[0].tokenCategory'));
if (removedGlvOutputLines.length !== 2) throw new Error('expected exactly two GLV handoff checks');
const glvBody = replaceNames(glvBodyLines.filter((line) =>
  !line.includes('tx.outputs[0].nftCommitment') && !line.includes('tx.outputs[0].tokenCategory'))
  .join('\n'), glvNames);

const millerNames = {
  Px0: 'Ax',
  Py0: 'Ay',
  Q0xa: 'millerBxa',
  Q0xb: 'millerBxb',
  Q0ya: 'millerBya',
  Q0yb: 'millerByb',
  Px3: 'Cx',
  Py3: 'Cy',
  Px2: 'vkxX',
  Py2: 'vkxY',
};
const derivedMillerParameters = new Set([...Object.keys(millerNames), 'bInfinityFlag']);
const millerParameters = millerSignature.parameters.filter((parameter) => {
  const name = parameterName(parameter);
  return name !== 'zeroPadding' && !derivedMillerParameters.has(name);
});
const millerBodyLines = millerLines.slice(millerSignature.index + 1, -2);
const removedMillerInputLines = millerBodyLines.filter((line) =>
  line.includes('tx.inputs[this.activeInputIndex].nftCommitment'));
if (removedMillerInputLines.length !== 1) throw new Error('expected exactly one Miller handoff check');
const millerBody = replaceNames(millerBodyLines.filter((line) =>
  !line.includes('tx.inputs[this.activeInputIndex].nftCommitment'))
  .join('\n'), millerNames);
const glvParameters = glvSignature.parameters.filter((parameter) => parameterName(parameter) !== 'zeroPadding');
const fusedParameters = [...glvParameters, ...millerParameters];
const fusedParameterNames = fusedParameters.map(parameterName);
if (new Set(fusedParameterNames).size !== fusedParameterNames.length ||
    [...derivedMillerParameters].some((name) => !millerSignature.parameters.some((parameter) => parameterName(parameter) === name)) ||
    Object.keys(millerNames).some((name) => new RegExp(`\\b${name}\\b`).test(millerBody))) {
  throw new Error('fused GLV/Miller parameter mapping is incomplete or ambiguous');
}

const source = `pragma cashscript ^0.14.0;
import "../../../singleton/bn254/lib/lazy/Bn254LazyG.cash";
// Fused GLV terminal [${glvChunk.lo},${glvChunk.hi}) and quotient-torus Miller prefix [${millerChunk.opLo},${millerChunk.opHi}).
${glvHelpers}
contract VkxGlvMillerFusedChunk() {
    function spend(${[...fusedParameters, 'bytes unused zeroPadding'].join(', ')}) {
${glvBody}
${millerBody}
    }
}
`;
writeFileSync(outputPath, source);

const variants = [
  ['opcost', compileFileBytecode(outputPath)],
  ['size', compileFileBytecodeSize(outputPath)],
  ['raw', compileFileBytecodeRaw(outputPath)],
];
writeFileSync(outputManifestPath, JSON.stringify({
  glvChunk: { idx: glvChunk.idx, lo: glvChunk.lo, hi: glvChunk.hi },
  millerChunk: { idx: millerChunk.idx, opLo: millerChunk.opLo, opHi: millerChunk.opHi },
  glvArgumentCount: glvParameters.length,
  millerWitnessCount: millerParameters.length,
  parameterNames: fusedParameterNames,
  compilerVariants: Object.fromEntries(variants.map(([name, bytecode]) => [name, bytecode.length])),
}, null, 2));
console.error(`fused GLV/Miller contract: ${variants.map(([name, bytecode]) => `${name}=${bytecode.length}B`).join(' ')}`);

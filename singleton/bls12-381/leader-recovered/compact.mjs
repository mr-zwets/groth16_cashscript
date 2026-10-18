import assert from 'node:assert/strict';
import {writeFileSync} from 'node:fs';
import {pathToFileURL} from 'node:url';
import {createHash} from 'node:crypto';
import {encodeDataPush, bigIntToVmNumber, OpcodesBCH} from '@bitauth/libauth';
import {functions, main} from './program.mjs';
import {assemble, build} from './build.mjs';

// Function identifiers are raw byte keys. Empty and 0x81 identifiers have the
// single-byte OP_0 and OP_1NEGATE encodings. The published compact map is retained except for the reviewed two-ID reassignment.
export const identifiers = new Map(functions.map(f => [f.name, f.originalId]));
identifiers.set('fieldPrime', 0);
identifiers.set('fp6Add', 1);
identifiers.set('fp6Mul', -1);
// Public inputs must be canonical scalars, 0 <= n < r (n1 is push 0, n0 push 1: depths 9, 8).
// Without this n + r gives the same vk_x, so one proof verifies two claimed integers.
// r = x^4 - x^2 + 1: curveSeedAndScalarMinusOne leaves [x, x^4 - x^2].
export const rangeCheck = `
    OP_9 OP_PICK OP_9 OP_PICK OP_2DUP OP_MIN OP_0 OP_GREATERTHANOREQUAL OP_VERIFY
    OP_MAX CALL curveSeedAndScalarMinusOne OP_NIP OP_1ADD OP_LESSTHAN OP_VERIFY
`;
// the program without the check is the 3,415-byte compact-identifier program
const unchecked = build(identifiers);
assert.equal(unchecked.bytecode.length, 3415);
assert.equal(createHash('sha256').update(unchecked.bytecode).digest('hex'), 'b982a3db459ec4bbb0a9742b54c2181919881af4d3af24b456e5b5825ba85558');
export const baselineProgram = build(identifiers, rangeCheck);
const {bytecode} = baselineProgram;
const sha256 = createHash('sha256').update(bytecode).digest('hex');
const mainStart = unchecked.bytecode.length - unchecked.mainBytecode.length;
assert.deepEqual(Buffer.from(bytecode.subarray(0, mainStart)), Buffer.from(unchecked.bytecode.subarray(0, mainStart)), 'declarations unchanged');
assert.deepEqual(Buffer.from(bytecode.subarray(bytecode.length - unchecked.mainBytecode.length)), Buffer.from(unchecked.mainBytecode), 'main unchanged after the prefix');

// SZ-a1: inline helpers whose body expansion beats their declaration and call-site overhead.
// The recovered program.mjs remains the semantic source owner; this stage derives the candidate
// from its symbolic bodies and preserves the exact range-check prefix above. fp2Sqr's identifier
// is reassigned to decompressG2 after inlining; every other retained binding is unchanged.
export const inlinedFunctions = ['stackSequence33', 'negFp', 'inverseFp', 'fp2Sqr'];
const inlineSet = new Set(inlinedFunctions);
const bodies = new Map(functions.map(f => [f.name, f.body]));
const replaceInlineCalls = text => {
  let output = text;
  for (const name of inlinedFunctions) output = output.replaceAll(`CALL ${name}`, bodies.get(name));
  return output;
};
const retainedFunctions = functions.filter(f => !inlineSet.has(f.name));
// Derive the candidate namespace from retained functions, then apply the reviewed two-ID
// reassignment: the outlined helper takes 7 and decompressG2 takes 17.
export const candidateIdentifiers = new Map(retainedFunctions.map(f => [f.name, identifiers.get(f.name)]));
candidateIdentifiers.set('decompressG2', 17);
assert.equal(candidateIdentifiers.size, retainedFunctions.length);
assert.equal(new Set([...candidateIdentifiers.values()].map(value =>
  Buffer.from(bigIntToVmNumber(BigInt(value))).toString('hex'))).size, retainedFunctions.length);
// SM-a2: outline one repeated straight-line stack move. SV-a2 then swaps its raw
// identifier with decompressG2; all function bodies, calls, guards, and values remain fixed.
const outlinedName = 'stackSequence52';
export const outlinedSequence = 'OP_PUSHBYTES_1 0x11 OP_ROLL OP_PUSHBYTES_1 0x11 OP_ROLL';
const outlinedPattern = /OP_PUSHBYTES_1 0x11\s+OP_ROLL\s+OP_PUSHBYTES_1 0x11\s+OP_ROLL/g;
const outlinedExtraName = 'mulFp';
// TB-a1: outline the repeated straight-line multiply/reduce sequence; TB-a2 assigns
// its 41-call helper the short ID 1 and moves fp6Add to the two-byte ID 18.
export const outlinedExtraSequence = 'OP_MUL CALL fieldPrime OP_MOD';
const outlinedExtraPattern = /OP_MUL\s+CALL fieldPrime\s+OP_MOD/g;
const outlinedTargets = new Set(['towerSequence38', 'millerLoop', 'stackSequence15']);
const outlineCount = text => text.match(outlinedPattern)?.length ?? 0;
const outlineExtraCount = text => text.match(outlinedExtraPattern)?.length ?? 0;
let outlinedTotal = 0;
let outlinedExtraTotal = 0;
const candidateFunctions = retainedFunctions.map(f => {
  const expanded = replaceInlineCalls(f.body);
  const count = outlineCount(expanded);
  if (outlinedTargets.has(f.name)) {
    assert(count === (f.name === 'stackSequence15' ? 3 : f.name === 'millerLoop' ? 2 : 1),
      `unexpected SM-a2 outline count in ${f.name}: ${count}`);
    outlinedTotal += count;
    const withExistingOutline = expanded.replace(outlinedPattern, `CALL ${outlinedName}`);
    outlinedExtraTotal += outlineExtraCount(expanded);
    return {...f, body: withExistingOutline.replace(outlinedExtraPattern, `CALL ${outlinedExtraName}`)};
  }
  assert.equal(count, 0, `unexpected SM-a2 outline occurrence in ${f.name}`);
  const extraCount = outlineExtraCount(expanded);
  if (extraCount > 0) {
    outlinedExtraTotal += extraCount;
    return {...f, body: expanded.replace(outlinedExtraPattern, `CALL ${outlinedExtraName}`)};
  }
  return {...f, body: expanded};
});
candidateIdentifiers.set(outlinedName, 7);
assert.equal(candidateIdentifiers.size, retainedFunctions.length + 1);
assert(!retainedFunctions.some(f => candidateIdentifiers.get(f.name) === 7));
candidateFunctions.push({name: outlinedName, body: outlinedSequence});
// TB-a2: give the 41-call helper the former fp6Add short ID 1 and demote fp6Add to 18.
candidateIdentifiers.set('fp6Add', 18);
candidateIdentifiers.set(outlinedExtraName, 1);
assert.equal(new Set([...candidateIdentifiers.values()].map(value =>
  Buffer.from(bigIntToVmNumber(BigInt(value))).toString('hex'))).size, retainedFunctions.length + 2);
assert.equal(candidateFunctions.length, 48);
candidateFunctions.push({name: outlinedExtraName, body: outlinedExtraSequence});
assert.equal(candidateFunctions.length, 49);
assert.equal(outlinedTotal, 6);
const expandedMain = replaceInlineCalls(main);
const candidateMain = expandedMain.replace(outlinedExtraPattern, `CALL ${outlinedExtraName}`);
outlinedExtraTotal += outlineExtraCount(expandedMain);
assert.equal(outlinedExtraTotal, 41);

// TJ-a2: share ten exact two-roll sequences; its short key comes from fp6Mul.
const outlinedThirdName = 'stackSequence53';
export const outlinedThirdSequence = 'OP_7 OP_ROLL OP_7 OP_ROLL';
const outlinedThirdPattern = /OP_7\s+OP_ROLL\s+OP_7\s+OP_ROLL/g;
const outlinedThirdCounts = new Map([
  ['fp6Add', 3], ['fp6Sub', 3], ['fp6Mul', 1],
  ['towerSequence38', 1], ['millerLoop', 2],
]);
let outlinedThirdTotal = 0;
for (const f of candidateFunctions) {
  const count = f.body.match(outlinedThirdPattern)?.length ?? 0;
  assert.equal(count, outlinedThirdCounts.get(f.name) ?? 0,
    `unexpected TJ-a2 outline count in ${f.name}`);
  outlinedThirdTotal += count;
  f.body = f.body.replace(outlinedThirdPattern, `CALL ${outlinedThirdName}`);
}
assert.equal(candidateMain.match(outlinedThirdPattern)?.length ?? 0, 0,
  'TJ-a2 must preserve the complete main and range guard');
assert.equal(outlinedThirdTotal, 10);
assert.equal(candidateIdentifiers.get('fp6Mul'), -1);
assert(![...candidateIdentifiers.values()].includes(19));
candidateIdentifiers.set('fp6Mul', 19);
candidateIdentifiers.set(outlinedThirdName, -1);
candidateFunctions.push({name: outlinedThirdName, body: outlinedThirdSequence});
assert.equal(candidateIdentifiers.size, 50);
assert.equal(new Set([...candidateIdentifiers.values()].map(value =>
  Buffer.from(bigIntToVmNumber(BigInt(value))).toString('hex'))).size, 50);

const buildCandidate = () => {
  const declarations = candidateFunctions.map(f => ({...f, bytecode: assemble(f.body, candidateIdentifiers)}));
  const mainBytecode = assemble(`${rangeCheck} ${candidateMain}`, candidateIdentifiers);
  const candidateBytecode = Uint8Array.from([
    ...declarations.flatMap(f => [
      ...encodeDataPush(f.bytecode),
      ...encodeDataPush(bigIntToVmNumber(BigInt(candidateIdentifiers.get(f.name)))),
      OpcodesBCH.OP_DEFINE,
    ]),
    ...mainBytecode,
  ]);
  return {bytecode: candidateBytecode, declarations, mainBytecode};
};
export const candidateProgram = buildCandidate();
const candidateSha256 = createHash('sha256').update(candidateProgram.bytecode).digest('hex');
assert.equal(candidateFunctions.length, 50);
assert.equal(candidateProgram.bytecode.length, 3333);
assert.equal(candidateSha256, 'ed8909fd0ed4f6ca058eb0144eac660741bea1e5b55d0f97b6506bfe44212eaf');
assert.equal(candidateFunctions.some(f => inlineSet.has(f.name)), false);
assert.equal(candidateMain.includes('OP_DEFINE'), false);
assert.equal(candidateMain.includes('OP_INVOKE'), false);
export const outlinedFunction = outlinedName;
export const outlinedOccurrences = outlinedTotal;
export const outlinedExtraFunction = outlinedExtraName;
export const outlinedExtraOccurrences = outlinedExtraTotal;
export const outlinedThirdFunction = outlinedThirdName;
export const outlinedThirdOccurrences = outlinedThirdTotal;
// The public source export is the reviewed candidate. baselineProgram remains available for
// byte-for-byte regression checks without making the unoptimized program the default output.
export const program = candidateProgram;
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  assert(process.argv[2], 'usage: node compact.mjs output.json');
  writeFileSync(process.argv[2], JSON.stringify({
    status: 'recovered program with compact identifiers, SZ-a1 inlining, and SM/TB/TJ outlining; gates reported separately',
    identifiers: Object.fromEntries(candidateIdentifiers),
    functionCount: candidateFunctions.length,
    baselineLockingBytes: bytecode.length, baselineLockingSha256: sha256,
    lockingBytes: candidateProgram.bytecode.length, lockingSha256: candidateSha256,
    inlinedFunctions,
    lockingHex: Buffer.from(program.bytecode).toString('hex'),
  }, null, 2) + '\n');
  console.log(JSON.stringify({lockingBytes: candidateProgram.bytecode.length, sha256: candidateSha256}));
}

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
let candidateMain = expandedMain.replace(outlinedExtraPattern, `CALL ${outlinedExtraName}`);
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

// TR-a2: share nine exact six/seven-roll sequences; fp2Scale supplies the short key.
const outlinedFourthName = 'stackSequence54';
export const outlinedFourthSequence = 'OP_6 OP_ROLL OP_7 OP_ROLL';
const outlinedFourthPattern = /OP_6\s+OP_ROLL\s+OP_7\s+OP_ROLL/g;
const outlinedFourthCounts = new Map([
  ['fp6Mul', 2], ['towerSequence37', 2], ['millerLoop', 2],
  ['g1Add', 2], ['stackSequence8', 1],
]);
let outlinedFourthTotal = 0;
for (const f of candidateFunctions) {
  const count = f.body.match(outlinedFourthPattern)?.length ?? 0;
  assert.equal(count, outlinedFourthCounts.get(f.name) ?? 0,
    `unexpected TR-a2 outline count in ${f.name}`);
  outlinedFourthTotal += count;
  f.body = f.body.replace(outlinedFourthPattern, `CALL ${outlinedFourthName}`);
}
assert.equal(candidateMain.match(outlinedFourthPattern)?.length ?? 0, 0,
  'TR-a2 must preserve the complete main and range guard');
assert.equal(outlinedFourthTotal, 9);
assert.equal(candidateIdentifiers.get('fp2Scale'), 14);
assert(![...candidateIdentifiers.values()].includes(31));
candidateIdentifiers.set('fp2Scale', 31);
candidateIdentifiers.set(outlinedFourthName, 14);
candidateFunctions.push({name: outlinedFourthName, body: outlinedFourthSequence});
assert.equal(candidateIdentifiers.size, 51);
assert.equal(new Set([...candidateIdentifiers.values()].map(value =>
  Buffer.from(bigIntToVmNumber(BigInt(value))).toString('hex'))).size, 51);

// TW/UE measured straight-line sequences share one local owner so each transformation checks
// its source counts, ID reassignment and main sites.
const stackOutlines = [];
const outlineStackSequence = ({label, name, sequence, pattern, counts, total, mainCount = 0, demotion, id}) => {
  let occurrences = 0;
  for (const f of candidateFunctions) {
    const count = f.body.match(pattern)?.length ?? 0;
    assert.equal(count, counts.get(f.name) ?? 0,
      `unexpected ${label} outline count in ${f.name}: ${count}`);
    occurrences += count;
    f.body = f.body.replace(pattern, `CALL ${name}`);
  }
  const mainOccurrences = candidateMain.match(pattern)?.length ?? 0;
  assert.equal(mainOccurrences, mainCount, `${label} main occurrence count`);
  candidateMain = candidateMain.replace(pattern, `CALL ${name}`);
  occurrences += mainOccurrences;
  assert.equal(occurrences, total);
  if (demotion) {
    assert.equal(candidateIdentifiers.get(demotion.name), demotion.from);
    assert(![...candidateIdentifiers.values()].includes(demotion.to));
    candidateIdentifiers.set(demotion.name, demotion.to);
  }
  assert(![...candidateIdentifiers.values()].includes(id));
  candidateIdentifiers.set(name, id);
  candidateFunctions.push({name, body: sequence});
  assert.equal(candidateIdentifiers.size, candidateFunctions.length);
  assert.equal(new Set([...candidateIdentifiers.values()].map(value =>
    Buffer.from(bigIntToVmNumber(BigInt(value))).toString('hex'))).size, candidateFunctions.length);
  stackOutlines.push({function: name, occurrences, sequence});
};

outlineStackSequence({
  label: 'TW-a1', name: 'stackSequence55', sequence: 'OP_2SWAP OP_SWAP OP_2ROT OP_SWAP',
  pattern: /OP_2SWAP\s+OP_SWAP\s+OP_2ROT\s+OP_SWAP/g,
  counts: new Map([['fp12Mul', 4], ['towerSequence38', 1], ['millerAccumulate', 1], ['millerLoop', 1]]),
  total: 9, mainCount: 2, demotion: {name: 'stackSequence15', from: 15, to: 33}, id: 15,
});
outlineStackSequence({
  label: 'TW-a2', name: 'stackSequence56', sequence: 'OP_11 OP_PICK OP_11 OP_PICK',
  pattern: /OP_11\s+OP_PICK\s+OP_11\s+OP_PICK/g,
  counts: new Map([['fp6Mul', 2], ['towerSequence37', 2], ['stackSequence29', 3], ['stackSequence45', 1]]),
  total: 8, demotion: {name: 'stackSequence16', from: 16, to: 35}, id: 16,
});
outlineStackSequence({
  label: 'TW-a3', name: 'stackSequence57',
  sequence: 'OP_PUSHBYTES_1 0x17 OP_PICK OP_PUSHBYTES_1 0x17 OP_PICK OP_PUSHBYTES_1 0x17',
  pattern: /OP_PUSHBYTES_1 0x17\s+OP_PICK\s+OP_PUSHBYTES_1 0x17\s+OP_PICK\s+OP_PUSHBYTES_1 0x17/g,
  counts: new Map([['fp12Mul', 2], ['towerSequence38', 1]]), total: 3, id: 52,
});
outlineStackSequence({
  label: 'TW-a4', name: 'stackSequence58', sequence: 'OP_12 OP_ROLL OP_13 OP_ROLL',
  pattern: /OP_12\s+OP_ROLL\s+OP_13\s+OP_ROLL/g,
  counts: new Map([['towerSequence38', 1], ['millerLoop', 5], ['stackSequence10', 1]]),
  total: 8, mainCount: 1, demotion: {name: 'fp2MulXi', from: 13, to: 53}, id: 13,
});
outlineStackSequence({
  label: 'UE-a1', name: 'stackSequence59',
  sequence: 'OP_PUSHBYTES_1 0x37 OP_ROLL OP_PUSHBYTES_1 0x37 OP_ROLL',
  pattern: /OP_PUSHBYTES_1 0x37\s+OP_ROLL\s+OP_PUSHBYTES_1 0x37\s+OP_ROLL/g,
  counts: new Map([['millerLoop', 1], ['stackSequence12', 3]]), total: 4, id: 54,
});
outlineStackSequence({
  label: 'UE-a2', name: 'stackSequence60',
  sequence: 'OP_PICK OP_2ROT OP_SWAP OP_6 OP_ROLL CALL g1Add OP_4 OP_ROLL OP_4 OP_ROLL',
  pattern: /OP_PICK\s+OP_2ROT\s+OP_SWAP\s+OP_6\s+OP_ROLL\s+CALL g1Add\s+OP_4\s+OP_ROLL\s+OP_4\s+OP_ROLL/g,
  counts: new Map(), total: 2, mainCount: 2, id: 55,
});
outlineStackSequence({
  label: 'UE-a3', name: 'stackSequence61',
  sequence: 'CALL fp2Mul OP_SWAP OP_2SWAP OP_SWAP CALL fp2Add',
  pattern: /CALL fp2Mul\s+OP_SWAP\s+OP_2SWAP\s+OP_SWAP\s+CALL fp2Add/g,
  counts: new Map([['fp6Mul', 2], ['stackSequence45', 1]]), total: 3, id: 56,
});
outlineStackSequence({
  label: 'UR-a1', name: 'stackSequence62',
  sequence: 'OP_3 OP_PICK OP_MOD CALL sqrtFp OP_DUP OP_5 OP_ROLL OP_1 OP_NUMEQUAL',
  pattern: /OP_3\s+OP_PICK\s+OP_MOD\s+CALL sqrtFp\s+OP_DUP\s+OP_5\s+OP_ROLL\s+OP_1\s+OP_NUMEQUAL/g,
  counts: new Map([['decompressG2', 2]]), total: 2, id: 57,
});
outlineStackSequence({
  label: 'UR-a1-chain', name: 'stackSequence63',
  sequence: 'OP_ROLL OP_2SWAP OP_SWAP OP_2ROT CALL stackSequence8 CALL stackSequence10 CALL millerAccumulate',
  pattern: /OP_ROLL\s+OP_2SWAP\s+OP_SWAP\s+OP_2ROT\s+CALL stackSequence8\s+CALL stackSequence10\s+CALL millerAccumulate/g,
  counts: new Map(), total: 2, mainCount: 2, id: 58,
});
export const outlinedStackSequences = stackOutlines;

// VO-a1: shift the remaining nonnegative exponent rather than a fixed loop counter.
// The frame [p, r, b, e] maintains r * b^e = a^E (mod p); E=0 returns 1.
// Only the compact body changes; program.mjs retains the recovered baseline.
const powFp = candidateFunctions.find(f => f.name === 'powFp');
assert(powFp, 'missing powFp source owner');
powFp.body = `
  CALL fieldPrime OP_TUCK OP_MOD OP_1 OP_SWAP OP_3 OP_ROLL
  OP_BEGIN
    OP_DUP OP_2 OP_MOD OP_IF
      OP_ROT OP_2 OP_PICK OP_MUL OP_3 OP_PICK OP_MOD OP_ROT OP_ROT
    OP_ENDIF
    OP_SWAP OP_DUP OP_MUL OP_3 OP_PICK OP_MOD OP_SWAP OP_1 OP_RSHIFTNUM
    OP_DUP OP_NOT
  OP_UNTIL
  OP_2DROP OP_NIP
`;

const buildCandidate = (functions, identifiers, main) => {
  const declarations = functions.map(f => ({...f, bytecode: assemble(f.body, identifiers)}));
  const mainBytecode = assemble(`${rangeCheck} ${main}`, identifiers);
  const candidateBytecode = Uint8Array.from([
    ...declarations.flatMap(f => [
      ...encodeDataPush(f.bytecode),
      ...encodeDataPush(bigIntToVmNumber(BigInt(identifiers.get(f.name)))),
      OpcodesBCH.OP_DEFINE,
    ]),
    ...mainBytecode,
  ]);
  return {bytecode: candidateBytecode, declarations, mainBytecode};
};
export const candidateProgram = buildCandidate(candidateFunctions, candidateIdentifiers, candidateMain);
const candidateSha256 = createHash('sha256').update(candidateProgram.bytecode).digest('hex');
assert.equal(candidateFunctions.length, 60);
assert.equal(candidateProgram.bytecode.length, 3295);
assert.equal(candidateSha256, 'c5b4cf41459b7ec2f4c84fef0eb8cba5dfffee09ad03da909c9d31378a9d5ece');
assert.equal(candidateFunctions.some(f => inlineSet.has(f.name)), false);
assert.equal(candidateMain.includes('OP_DEFINE'), false);
assert.equal(candidateMain.includes('OP_INVOKE'), false);
export const outlinedFunction = outlinedName;
export const outlinedOccurrences = outlinedTotal;
export const outlinedExtraFunction = outlinedExtraName;
export const outlinedExtraOccurrences = outlinedExtraTotal;
export const outlinedThirdFunction = outlinedThirdName;
export const outlinedThirdOccurrences = outlinedThirdTotal;
export const outlinedFourthFunction = outlinedFourthName;
export const outlinedFourthOccurrences = outlinedFourthTotal;
// The public source export is the reviewed candidate. baselineProgram remains available for
// byte-for-byte regression checks without making the unoptimized program the default output.
export const program = candidateProgram;

// Keep the byte-best program as the default. Cost profiles undo selected existing
// outlines using each helper's sole body owner and restoring its displaced key.
const inlineKeys = {
  stackSequence53: {displaced: 'fp6Mul', from: 19, to: -1, occurrences: outlinedThirdTotal},
  stackSequence54: {displaced: 'fp2Scale', from: 31, to: 14, occurrences: outlinedFourthTotal},
  stackSequence56: {displaced: 'stackSequence16', from: 35, to: 16,
    occurrences: stackOutlines.find(f => f.function === 'stackSequence56').occurrences},
  stackSequence58: {displaced: 'fp2MulXi', from: 53, to: 13,
    occurrences: stackOutlines.find(f => f.function === 'stackSequence58').occurrences},
};
const profileInlines = {
  balanced: ['stackSequence58'],
  cost: ['stackSequence56'],
  combined: ['stackSequence56', 'stackSequence58'],
  expanded: ['stackSequence54', 'stackSequence56', 'stackSequence58'],
  aggressive: ['stackSequence53', 'stackSequence56', 'stackSequence58'],
  extended: ['stackSequence53', 'stackSequence54', 'stackSequence56', 'stackSequence58'],
};
export function buildProfile(profile = 'bytes') {
  assert(profile === 'bytes' || Object.hasOwn(profileInlines, profile), `unknown profile: ${profile}`);
  if (profile === 'bytes') return {program, identifiers: candidateIdentifiers, inlinedFunctions, outlinedStackSequences};
  const names = profileInlines[profile];
  const identifiers = new Map(candidateIdentifiers);
  let functions = candidateFunctions;
  let main = candidateMain;
  for (const name of names) {
    const {displaced, from, to, occurrences: expectedOccurrences} = inlineKeys[name];
    const helper = candidateFunctions.find(f => f.name === name);
    assert(helper, `missing profile helper: ${name}`);
    assert.equal(assemble(helper.body, candidateIdentifiers).length, 4);
    assert(helper.body.trim().split(/\s+/).every(token => /^OP_(?:[0-9]+|PICK|ROLL)$/.test(token)),
      `profile helper must remain a straight-line stack sequence: ${name}`);
    assert.equal(candidateIdentifiers.get(name), to);
    assert.equal(candidateIdentifiers.get(displaced), from);
    identifiers.delete(name);
    identifiers.set(displaced, to);
    assert.equal(new Set([...identifiers.values()]).size, identifiers.size);
    const pattern = new RegExp(`\\bCALL ${name}\\b`, 'g');
    let occurrences = 0;
    const inline = body => {
      occurrences += body.match(pattern)?.length ?? 0;
      return body.replace(pattern, helper.body);
    };
    functions = functions.filter(f => f.name !== name).map(f => ({...f, body: inline(f.body)}));
    main = inline(main);
    assert.equal(occurrences, expectedOccurrences, `unexpected profile call count: ${name}`);
  }
  const selected = buildCandidate(functions, identifiers, main);
  const retained = new Set(selected.declarations.map(f => f.name));
  return {program: selected, identifiers, inlinedFunctions: [...inlinedFunctions, ...names],
    outlinedStackSequences: outlinedStackSequences.filter(f => retained.has(f.function))};
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  assert(process.argv[2], 'usage: node compact.mjs output.json [bytes|balanced|cost|combined|expanded|aggressive|extended]');
  const profile = process.argv[3] ?? 'bytes';
  const selected = buildProfile(profile);
  const selectedSha256 = createHash('sha256').update(selected.program.bytecode).digest('hex');
  writeFileSync(process.argv[2], JSON.stringify({
    status: 'recovered program with compact identifiers, SZ-a1 inlining, SM/TB/TJ/TR outlining, and exponent-driven powFp; gates reported separately',
    identifiers: Object.fromEntries(selected.identifiers),
    functionCount: selected.program.declarations.length,
    baselineLockingBytes: bytecode.length, baselineLockingSha256: sha256,
    lockingBytes: selected.program.bytecode.length, lockingSha256: selectedSha256,
    inlinedFunctions: selected.inlinedFunctions,
    lockingHex: Buffer.from(selected.program.bytecode).toString('hex'),
    ...(profile === 'bytes' ? {} : {profile}),
  }, null, 2) + '\n');
  console.log(JSON.stringify({lockingBytes: selected.program.bytecode.length, sha256: selectedSha256,
    ...(profile === 'bytes' ? {} : {profile})}));
}

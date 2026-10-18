// A staged reverse macro expansion proof, never used to build the candidate. The candidate's
// main starts with the public-input range check (0 <= n0, n1 < r, r = P - 6x^2); the proof
// checks that prefix exactly, strips it, and shows the rest expands to the official artifact.
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {OpcodesBCH as O, decodeAuthenticationInstructions as decode, encodeAuthenticationInstructions as encode, encodeDataPush, bigIntToVmNumber, vmNumberToBigInt} from '@bitauth/libauth';
import {assemble} from './build.mjs';

const deduplicated = assemble(readFileSync(new URL('verifier.asm', import.meta.url), 'utf8'));
assert.equal(deduplicated.bodies.length, 61);
assert.equal(deduplicated.bytecode.length, 4236);
assert.equal(createHash('sha256').update(deduplicated.bytecode).digest('hex'),
  'bd4d26598f7f1db43527f242d73c608610a63a07ebadfd30fdd9fd058e0e6e34');
assert(!deduplicated.bodies.some(body => body.id === 17));
assert(deduplicated.bodies.some(body => body.id === -1 && body.name === 'outline_18'));
const duplicate = deduplicated.bodies.find(body => body.name === 'outline_9');
assert(duplicate && duplicate.id === 9);

const number = instruction => instruction.data !== undefined
  ? vmNumberToBigInt(instruction.data, {maximumVmNumberByteLength: 10000})
  : instruction.opcode === O.OP_0 ? 0n
    : instruction.opcode >= O.OP_1 && instruction.opcode <= O.OP_16
      ? BigInt(instruction.opcode - O.OP_1 + 1) : undefined;
const literal = value => decode(encodeDataPush(bigIntToVmNumber(value)))[0];
const bytes = instructions => Buffer.from(encode(instructions));
const hash = value => createHash('sha256').update(value).digest('hex');

// First reverse only the compact namespace encoding. This isolates the six-byte saving
// from the duplicate-body rewrite and proves the historical 4,242-byte control directly.
const candidateInstructions = decode(deduplicated.bytecode);
const candidateMain = candidateInstructions.slice(deduplicated.bodies.length * 3);
let restoredNamespaceCalls = 0;
const namespaceBodies = deduplicated.bodies.map(body => {
  const code = decode(body.bytecode);
  for (let ip = 1; ip < code.length; ip++) {
    if (code[ip].opcode === O.OP_INVOKE && code[ip - 1].opcode === O.OP_1NEGATE) {
      code[ip - 1] = literal(18n);
      restoredNamespaceCalls++;
    }
  }
  return {...body, id: body.id === -1 ? 18 : body.id, bytecode: Buffer.from(encode(code))};
});
for (let ip = 1; ip < candidateMain.length; ip++) {
  if (candidateMain[ip].opcode === O.OP_INVOKE && candidateMain[ip - 1].opcode === O.OP_1NEGATE) {
    candidateMain[ip - 1] = literal(18n);
    restoredNamespaceCalls++;
  }
}
assert.equal(restoredNamespaceCalls, 5);
const namespaceOnly = Buffer.concat([
  ...namespaceBodies.flatMap(body => [Buffer.from(encodeDataPush(body.bytecode)),
    Buffer.from(encodeDataPush(bigIntToVmNumber(BigInt(body.id)))), Buffer.from([O.OP_DEFINE])]),
  Buffer.from(encode(candidateMain)),
]);
assert.equal(namespaceOnly.length, 4242);
assert.equal(hash(namespaceOnly), '8537de8922c6e4711357e4390fd0e1a2006015a16e7b93a7f1d5a88c7d0d58a2');

// Then reverse the identical-body sharing on the 4,242-byte control.
const namespaceDecoded = decode(namespaceOnly);
const namespaceMain = namespaceDecoded.slice(namespaceBodies.length * 3);
const callsToRestore = new Map([['outline_30', 1], ['outline_40', 4]]);
const restoredBodies = [];
let restoredDuplicateCalls = 0;
for (const body of namespaceBodies) {
  if (body.id === 9) restoredBodies.push({...body, name: 'outline_17', id: 17});
  const code = decode(body.bytecode);
  let restoredCalls = 0;
  if (callsToRestore.has(body.name)) {
    for (let ip = 0; ip + 1 < code.length; ip++) {
      if (code[ip].opcode === O.OP_9 && code[ip + 1].opcode === O.OP_INVOKE) {
        code[ip] = decode(encodeDataPush(bigIntToVmNumber(17n)))[0];
        restoredCalls++;
      }
    }
    assert.equal(restoredCalls, callsToRestore.get(body.name));
  }
  restoredDuplicateCalls += restoredCalls;
  restoredBodies.push({...body, bytecode: Buffer.from(encode(code))});
}
assert.equal(restoredDuplicateCalls, 5);
const oldMain = namespaceMain;
const bytecode = Buffer.concat([
  ...restoredBodies.flatMap(body => [Buffer.from(encodeDataPush(body.bytecode)),
    Buffer.from(encodeDataPush(bigIntToVmNumber(BigInt(body.id)))), Buffer.from([O.OP_DEFINE])]),
  Buffer.from(encode(oldMain)),
]);
const bodies = restoredBodies;
assert.equal(bytecode.length, 4260);
const expandedLockingSha256 = hash(bytecode);
assert.equal(expandedLockingSha256,
  '6d884ee69b1ec0f6b20e749d64422a4f0c779f756a1b01bb1b8edb9b40836e80');
const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const R_RANGE_CHECK = [O.OP_9, O.OP_PICK, O.OP_9, O.OP_PICK, O.OP_2DUP, O.OP_MIN, O.OP_0, O.OP_GREATERTHANOREQUAL,
  O.OP_VERIFY, O.OP_MAX].map(opcode => ({opcode}));
const rangeCheck = bytes([...R_RANGE_CHECK, literal(0n), {opcode: O.OP_INVOKE}, literal(147946756881789318990833708069417712966n),
  ...[O.OP_SUB, O.OP_LESSTHAN, O.OP_VERIFY].map(opcode => ({opcode}))]);
const mainStart = bytecode.length - Buffer.from(encode(decode(bytecode).slice(bodies.length * 3))).length;
assert.deepEqual(bytecode.subarray(mainStart, mainStart + rangeCheck.length), rangeCheck, 'main starts with the range check');
const candidate = Buffer.concat([bytecode.subarray(0, mainStart), bytecode.subarray(mainStart + rangeCheck.length)]);
const instructions = decode(candidate);
const ids = new Set(bodies.map(body => body.id));
assert.equal(bodies.length, 62);
assert(ids.has(0) && !ids.has(47));
let restoredLiterals = 0;
let restoredPairs = 0;
const expand = (body, id) => {
  const result = [];
  for (let ip = 0; ip < body.length; ip++) {
    const instruction = body[ip];
    assert.notEqual(instruction.opcode, O.OP_DEFINE, 'no nested definitions');
    if (instruction.opcode === O.OP_INVOKE) {
      assert(ids.has(Number(number(body[ip - 1]))), 'every call is literal and defined');
    }
    if (number(instruction) === 0n && body[ip + 1]?.opcode === O.OP_INVOKE) {
      if (id === 4 || id === 46) {
        result.push(literal(P));
        restoredLiterals++;
      } else {
        assert.equal(body[ip + 2]?.opcode, O.OP_DUP, 'preserve former pair interface');
        result.push(literal(47n), body[ip + 1]);
        ip++;
        restoredPairs++;
      }
      ip++;
    } else {
      result.push(instruction);
    }
  }
  return result;
};
const original = [];
for (const [index, body] of bodies.entries()) {
  const at = index * 3;
  assert.deepEqual(Buffer.from(instructions[at].data), body.bytecode);
  assert.equal(Number(number(instructions[at + 1])), body.id);
  assert.equal(instructions[at + 2].opcode, O.OP_DEFINE);
  let restored;
  if (body.id === 0) {
    assert.deepEqual(body.bytecode, bytes([literal(P)]), 'constant body only pushes P');
    restored = [literal(P), {opcode: O.OP_DUP}];
  } else {
    restored = expand(decode(body.bytecode), body.id);
  }
  original.push(...decode(encodeDataPush(bytes(restored))), literal(body.id === 0 ? 47n : BigInt(body.id)), {opcode: O.OP_DEFINE});
}
original.push(...expand(instructions.slice(bodies.length * 3), null));
assert.equal(restoredLiterals, 2);
assert.equal(restoredPairs, 2);
const restored = bytes(original);
assert.equal(restored.length, 4292);
assert.equal(hash(restored), '61c451d0bf8835e6ab850a02c325775d3769dbff92b87ba2d564c8f1f8494c83');
assert.equal(candidate.length, 4228);
assert.equal(hash(candidate), 'a7686356eba90eb594d2a05189e645111506e67fc3c52007144081761d357cd0');
console.log(JSON.stringify({status: 'PASS', namespaceOnlyBytes: namespaceOnly.length, namespaceOnlySha256: hash(namespaceOnly), rangeCheckedBytes: deduplicated.bytecode.length, rangeCheckedSha256: hash(deduplicated.bytecode), expandedLockingBytes: bytecode.length, expandedLockingSha256, restoredDuplicateCalls, currentDefinitions: deduplicated.bodies.length, candidateBytes: candidate.length, originalBytes: restored.length, restoredLiterals, restoredPairs, definitions: bodies.length, candidateSha256: hash(candidate), originalSha256: hash(restored)}));

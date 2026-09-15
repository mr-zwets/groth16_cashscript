// A reverse macro expansion proof, never used to build the candidate.
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {OpcodesBCH as O, decodeAuthenticationInstructions as decode, encodeAuthenticationInstructions as encode, encodeDataPush, bigIntToVmNumber, vmNumberToBigInt} from '@bitauth/libauth';
import {assemble} from './build.mjs';

const {bytecode, bodies} = assemble(readFileSync(new URL('verifier.asm', import.meta.url), 'utf8'));
const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const number = instruction => instruction.data !== undefined
  ? vmNumberToBigInt(instruction.data, {maximumVmNumberByteLength: 10000})
  : instruction.opcode === O.OP_0 ? 0n
    : instruction.opcode >= O.OP_1 && instruction.opcode <= O.OP_16
      ? BigInt(instruction.opcode - O.OP_1 + 1) : undefined;
const literal = value => decode(encodeDataPush(bigIntToVmNumber(value)))[0];
const bytes = instructions => Buffer.from(encode(instructions));
const hash = value => createHash('sha256').update(value).digest('hex');
const instructions = decode(bytecode);
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
assert.equal(bytecode.length, 4228);
assert.equal(hash(bytecode), 'a7686356eba90eb594d2a05189e645111506e67fc3c52007144081761d357cd0');
console.log(JSON.stringify({status: 'PASS', candidateBytes: bytecode.length, originalBytes: restored.length, restoredLiterals, restoredPairs, definitions: bodies.length, candidateSha256: hash(bytecode), originalSha256: hash(restored)}));

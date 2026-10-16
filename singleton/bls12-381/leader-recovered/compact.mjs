import assert from 'node:assert/strict';
import {writeFileSync} from 'node:fs';
import {pathToFileURL} from 'node:url';
import {createHash} from 'node:crypto';
import {functions} from './program.mjs';
import {build} from './build.mjs';

// Function identifiers are raw byte keys. Empty and 0x81 identifiers have the
// single-byte OP_0 and OP_1NEGATE encodings. Keep every other binding unchanged.
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
export const program = build(identifiers, rangeCheck);
const {bytecode} = program;
const sha256 = createHash('sha256').update(bytecode).digest('hex');
const mainStart = unchecked.bytecode.length - unchecked.mainBytecode.length;
assert.deepEqual(Buffer.from(bytecode.subarray(0, mainStart)), Buffer.from(unchecked.bytecode.subarray(0, mainStart)), 'declarations unchanged');
assert.deepEqual(Buffer.from(bytecode.subarray(bytecode.length - unchecked.mainBytecode.length)), Buffer.from(unchecked.mainBytecode), 'main unchanged after the prefix');
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  assert(process.argv[2], 'usage: node compact.mjs output.json');
  writeFileSync(process.argv[2], JSON.stringify({
    status: 'recovered program with compact function identifiers; gates reported separately',
    identifiers: Object.fromEntries(identifiers),
    lockingBytes: bytecode.length, lockingSha256: sha256,
    lockingHex: Buffer.from(bytecode).toString('hex'),
  }, null, 2) + '\n');
  console.log(JSON.stringify({lockingBytes: bytecode.length, sha256}));
}

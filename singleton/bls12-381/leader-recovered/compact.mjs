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
export const program = build(identifiers);
const {bytecode} = program;
const sha256 = createHash('sha256').update(bytecode).digest('hex');
assert.equal(bytecode.length, 3415);
assert.equal(sha256, 'b982a3db459ec4bbb0a9742b54c2181919881af4d3af24b456e5b5825ba85558');
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

import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';

// A source-owned lookup emitter. Constants come from the fixed public table,
// and every reconstructed entry is checked before any bytecode is emitted.
export function emitOrbitHelper(lib, table, prime, beta, retainPrime) {
  assert.equal(table.length, 960);
  assert(beta > 1n && beta < prime && beta * beta % prime * beta % prime === 1n);
  const representatives = [1, 4, 5, 6, 7, 9, 11, 13, 14];
  const mapping = new Map(representatives.map((index, position) => [index, [position, 0]]));
  for (const [first, second, third] of [[1, 2, 3], [4, 8, 12], [5, 10, 15]]) {
    mapping.set(second, [representatives.indexOf(first), 1]);
    mapping.set(third, [representatives.indexOf(first), 2]);
  }
  const packed = lib.flattenBinArray(representatives.map(index => table.slice((index - 1) * 64, index * 64)));
  const descriptors = Uint8Array.from({length: 15}, (_, i) => {
    const [position, transform] = mapping.get(i + 1);
    return position + 16 * transform;
  });
  const number = raw => raw.reduceRight((n, byte) => n * 256n + BigInt(byte), 0n);
  const encode = value => {
    assert(value >= 0n && value < prime);
    return Uint8Array.from({length: 32}, (_, i) => Number(value >> BigInt(8 * i) & 255n));
  };
  const betaSquared = beta * beta % prime;
  const restored = [];
  for (let i = 0; i < 15; i++) {
    const [position, transform] = mapping.get(i + 1), base = packed.slice(position * 64, (position + 1) * 64);
    let x = number(base.slice(0, 32)), y = number(base.slice(32));
    assert(x > 0n && x < prime && y > 0n && y < prime);
    if (transform) x = x * (transform === 1 ? beta : betaSquared) % prime;
    if (transform === 2) y = prime - y;
    restored.push(encode(x), encode(y));
  }
  assert.deepEqual(lib.flattenBinArray(restored), table);
  const op = (...values) => Uint8Array.of(...values);
  const push = value => lib.encodeDataPush(lib.bigIntToVmNumber(BigInt(value)));
  const parts = [
    // idx -> descriptor, retaining the old 1..15 range by both split bounds.
    lib.encodeDataPush(descriptors), op(120, 127, 117, 124, 140, 127, 119, 129),
    // descriptor -> x, y, transform.
    op(118), push(16), op(151), push(64), op(149), lib.encodeDataPush(packed),
    op(124, 127, 119), push(64), op(127, 117), push(32), op(127, 129, 124, 129, 124, 123), push(16), op(150),
    // Transform0 returns the selected pair. Transform1 multiplies x by beta;
    // transform2 multiplies by betaSquared and negates y in the field.
    op(118, 99, 118, 81, 156, 99), push(beta), op(103), push(betaSquared), op(104),
  ];
  if (retainPrime) {
    parts.push(push(prime), op(84, 122, 123, 149, 120, 151, 82, 122, 82, 156, 99,
      123, 123, 124, 148, 103, 119, 124, 104));
  } else {
    parts.push(op(83, 122, 149), push(prime), op(151, 124, 82, 156, 99),
      push(prime), op(123, 148, 103, 124, 104));
  }
  parts.push(op(103, 117, 104));
  return {bytecode: lib.flattenBinArray(parts), packed, descriptors};
}

import * as lib from '@bitauth/libauth';
const prime = 21888242871839275222246405745257275088696311157297823662689037894645226208583n, beta = 2203960485148121921418603742825762020974279258880205651966n;
const originalHashes = {"201": "ef86a7e4834b2463e17e666406d2393e5a411747db16a20fe535107874a5d3d1", "203": "1d72d820e37e181f50f0abdc55deae9697e92d8298a84d0da530e6898e5ea9a6"};

// Replace the two fixed public-table definitions before the shared loader block
// is split. Every entry reconstructs exactly; the emitted lookup keeps its ABI.
export function compressOrbitTables(bytecode) {
  const instructions = lib.decodeAuthenticationInstructions(bytecode);
  const replacements = new Map();
  for (let i = 0; i + 2 < instructions.length && instructions[i + 2].opcode === lib.OpcodesBCH.OP_DEFINE; i += 3) {
    const identifier = lib.vmNumberToBigInt(instructions[i + 1].data);
    if (identifier !== 201n && identifier !== 203n) continue;
    const body = instructions[i].data;
    assert.equal(body.length, 986);
    assert.equal(createHash('sha256').update(body).digest('hex'), originalHashes[String(identifier)]);
    const blobs = lib.decodeAuthenticationInstructions(body).filter(instruction => instruction.data?.length === 960);
    assert.equal(blobs.length, 1);
    const emitted = emitOrbitHelper(lib, Uint8Array.from(blobs[0].data), prime, beta, false);
    assert.equal(emitted.bytecode.length, 774);
    assert(!replacements.has(String(identifier)));
    replacements.set(String(identifier), i);
    instructions[i] = {opcode: lib.OpcodesBCH.OP_PUSHDATA_2, data: emitted.bytecode};
  }
  assert.equal(replacements.size, 2);
  return Buffer.from(lib.encodeAuthenticationInstructions(instructions));
}

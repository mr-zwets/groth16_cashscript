import assert from 'node:assert/strict';
import {readFileSync, writeFileSync, mkdirSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {OpcodesBCH as O, encodeDataPush, bigIntToVmNumber, decodeAuthenticationInstructions, encodeAuthenticationInstruction, vmNumberToBigInt} from '@bitauth/libauth';

const constants = {
  P: 21888242871839275222246405745257275088696311157297823662689037894645226208583n,
  BN_X: 4965661367192848881n,
  G2_SUBGROUP_SCALAR: 147946756881789318990833708069417712966n,
};
assert.equal(constants.G2_SUBGROUP_SCALAR, 6n * constants.BN_X ** 2n);
const push = value => Buffer.from(encodeDataPush(value));
const integer = value => push(bigIntToVmNumber(BigInt(value)));
const hash = value => createHash('sha256').update(value).digest('hex');

export function assemble(source) {
  const functions = new Map();
  let main, current;
  for (const [index, raw] of source.split('\n').entries()) {
    const line = raw.split('#')[0].trim();
    if (!line) continue;
    const [command, ...args] = line.split(/\s+/);
    const where = `assembly line ${index + 1}`;
    if (command === 'function') {
      assert(!current && !main && args.length === 2, where);
      const [name, encodedId] = args;
      // The compact namespace reserves -1 for a proven-unused raw key. Other
      // IDs retain the original non-negative byte-domain contract.
      assert(/^[a-z][a-z0-9_]*$/.test(name) && /^(?:-1|\d+)$/.test(encodedId), where);
      const id = Number(encodedId);
      assert((id === -1 || (Number.isSafeInteger(id) && id >= 0 && id <= 255)) && !functions.has(name), where);
      assert(![...functions.values()].some(fn => fn.id === id), where);
      current = {id, lines: []};
      functions.set(name, current);
    } else if (command === 'main') {
      assert(!current && !main && args.length === 0, where);
      main = {lines: []};
      current = main;
    } else if (command === 'end') {
      assert(current && args.length === 0, where);
      current = undefined;
    } else {
      assert(current, where);
      current.lines.push({command, args, where});
    }
  }
  assert(main && !current && functions.size > 0, 'complete assembly required');
  const compile = lines => Buffer.concat(lines.flatMap(({command, args, where}) => {
    if (command === 'call') {
      assert(args.length === 1 && functions.has(args[0]), where);
      return [integer(functions.get(args[0]).id), Buffer.from([O.OP_INVOKE])];
    }
    if (command === 'constant') {
      assert(args.length === 1 && Object.hasOwn(constants, args[0]), where);
      return [integer(constants[args[0]])];
    }
    if (command === 'push') {
      assert(args.length === 1 && /^(?:[0-9a-f]{2})+$/.test(args[0]), where);
      return [push(Buffer.from(args[0], 'hex'))];
    }
    assert(args.length === 0 && /^OP_[A-Z0-9_]+$/.test(command) && Number.isInteger(O[command]), where);
    assert(command === 'OP_0' || (O[command] > O.OP_PUSHDATA_4 && ![O.OP_DEFINE, O.OP_INVOKE].includes(O[command])), where);
    return [Buffer.from([O[command]])];
  }));
  const bodies = [...functions].map(([name, fn]) => ({name, id: fn.id, bytecode: compile(fn.lines)}));
  const bytecode = Buffer.concat([
    ...bodies.flatMap(fn => [push(fn.bytecode), integer(fn.id), Buffer.from([O.OP_DEFINE])]),
    compile(main.lines),
  ]);
  const callCounts = new Map();
  for (const {command, args} of [...functions.values(), main].flatMap(fn => fn.lines)) {
    if (command === 'call') callCounts.set(args[0], (callCounts.get(args[0]) ?? 0) + 1);
  }
  const outlinedAdditionalFunctions = [...functions].filter(([name]) => {
    const match = /^outline_(\d+)$/.exec(name);
    return match && Number(match[1]) >= 66;
  }).map(([name, fn]) => ({function: name, id: fn.id, occurrences: callCounts.get(name) ?? 0}));
  return {bytecode, bodies, outlinedAdditionalFunctions};
}

// Fixed fixtures retain their original proof coordinates; only the exported
// witness representation changes. A/C y occupy pushes 2/8, with x at 3/9.
function compressG1Witness(hex) {
  const instructions = decodeAuthenticationInstructions(Buffer.from(hex, 'hex'));
  assert.equal(instructions.length, 10, 'expected ten fixed witness pushes');
  assert(instructions.every(instruction => instruction.data !== undefined && !instruction.malformed),
    'fixed witness must contain well-formed data pushes');
  return Buffer.concat(instructions.map((instruction, index) => {
    if (index !== 2 && index !== 8) return Buffer.from(encodeAuthenticationInstruction(instruction));
    const y = vmNumberToBigInt(instruction.data, {maximumVmNumberByteLength: 32});
    assert(typeof y === 'bigint' && y >= 0n && y < constants.P, 'G1 y must be canonical');
    const x = vmNumberToBigInt(instructions[index + 1].data, {maximumVmNumberByteLength: 32});
    assert(typeof x === 'bigint', 'G1 x must be a valid fixed coordinate');
    const rhs = (((x * x) % constants.P * x) % constants.P + 3n) % constants.P;
    assert.equal(y * y % constants.P, rhs, 'fixed G1 point must be on curve');
    return integer(y & 1n);
  })).toString('hex');
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  assert.equal(process.argv.length, 3, 'usage: node build.mjs OUTPUT_DIRECTORY');
  const here = new URL('./', import.meta.url);
  const source = readFileSync(new URL('verifier.asm', here), 'utf8');
  const {bytecode, bodies, outlinedAdditionalFunctions} = assemble(source);
  const output = resolve(process.argv[2]);
  mkdirSync(output, {recursive: true});
  const lockingOK = bytecode.toString('hex');
  for (const [name, fixture] of [['groth16-singleton-genpow-vectors.json', 'committed-fixtures.json'], ['groth16-singleton-genpow-multiproof-vectors.json', 'multiproof-fixtures.json']]) {
    const vectors = JSON.parse(readFileSync(new URL(fixture, here)));
    assert(!Object.hasOwn(vectors, 'lockingOK'), 'fixtures must not supply the program');
    const encodeProof = proof => ({...proof,
      unlocking: compressG1Witness(proof.unlocking),
      invalidUnlocking: compressG1Witness(proof.invalidUnlocking),
    });
    const encoded = vectors.proofs
      ? {...vectors, proofs: vectors.proofs.map(encodeProof)}
      : encodeProof(vectors);
    const exported = {...encoded, lockingOK,
      contract: 'genpow-reconstructed/verifier.asm (BN254 genpow, G1 parity compression)',
      description: 'Fixed proof and public-input integers with A/C y represented by parity. The verifier reconstructs and checks each exact canonical G1 point before unchanged later arithmetic. Relaxed VM research; native compatibility requires independent qualification.',
      witnessEncoding: 'g1-a-c-x-parity-v1',
    };
    writeFileSync(resolve(output, name), JSON.stringify(exported, null, 2) + '\n');
  }
  const manifest = {
    emitter: 'explicit symbolic assembly; no CashScript compiler or replay optimizer',
    node: process.version,
    assemblySha256: hash(source),
    lockingBytes: bytecode.length,
    lockingSha256: hash(bytecode),
    functions: bodies.map(({name, id, bytecode: body}) => ({name, id, bytes: body.length, sha256: hash(body)})),
    outlinedAdditionalFunctions,
  };
  writeFileSync(resolve(output, 'build-manifest.json'), JSON.stringify(manifest, null, 2) + '\n');
  console.log(JSON.stringify(manifest, null, 2));
}

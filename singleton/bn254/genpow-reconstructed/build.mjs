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

export function assemble(source, {profile = 'bytes'} = {}) {
  const profiles = {
    bytes: [],
    factored: [],
    balanced: ['outline_70', 'outline_71'],
    cost: ['outline_69', 'outline_70', 'outline_71'],
    light: ['outline_71'],
    selective: ['outline_69'],
    expanded: ['outline_69', 'outline_71'],
    lean: ['outline_68'],
    'lean-expanded': ['outline_68', 'outline_69', 'outline_71'],
    'lean-expanded64': ['outline_64', 'outline_68', 'outline_69', 'outline_71'],
    'lean-expanded64-65': ['outline_64', 'outline_65', 'outline_68', 'outline_69', 'outline_71'],
  };
  assert(Object.hasOwn(profiles, profile), `unknown assembly profile: ${profile}`);
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
  if (profile === 'factored') {
    // For canonical f, H=(P^4-P^2+1)/r and h=Frob2(f^H)*f^H give
    // f^((P^12-1)/r)=1 iff h is a nonzero element of Fp6.
    // Existing field calls own multiplication; only the final verdict changes.
    const op = (command, ...args) => ({command, args, where: 'factored final exponent'});
    const same = line => [line.command, ...line.args];
    const begin = main.lines.findLastIndex(line => line.command === 'OP_BEGIN');
    const until = main.lines.findLastIndex(line => line.command === 'OP_UNTIL');
    assert(begin > 0 && until > begin && main.lines[begin - 1].command === 'OP_0',
      'expected positive generic Fp12 exponent loop');
    assert(main.lines.slice(until + 1, until + 15).every(line =>
      line.command === 'OP_DROP' && line.args.length === 0), 'expected fourteen loop cleanup drops');
    const tail = ['OP_11', 'OP_ROLL', 'OP_1', 'OP_NUMEQUALVERIFY'];
    for (let depth = 10; depth >= 3; depth--) tail.push(`OP_${depth}`, 'OP_ROLL', 'OP_0', 'OP_NUMEQUALVERIFY');
    tail.push('OP_ROT', 'OP_0', 'OP_NUMEQUALVERIFY', 'OP_SWAP', 'OP_0', 'OP_NUMEQUALVERIFY', 'OP_0', 'OP_NUMEQUAL');
    assert.deepEqual(main.lines.slice(until + 15).map(same), tail.map(command => [command]),
      'expected complete canonical Fp12 identity verdict');
    const power = main.lines.slice(begin - 1, until + 15);
    const prefix = main.lines.slice(0, begin - 1);
    const oldExponent = ['OP_OVER', 'OP_ROT', 'OP_MUL', 'OP_DUP', 'OP_MUL', 'OP_DUP',
      'OP_DUP', 'OP_MUL', 'OP_MUL', 'OP_1SUB', 'OP_SWAP', 'OP_DIV'];
    const hardExponent = ['OP_SWAP', 'OP_DUP', 'OP_MUL', 'OP_DUP', 'OP_DUP', 'OP_MUL',
      'OP_SWAP', 'OP_SUB', 'OP_1ADD', 'OP_SWAP', 'OP_DIV'];
    assert.deepEqual(prefix.slice(-oldExponent.length).map(same), oldExponent.map(command => [command]),
      'expected full exponent derivation from existing P and r');
    prefix.splice(-oldExponent.length, oldExponent.length, ...hardExponent.map(command => op(command)));
    for (const [name, id] of [['fp12_frob2', 72], ['fp12_power', 73], ['fp_mul_frob2', 74]]) {
      assert(!functions.has(name) && ![...functions.values()].some(fn => fn.id === id),
        `${name}: expected unused function name and ID ${id}`);
    }
    // The nontrivial cube root gives the Frob2 diagonal:
    // 1,1,-(t+1),-(t+1),t,t,-t,-t,-1,-1,t+1,t+1.
    const u = constants.BN_X;
    const root = 18n*u**3n + 18n*u**2n + 9n*u + 1n;
    assert.equal((root*root + root + 1n) % constants.P, 0n);
    const frobenius = [];
    const add = (...commands) => frobenius.push(...commands.map(command => op(command)));
    for (let index = 0; index < 12; index++) {
      add('OP_11', 'OP_ROLL');
      if ([2, 3, 10, 11].includes(index)) add('OP_DUP');
      if ([2, 3, 4, 5, 6, 7, 10, 11].includes(index)) frobenius.push(op('call', 'fp_mul_frob2'));
      if ([2, 3, 10, 11].includes(index)) frobenius.push(op('call', 'fp_add'));
      if ([2, 3, 6, 7, 8, 9].includes(index)) {
        add('OP_0');
        frobenius.push(op('call', 'fp_sub_top_minus_next'));
      }
    }
    functions.set('fp12_frob2', {id: 72, lines: frobenius});
    functions.set('fp12_power', {id: 73, lines: power});
    functions.set('fp_mul_frob2', {id: 74, lines: [
      op('push', Buffer.from(bigIntToVmNumber(root)).toString('hex')), op('call', 'fp_mul'),
    ]});
    const guard = [];
    for (let depth = 1; depth <= 12; depth++) guard.push(
      op(`OP_${depth}`), op('OP_PICK'), op('OP_DUP'), op('OP_0'),
      op('OP_GREATERTHANOREQUAL'), op('OP_VERIFY'), op('call', 'prime'),
      op('OP_LESSTHAN'), op('OP_VERIFY'),
    );
    const duplicate = Array.from({length: 12}, () => [op('OP_11'), op('OP_PICK')]).flat();
    const subfield = Array.from({length: 6}, () => [op('OP_0'), op('OP_NUMEQUALVERIFY')]).flat();
    const nonzero = [op('OP_0NOTEQUAL'), ...Array.from({length: 5}, () =>
      [op('OP_SWAP'), op('OP_0NOTEQUAL'), op('OP_BOOLOR')]).flat()];
    main.lines = [...prefix, ...guard, op('call', 'fp12_power'), ...duplicate,
      op('call', 'fp12_frob2'), op('OP_1'), op('call', 'fp12_power'), ...subfield, ...nonzero];
  }
  if (profile !== 'bytes') {
    const inline = new Map(profiles[profile].map(name => [name, functions.get(name)]));
    const lines = [...functions.values(), main].flatMap(fn => fn.lines);
    for (const [name, id, occurrences] of [
      ['outline_64', -1, 11], ['outline_65', 13, 11], ['outline_68', 65, 5],
      ['outline_69', 15, 10], ['outline_70', 69, 5], ['outline_71', 70, 5],
    ]) {
      if (!inline.has(name)) continue;
      const fn = inline.get(name);
      assert(fn && fn.id === id, `${name}: expected profile helper ID ${id}`);
      assert.equal(lines.filter(line => line.command === 'call' && line.args[0] === name).length,
        occurrences, `${name}: expected profile call sites`);
      if (name === 'outline_64') {
        assert.deepEqual(fn.lines.map(({command, args}) => [command, ...args]),
          [['OP_4'], ['OP_PICK'], ['OP_6'], ['OP_PICK']],
          'outline_64: expected exact four/six-pick sequence');
      } else if (name === 'outline_65') {
        assert.deepEqual(fn.lines.map(({command, args}) => [command, ...args]),
          [['OP_6'], ['OP_ROLL'], ['OP_7'], ['OP_ROLL']],
          'outline_65: expected exact six/seven-roll sequence');
      } else {
        assert(fn.lines.every(({command, args}) => command === 'call'
          ? args[0] === 'fp_mul'
          : command === 'push' || ['OP_7', 'OP_ROLL', 'OP_DUP', 'OP_OVER', 'OP_PICK'].includes(command)),
        `${name}: profile inlining requires a straight-line stack/arithmetic helper`);
      }
    }
    for (const fn of [...functions.values(), main]) {
      fn.lines = fn.lines.flatMap(line => line.command === 'call' && inline.has(line.args[0])
        ? inline.get(line.args[0]).lines : [line]);
    }
    for (const name of inline.keys()) functions.delete(name);
    if (inline.has('outline_69')) {
      const displaced = functions.get('outline_15');
      assert(displaced && displaced.id === 68 && ![...functions.values()].some(fn => fn.id === 15),
        'outline_15: expected displaced ID 68 and released ID 15');
      displaced.id = 15;
    }
    if (inline.has('outline_64')) {
      const displaced = functions.get('outline_18');
      assert(displaced && displaced.id === 18 && ![...functions.values()].some(fn => fn.id === -1),
        'outline_18: expected displaced ID 18 and released ID -1');
      displaced.id = -1;
    }
    if (inline.has('outline_65')) {
      const displaced = functions.get('outline_13');
      assert(displaced && displaced.id === 47 && ![...functions.values()].some(fn => fn.id === 13),
        'outline_13: expected displaced ID 47 and released ID 13');
      displaced.id = 13;
    }
  }
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
  assert([3, 4].includes(process.argv.length),
    'usage: node build.mjs OUTPUT_DIRECTORY [bytes|balanced|cost|light|selective|expanded|lean|lean-expanded|lean-expanded64|lean-expanded64-65|factored]');
  const profile = process.argv[3] ?? 'bytes';
  const here = new URL('./', import.meta.url);
  const source = readFileSync(new URL('verifier.asm', here), 'utf8');
  const {bytecode, bodies, outlinedAdditionalFunctions} = assemble(source, {profile});
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
    ...(profile === 'bytes' ? {} : {profile}),
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

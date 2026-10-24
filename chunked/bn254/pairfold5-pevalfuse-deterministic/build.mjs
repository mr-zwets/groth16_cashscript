import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {writeFileSync} from 'node:fs';
import {pathToFileURL} from 'node:url';
import {OpcodesBCH, encodeAuthenticationInstructions, encodeDataPush, bigIntToVmNumber} from '@bitauth/libauth';
import * as shared from '../leader-recovered/shared.mjs';
import * as genesis from './genesis.mjs';
import * as terminal from '../leader-recovered/terminal.mjs';
import * as equation from './equation-guard.mjs';
import {executor, p2sh} from './loader.mjs';
import {BASE_FIELD, SCALAR_FIELD, deploymentTag, layout} from './constants.mjs';

const hash256 = bytes => createHash('sha256').update(createHash('sha256').update(bytes).digest()).digest();
const numbers = {
  BASE_FIELD, SCALAR_FIELD, SQUARE_BIAS: 64n * BASE_FIELD,
  FRAGMENT_OFFSET: BigInt(layout.fragmentOffset),
  ...Object.fromEntries(layout.codePageOffsets.map((offset, i) => [`CODE_PAGE_${i}_OFFSET`, BigInt(offset)])),
  ...Object.fromEntries(layout.fragmentLengths.map((length, i) => [`FRAGMENT_${i}_BYTES`, BigInt(length)])),
};

// Preserve explicit push opcodes and unsigned payload lengths. Symbols describe
// static function references; INVOKE_STACK preserves the three dynamic sites.
export function assemble(body, identifiers, data = {}) {
  const tokens = body.trim() ? body.trim().split(/\s+/) : [];
  const encoded = [];
  for (let i = 0; i < tokens.length; i++) {
    const token = tokens[i];
    if (['CALL', 'DEFINE_STACK', 'NUM', 'DATA'].includes(token)) {
      const name = tokens[++i];
      const value = token === 'NUM' ? (numbers[name] ?? data[name]) : token === 'DATA' ? data[name] : identifiers.get(name);
      assert(value !== undefined, `unknown ${token} symbol: ${name}`);
      encoded.push(...encodeDataPush(token === 'DATA' ? value : bigIntToVmNumber(BigInt(value))));
      if (token === 'CALL') encoded.push(OpcodesBCH.OP_INVOKE);
      if (token === 'DEFINE_STACK') encoded.push(OpcodesBCH.OP_DEFINE);
      continue;
    }
    if (token === 'INVOKE_STACK') {
      encoded.push(OpcodesBCH.OP_INVOKE);
      continue;
    }
    const opcode = OpcodesBCH[token];
    assert(Number.isInteger(opcode), `unknown opcode: ${token}`);
    assert(opcode !== OpcodesBCH.OP_INVOKE && opcode !== OpcodesBCH.OP_DEFINE,
      'function operations require an explicit symbolic or stack-selected form');
    if (opcode > 0 && opcode <= 78) {
      const length = opcode < 76 ? opcode : Number(tokens[++i]);
      const hex = tokens[++i];
      assert(/^0x(?:[0-9a-f]{2})+$/.test(hex), `invalid push payload: ${hex}`);
      const bytes = Buffer.from(hex.slice(2), 'hex');
      assert.equal(bytes.length, length);
      encoded.push(...encodeAuthenticationInstructions([{opcode, data: bytes}]));
    } else encoded.push(opcode);
  }
  return Buffer.from(encoded);
}

export function build() {
  const equationIds = new Map(equation.functions.map(f => [f.name, f.originalId]));
  assert.equal(equationIds.size, equation.functions.length);
  const equationDeclarations = equation.functions.map(f => ({
    name: f.name, id: f.originalId, bytecode: assemble(f.body, equationIds),
  }));
  const equationLoader = Buffer.concat([
    assemble(equation.prefix, equationIds),
    ...equationDeclarations.map(f => Buffer.from([
      ...encodeDataPush(f.bytecode), ...encodeDataPush(bigIntToVmNumber(BigInt(f.id))), OpcodesBCH.OP_DEFINE,
    ])),
    assemble(equation.main, equationIds),
  ]);
  const equationEntryId = equationIds.get('checker_main');
  assert(equationEntryId !== undefined);
  const callableLoaderId = 32767;
  const allKeys = [...equation.functions, ...genesis.functions].map(f =>
    Buffer.from(bigIntToVmNumber(BigInt(f.originalId))).toString('hex'));
  allKeys.push(Buffer.from(bigIntToVmNumber(BigInt(callableLoaderId))).toString('hex'));
  assert.equal(new Set(allKeys).size, allKeys.length, 'callable/host namespace collision');
  const pageBytes = Math.ceil(equationLoader.length / 3);
  const equationPages = Array.from({length: 3}, (_, i) => equationLoader.subarray(i * pageBytes, (i + 1) * pageBytes));
  equationPages.forEach(page => assert(page.length >= 256 && page.length <= 65535, 'code page requires PUSHDATA2'));
  assert(Buffer.concat(equationPages).equals(equationLoader));
  const programs = {}, declarations = {}, constants = {deploymentTag, callableHash256: hash256(equationLoader)};
  equationPages.forEach((page, i) => { constants[`CODE_PAGE_${i}_BYTES`] = BigInt(page.length); });
  for (const [name, source] of Object.entries({shared, genesis, terminal})) {
    if (name === 'terminal') {
      programs.executor = assemble(executor, new Map([['sharedProgram', 100]]), constants);
      const workerLockings = [programs.executor, programs.executor, programs.executor, programs.genesis]
        .map(redeem => assemble(p2sh, new Map(), {redeemHash256: hash256(redeem)}));
      constants.workerLockingRoot = hash256(Buffer.concat(workerLockings.map(hash256)));
    }
    const identifiers = new Map(source.functions.map(f => [f.name, f.originalId]));
    if (name === 'genesis') {
      identifiers.set('callableLoader', callableLoaderId);
      identifiers.set('callableVerifier', equationEntryId);
    }
    assert.equal(identifiers.size, source.functions.length + (name === 'genesis' ? 2 : 0), 'duplicate function name');
    const keys = [...identifiers.values()].map(id => Buffer.from(bigIntToVmNumber(BigInt(id))).toString('hex'));
    assert.equal(new Set(keys).size, identifiers.size, 'duplicate function identifier');
    declarations[name] = source.functions.map(f => ({
      name: f.name, id: f.originalId, bytecode: assemble(f.body, identifiers, constants),
    }));
    programs[name] = Buffer.concat([
      assemble(source.prefix, identifiers, constants),
      ...declarations[name].map(f => Buffer.from([
        ...encodeDataPush(f.bytecode), ...encodeDataPush(bigIntToVmNumber(BigInt(f.id))), OpcodesBCH.OP_DEFINE,
      ])),
      assemble(source.main, identifiers, constants),
    ]);
    if (name === 'shared') constants.sharedHash256 = hash256(programs.shared);
  }
  const redeems = [programs.executor, programs.executor, programs.executor, programs.genesis, programs.terminal];
  const lockings = redeems.map(redeem => assemble(p2sh, new Map(), {redeemHash256: hash256(redeem)}));
  let offset = 0;
  const sharedFragments = layout.fragmentLengths.map(length => {
    const fragment = programs.shared.subarray(offset, offset + length);
    assert.equal(fragment.length, length);
    offset += length;
    return fragment;
  });
  assert.equal(offset, programs.shared.length, 'fragment layout must cover the complete program');
  const quotientSuffixes = layout.quotientSuffixLengths.map((length, i) => Buffer.alloc(length, layout.quotientSuffixBytes[i]));
  const executorPadding = layout.executorPaddingLengths.map((length, i) =>
    Buffer.from(Array.from({length}, (_, j) => (165 + 37 * i + 19 * j) % 256)));
  const terminalPadding = Buffer.from(Array.from({length: layout.terminalPaddingLength}, (_, j) => (60 + 13 * j) % 256));
  return {programs, declarations, equationLoader, equationDeclarations, equationPages, equationEntryId, callableLoaderId, sharedFragments, quotientSuffixes, executorPadding, terminalPadding, redeems, lockings, layout};
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  assert.equal(process.argv.length, 3, 'usage: node build.mjs static-code.json');
  const {programs, equationLoader, equationPages, equationEntryId, redeems, lockings} = build();
  writeFileSync(process.argv[2], JSON.stringify({
    schema: 'native5-deterministic-static-code/v1',
    nativeResourceAdmission: 'HOLD',
    programs: Object.fromEntries(Object.entries(programs).map(([name, bytes]) => [name, bytes.toString('hex')])),
    equationLoader: equationLoader.toString('hex'),
    equationPages: equationPages.map(bytes => bytes.toString('hex')),
    equationEntryId,
    redeems: redeems.map(bytes => bytes.toString('hex')),
    lockings: lockings.map(bytes => bytes.toString('hex')),
  }, null, 2) + '\n');
}

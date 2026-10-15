import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {writeFileSync} from 'node:fs';
import {pathToFileURL} from 'node:url';
import {programA, programB} from '../pairfold5-msm/vkx-msm-asm.mjs';
import {sourceA, sourceB, compile as compileCash} from '../pairfold5-msm/vkx-msm.mjs';
import {OpcodesBCH, encodeAuthenticationInstructions, encodeDataPush, bigIntToVmNumber} from '@bitauth/libauth';
import * as shared from '../densless-recovered/shared.mjs';
import * as genesis from '../densless-recovered/genesis.mjs';
import * as terminal from './terminal.mjs';
import {executor, fragmentReader, p2sh} from '../densless-recovered/loader.mjs';
import {BASE_FIELD, SCALAR_FIELD, deploymentTag, layout} from '../densless-recovered/constants.mjs';

const hash256 = bytes => createHash('sha256').update(createHash('sha256').update(bytes).digest()).digest();
const numbers = {
  BASE_FIELD, SCALAR_FIELD, SQUARE_BIAS: 64n * BASE_FIELD,
  FRAGMENT_OFFSET: BigInt(layout.fragmentOffset),
  ...Object.fromEntries(layout.fragmentLengths.map((length, i) => [`FRAGMENT_${i}_BYTES`, BigInt(length)])),
};

// Preserve explicit push opcodes and unsigned payload lengths. Symbols describe
// static function references; INVOKE_STACK preserves the two dynamic sites.
export function assemble(body, identifiers, data = {}) {
  const tokens = body.trim() ? body.trim().split(/\s+/) : [];
  const encoded = [];
  for (let i = 0; i < tokens.length; i++) {
    const token = tokens[i];
    if (['CALL', 'DEFINE_STACK', 'NUM', 'DATA'].includes(token)) {
      const name = tokens[++i];
      const value = token === 'NUM' ? numbers[name] : token === 'DATA' ? data[name] : identifiers.get(name);
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

// Sound vk_x: two MSM inputs (5, 6) recompute vk_x from the claimed public inputs
// (genesis pushes 38, 39); see ../pairfold5-msm/vkx-msm.mjs and README.md.
export const MSM_SPLIT = 36;
// MSM implementation: 'cash' (CashScript source vkx-msm.mjs, default; needs cashc
// compiler-optimizations-7) or 'asm' (hand-scheduled vkx-msm-asm.mjs, kept as a cross-check).
export const MSM_IMPL = process.env.MSM_IMPL ?? 'cash';
// Zero-pad bytes buying each MSM input's op-cost budget ((41 + unlocking) * 800 >= op-cost):
// the dense fixture's cost, plus 52k op for every table add it skipped (bound: every 4-bit
// index nonzero), plus 1%.
export const MSM_PAD = MSM_IMPL === 'cash' ? {a: 2152, b: 3400} : {a: 270, b: 3324};
const pushHeader = n => encodeDataPush(new Uint8Array(n)).length - n;
const msmCache = new Map();
export const msmPrograms = (genesisLength) => {
  if (!msmCache.has(genesisLength)) msmCache.set(genesisLength, {
    msmA: MSM_IMPL === 'cash'
      ? compileCash(sourceA({split: MSM_SPLIT, genIdx: 3, bIdx: 6, genesisRedeemPushBytes: genesisLength + 3, pubIdx: 38}))
      : programA({split: MSM_SPLIT, genIdx: 3, bIdx: 6, genesisRedeemPushBytes: genesisLength + 3, pubIdx: 38}),
    msmB: MSM_IMPL === 'cash'
      ? compileCash(sourceB({split: MSM_SPLIT, aIdx: 5, waOffset: pushHeader(MSM_PAD.a) + MSM_PAD.a + 1}))
      : programB({split: MSM_SPLIT, aIdx: 5, waOffset: pushHeader(MSM_PAD.a) + MSM_PAD.a + 1}),
  });
  return msmCache.get(genesisLength);
};

export function build() {
  const programs = {}, declarations = {}, constants = {deploymentTag};
  for (const [name, source] of Object.entries({shared, genesis, terminal})) {
    if (name === 'terminal') {
      assert(programs.genesis.length > 255 && programs.genesis.length < 65536, 'genesis redeem push must be PUSHDATA2');
      Object.assign(programs, msmPrograms(programs.genesis.length));
      const loaderIdentifiers = new Map([['fragmentReader', -1], ['sharedProgram', 100]]);
      const globalFunctionKeys = [
        ...loaderIdentifiers.values(),
        ...shared.functions.map(f => f.originalId),
      ].map(id => Buffer.from(bigIntToVmNumber(BigInt(id))).toString('hex'));
      assert.equal(new Set(globalFunctionKeys).size, globalFunctionKeys.length,
        'loader/shared function identifier byte collision');
      const fragmentReaderBytecode = assemble(fragmentReader, loaderIdentifiers, constants);
      const fragmentReaderDeclaration = Buffer.from([
        ...encodeDataPush(fragmentReaderBytecode),
        ...encodeDataPush(bigIntToVmNumber(-1n)),
        OpcodesBCH.OP_DEFINE,
      ]);
      programs.executor = Buffer.concat([
        fragmentReaderDeclaration,
        assemble(executor, loaderIdentifiers, constants),
      ]);
      const workerLockings = [programs.executor, programs.executor, programs.executor, programs.genesis, programs.msmA, programs.msmB]
        .map(redeem => assemble(p2sh, new Map(), {redeemHash256: hash256(redeem)}));
      constants.workerLockingRoot = hash256(Buffer.concat(workerLockings.map(hash256)));
    }
    const identifiers = new Map(source.functions.map(f => [f.name, f.originalId]));
    assert.equal(identifiers.size, source.functions.length, 'duplicate function name');
    const keys = [...identifiers.values()].map(id => Buffer.from(bigIntToVmNumber(BigInt(id))).toString('hex'));
    assert.equal(new Set(keys).size, source.functions.length, 'duplicate function identifier');
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
  const redeems = [programs.executor, programs.executor, programs.executor, programs.genesis, programs.terminal, programs.msmA, programs.msmB];
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
  return {programs, declarations, sharedFragments, quotientSuffixes, executorPadding, terminalPadding, redeems, lockings, layout};
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  assert.equal(process.argv.length, 3, 'usage: node build.mjs output.json');
  const {programs, sharedFragments, quotientSuffixes, executorPadding, terminalPadding, redeems, lockings, layout: wireLayout} = build();
  writeFileSync(process.argv[2], JSON.stringify({
    historicalCompilerRecovered: false,
    programs: Object.fromEntries(Object.entries(programs).map(([name, bytes]) => [name, bytes.toString('hex')])),
    sharedFragments: sharedFragments.map(bytes => bytes.toString('hex')),
    quotientSuffixes: quotientSuffixes.map(bytes => bytes.toString('hex')),
    executorPadding: executorPadding.map(bytes => bytes.toString('hex')),
    terminalPadding: terminalPadding.toString('hex'),
    redeems: redeems.map(bytes => bytes.toString('hex')),
    lockings: lockings.map(bytes => bytes.toString('hex')),
    layout: wireLayout,
  }, null, 2) + '\n');
}

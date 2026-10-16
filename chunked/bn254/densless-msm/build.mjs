import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {writeFileSync} from 'node:fs';
import {pathToFileURL} from 'node:url';
import {programA, programB} from '../pairfold5-msm/vkx-msm-asm.mjs';
import {sourceA, sourceB, compile as compileCash} from '../pairfold5-msm/vkx-msm.mjs';
import {sliceGenesis} from './genesis-slice.mjs';
import {carrier, remapFunctionIds} from './carrier.mjs';
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

// Sound vk_x: MSM part A (carried inside genesis, see carrier.mjs) and part B (input 5) recompute
// vk_x from the claimed public inputs (genesis pushes 22 n0, 21 n1); see README.md.
export const MSM_SPLIT = Number(process.env.MSM_SPLIT ?? 25);
// Zero-pad bytes buying op-cost budget ((41 + unlocking) * 800 >= op-cost), sized from a linear
// fit of op-cost against the number of table adds over 37 fresh proofs (standard VM), evaluated
// at the worst case where every 4-bit index is nonzero, plus the fit's largest residual, plus 1%:
//   genesis (sliced genesis + MSM part A, positions 63..MSM_SPLIT): 50.7k/add, 78 adds -> 6.22M
//   MSM part B (input 5, positions MSM_SPLIT-1..0, GLV check):       52.1k/add, 50 adds -> 4.42M
// Sized for the CashScript build; the asm build is cheaper. Re-fit after changing MSM_SPLIT.
export const GENESIS_PAD = Number(process.env.GENESIS_PAD ?? 49);
// MSM implementation: 'cash' (CashScript source vkx-msm.mjs, default; needs cashc
// compiler-optimizations-7) or 'asm' (hand-scheduled vkx-msm-asm.mjs, kept as a cross-check).
export const MSM_IMPL = process.env.MSM_IMPL ?? 'cash';
export const MSM_PAD = {b: 1422};
const msmCache = new Map();
export const msmPrograms = (genesisLength) => {
  if (!msmCache.has(genesisLength)) msmCache.set(genesisLength, {
    // MSM part A runs inside genesis (see carrier.mjs), so it has no pad of its own; its function
    // identifiers are moved above the genesis program's (0..29).
    msmA: remapFunctionIds(MSM_IMPL === 'cash'
      ? compileCash(sourceA({split: MSM_SPLIT, bIdx: 5, ownInputs: true, noPad: true}))
      : programA({split: MSM_SPLIT, bIdx: 5, ownInputs: true, noPad: true}), 100),
    msmB: MSM_IMPL === 'cash'
      ? compileCash(sourceB({split: MSM_SPLIT}))
      : programB({split: MSM_SPLIT}),
  });
  return msmCache.get(genesisLength);
};

export function build() {
  const programs = {}, declarations = {}, constants = {deploymentTag};
  for (const [name, source] of Object.entries({shared, genesis, terminal})) {
    if (name === 'terminal') {
      // drop the dead vk_x auxiliary predicate from genesis (see genesis-slice.mjs)
      Object.assign(programs, msmPrograms(0));
      // genesis: the sliced program, then MSM part A on its parked pushes (wa, n1, n0)
      programs.genesis = carrier(sliceGenesis(programs.genesis), programs.msmA, 3);
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
      const workerLockings = [programs.executor, programs.executor, programs.executor, programs.genesis, programs.msmB]
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
  const redeems = [programs.executor, programs.executor, programs.executor, programs.genesis, programs.terminal, programs.msmB];
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

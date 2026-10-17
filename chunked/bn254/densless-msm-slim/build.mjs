import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {writeFileSync} from 'node:fs';
import {pathToFileURL} from 'node:url';
import {sourceA, compile as compileCash} from '../pairfold5-msm/vkx-msm.mjs';
import {cachePrimeLiterals, cacheProfile} from './prime-cache.mjs';
import {compactInverseCopy} from './terminal-copies.mjs';
import {STATE_BYTES, EXEC_STATE_BYTES, sourceExec, sourceFinal} from './vkx-stages.mjs';
import {sliceGenesis} from './genesis-slice.mjs';
import {carrier, remapFunctionIds} from '../densless-msm/carrier.mjs';
import {compileTerminalPins, compileTerminalPinsLenOrder, compileTerminalPinsLenOnly, compileTerminalPinsOrderOnly, compileTerminalPinsLenSign} from './malleability-pins.mjs';
import {OpcodesBCH, decodeAuthenticationInstructions, encodeAuthenticationInstructions, encodeDataPush, bigIntToVmNumber} from '@bitauth/libauth';
import * as shared from '../densless-recovered/shared.mjs';
import * as genesis from '../densless-recovered/genesis.mjs';
import * as terminal from '../densless-recovered/terminal.mjs';
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
export function assemble(body, identifiers, data = {}, extraNumbers = {}) {
  const tokens = body.trim() ? body.trim().split(/\s+/) : [];
  const encoded = [];
  for (let i = 0; i < tokens.length; i++) {
    const token = tokens[i];
    if (['CALL', 'DEFINE_STACK', 'NUM', 'DATA'].includes(token)) {
      const name = tokens[++i];
      const value = token === 'NUM' ? (extraNumbers[name] ?? numbers[name]) : token === 'DATA' ? data[name] : identifiers.get(name);
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

// Sound vk_x: genesis recomputes MSM part A (positions 63..MSM_SPLIT) from its claimed public
// inputs (genesis pushes 22 n0, 21 n1) and the executors and the terminal carry the remaining
// positions as a chain of pinned state pushes (vkx-stages.mjs); see README.md.
export const MSM_SPLIT = Number(process.env.MSM_SPLIT ?? 31);
// Witness-byte cuts: genesis runs [0, CUTS[0]), executor k runs [CUTS[k], CUTS[k + 1]), the
// terminal runs [CUTS[3], 64) and finishes. CUTS[0] = 64 - MSM_SPLIT.
export const CUTS = (process.env.MSM_CUTS ?? `${64 - MSM_SPLIT},43,54,60`).split(',').map(Number);
// Default repartition: genesis consumes positions0..32, executors33..42,
// 43..53 and54..59; terminal60..63. Full MADD caching reduces genesis bytes
// and its budget, so four positions move to executors0and1. The archived
// dense corpus fits without padding; no universal resource bound is claimed.
// GENESIS_PAD/STAGE_PADS remain explicit resource-budget options.
export const GENESIS_PAD = Number(process.env.GENESIS_PAD ?? 0);
export const STAGE_PADS = (process.env.STAGE_PADS ?? '0,0,0,0').split(',').map(Number);
export const PIN_MODE = process.env.SLIM_PINS ?? 'full';
// Carried function identifiers: the MSM helpers (dbl, madd, tab0, tab64) are defined once in
// genesis; the stages read that definition block out of the genesis redeem and run it as
// function LOADER_ID. Clear of genesis (0..29), shared (0..25), terminal (-1, 0..36) and the
// executor loader (-1, 100).
const MSM_ID_OFFSET = 200, LOADER_ID = 199n;
const redeemPushBytes = (length) => length + (length < 76 ? 1 : length < 256 ? 2 : 3);
function cachePrimeDefinition(bytecode, id) {
  const instructions = decodeAuthenticationInstructions(bytecode);
  const key = Buffer.from(encodeDataPush(bigIntToVmNumber(id)));
  let target = -1;
  for (let i = 0; i + 2 < instructions.length && instructions[i + 2].opcode === OpcodesBCH.OP_DEFINE; i += 3) {
    if (!Buffer.from(encodeAuthenticationInstructions([instructions[i + 1]])).equals(key)) continue;
    assert.equal(target, -1, 'duplicate cached-prime definition');
    assert(instructions[i].data !== undefined, 'cached-prime body must be a literal push');
    target = i;
  }
  assert(target >= 0, 'cached-prime definition missing');
  return Buffer.concat(instructions.map((instruction, i) => Buffer.from(i === target
    ? encodeDataPush(cachePrimeLiterals(instruction.data))
    : encodeAuthenticationInstructions([instruction]))));
}
const cashCache = new Map();
const cash = (source) => {
  if (!cashCache.has(source)) cashCache.set(source, cachePrimeDefinition(cachePrimeDefinition(remapFunctionIds(compileCash(source), MSM_ID_OFFSET), 202n), 200n));
  return cashCache.get(source);
};
// Split compiled CashScript into its leading function-definition block and its main code.
const splitDefinitions = (bytecode) => {
  const list = decodeAuthenticationInstructions(bytecode);
  let i = 0;
  while (i + 2 < list.length && list[i + 2].opcode === OpcodesBCH.OP_DEFINE) i += 3;
  const length = encodeAuthenticationInstructions(list.slice(0, i)).length;
  return [bytecode.subarray(0, length), bytecode.subarray(length)];
};
// Stage code: define the helpers from genesis (the definition block sits `back` bytes before the
// end of input 3's unlocking, inside the hash-pinned genesis redeem), then run the stage's main.
const stage = (bytecode, definitions, back) => {
  const [own, main] = splitDefinitions(bytecode);
  assert(own.equals(definitions), 'stage helper definitions differ from the genesis copy');
  return Buffer.concat([assemble(`OP_3 OP_INPUTBYTECODE OP_SIZE NUM BACK OP_SUB OP_SPLIT OP_NIP NUM LENGTH OP_SPLIT OP_DROP`,
    new Map(), {}, {BACK: BigInt(back), LENGTH: BigInt(definitions.length)}),
  Buffer.from([...encodeDataPush(bigIntToVmNumber(LOADER_ID)), OpcodesBCH.OP_DEFINE, ...encodeDataPush(bigIntToVmNumber(LOADER_ID)), OpcodesBCH.OP_INVOKE]),
  main]);
};

const compileModule = (source, constants) => {
  const identifiers = new Map(source.functions.map(f => [f.name, f.originalId]));
  assert.equal(identifiers.size, source.functions.length, 'duplicate function name');
  const keys = [...identifiers.values()].map(id => Buffer.from(bigIntToVmNumber(BigInt(id))).toString('hex'));
  assert.equal(new Set(keys).size, source.functions.length, 'duplicate function identifier');
  const declarations = source.functions.map(f => ({
    name: f.name, id: f.originalId, bytecode: assemble(f.body, identifiers, constants),
  }));
  const program = Buffer.concat([
    assemble(source.prefix, identifiers, constants),
    ...declarations.map(f => Buffer.from([
      ...encodeDataPush(f.bytecode), ...encodeDataPush(bigIntToVmNumber(BigInt(f.id))), OpcodesBCH.OP_DEFINE,
    ])),
    assemble(source.main, identifiers, constants),
  ]);
  return {declarations, program};
};

const execPadded = STAGE_PADS.slice(0, 3).some(Boolean), terminalPadded = STAGE_PADS[3] > 0;

function buildWith({backExec, backTerminal}) {
  const programs = {}, declarations = {}, constants = {deploymentTag};
  ({declarations: declarations.shared, program: programs.shared} = compileModule(shared, constants));
  constants.sharedHash256 = hash256(programs.shared);
  ({declarations: declarations.genesis, program: programs.genesisUnsliced} = compileModule(genesis, constants));
  // genesis: the sliced program (dead vk_x auxiliary predicate dropped, see genesis-slice.mjs),
  // then MSM part A on its parked pushes (wa, n1, n0); part A pins input 0's state push
  programs.msmA = cash(sourceA({split: MSM_SPLIT, ownInputs: true, noPad: true,
    pinEnd: {idx: 0, back: backExec, size: EXEC_STATE_BYTES}, pinN: {idx: 4, back: backTerminal}}));
  programs.genesis = carrier(sliceGenesis(programs.genesisUnsliced), programs.msmA, 0);
  delete programs.genesisUnsliced;
  const [definitions] = splitDefinitions(programs.msmA);
  // executors: the shared-program loader, then the executor MSM stage on its parked state push
  // (and, with stage pads, the pad below it dropped first)
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
  programs.loader = Buffer.concat([fragmentReaderDeclaration, assemble(executor, loaderIdentifiers, constants)]);
  programs.msmExec = stage(cash(sourceExec({cuts: CUTS, backExec, backTerminal})), definitions, programs.msmA.length);
  programs.executor = Buffer.concat([execPadded ? Buffer.from([OpcodesBCH.OP_NIP]) : Buffer.alloc(0),
    carrier(programs.loader, programs.msmExec, 1)]);
  const workerLockings = [programs.executor, programs.executor, programs.executor, programs.genesis]
    .map(redeem => assemble(p2sh, new Map(), {redeemHash256: hash256(redeem)}));
  constants.workerLockingRoot = hash256(Buffer.concat(workerLockings.map(hash256)));
  // terminal: the densless terminal, then the final MSM stage on its parked pushes (zInv, state)
  ({declarations: declarations.terminal, program: programs.terminalBase} = compileModule(terminal, constants));
  programs.msmFinal = stage(cash(sourceFinal({from: CUTS[3]})), definitions, programs.msmA.length);
  if (cacheProfile === 'raw-both') programs.msmFinal = compactInverseCopy(programs.msmFinal);
  // Malleability pins (length / order / sign-bit) run before the densless terminal, paid once.
  const layoutExec = [
    { shared: layout.fragmentLengths[0], witness: 2560, table: 928 },
    { shared: layout.fragmentLengths[1], witness: 2304, table: 832 },
    { shared: layout.fragmentLengths[2], witness: 2560, table: 928 },
  ];
  const pinMode = PIN_MODE;
  const pins = pinMode === '0' ? Buffer.alloc(0)
    : pinMode === 'lenonly' ? compileTerminalPinsLenOnly()
    : pinMode === 'lensign' ? compileTerminalPinsLenSign(layoutExec)
    : pinMode === 'orderonly' ? compileTerminalPinsOrderOnly()
    : pinMode === 'lenorder' ? compileTerminalPinsLenOrder(layoutExec)
    : compileTerminalPins(layoutExec);
  programs.terminalBase = Buffer.concat([pins, programs.terminalBase]);
  programs.terminal = Buffer.concat([terminalPadded ? Buffer.from([OpcodesBCH.OP_ROT, OpcodesBCH.OP_DROP]) : Buffer.alloc(0),
    carrier(programs.terminalBase, programs.msmFinal, 4)]);
  delete programs.terminalBase;
  return {programs, declarations};
}

export function build() {
  // the stages locate each other's state push by redeem length, which the redeems embed:
  // iterate to the fixed point
  let backs = {backExec: 600, backTerminal: 6000};
  for (let round = 0; round < 8; round++) {
    const result = buildWith(backs);
    const next = {backExec: redeemPushBytes(result.programs.executor.length),
      backTerminal: redeemPushBytes(result.programs.terminal.length)};
    if (next.backExec === backs.backExec && next.backTerminal === backs.backTerminal) return finish(result);
    backs = next;
  }
  throw new Error('redeem lengths did not converge');
}

function finish({programs, declarations}) {
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

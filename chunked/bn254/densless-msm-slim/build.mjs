import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {writeFileSync} from 'node:fs';
import {pathToFileURL} from 'node:url';
import {sourceA, compile as compileCash} from '../pairfold5-msm/vkx-msm.mjs';
import {cachePrimeLiterals, cacheProfile} from './prime-cache.mjs';
import {compactInverseCopy} from './terminal-copies.mjs';
import {compactExecutorCleanup} from './executor-cleanup.mjs';
import {compressOrbitTables} from './table-orbits.mjs';
import {STATE_BYTES, EXEC_STATE_BYTES, sourceExec, sourceFinal} from './vkx-stages.mjs';
import {sliceGenesis} from './genesis-slice.mjs';
import {carrier, remapFunctionIds} from '../densless-msm/carrier.mjs';
import {compileTerminalPins, compileTerminalPinsLenOrder, compileTerminalPinsLenOnly, compileTerminalPinsOrderOnly, compileTerminalPinsLenSign, defaultPinIds, compactPinIds} from './malleability-pins.mjs';
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
const orbitProfile = cacheProfile === 'orbit' || cacheProfile === 'orbit-retained';
export const MSM_SPLIT = Number(process.env.MSM_SPLIT ?? (orbitProfile ? 37 : 31));
// Witness-byte cuts: genesis runs [0, CUTS[0]), executor k runs [CUTS[k], CUTS[k + 1]), the
// terminal runs [CUTS[3], 64) and finishes. CUTS[0] = 64 - MSM_SPLIT.
export const CUTS = (process.env.MSM_CUTS ?? (orbitProfile ? `${64 - MSM_SPLIT},36,47,55` : `${64 - MSM_SPLIT},43,54,60`)).split(',').map(Number);
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
// The shared-prime companion is deliberately scoped to the reviewed retained-orbit schedule.  The
// profile is opt-in and rejects accidental reuse for any other source profile.
export const SHARED_PRIME_PROFILE = process.env.SHARED_PRIME_PROFILE ?? 'off';
assert(['off', 'orbit-retained'].includes(SHARED_PRIME_PROFILE), 'unknown shared-prime profile');
const sharedPrimeEnabled = SHARED_PRIME_PROFILE === 'orbit-retained';
const selectedPinIds = sharedPrimeEnabled ? compactPinIds : defaultPinIds;
if (sharedPrimeEnabled) {
  assert.equal(cacheProfile, 'orbit-retained', 'shared-prime requires retained-orbit cache');
  assert.equal(MSM_SPLIT, 37, 'shared-prime requires split37');
  assert.deepEqual(CUTS, [27, 36, 47, 55], 'shared-prime requires the reviewed cuts');
  assert.equal(PIN_MODE, 'full', 'shared-prime requires full pins');
  assert.deepEqual(STAGE_PADS, [0, 0, 0, 0], 'shared-prime requires zero stage pads');
  assert.equal(GENESIS_PAD, 0, 'shared-prime requires zero genesis pad');
}
const SHARED_PRIME_ID = 37n;
const SHARED_PRIME_KEY = Buffer.from(encodeDataPush(bigIntToVmNumber(SHARED_PRIME_ID)));
const SHARED_PRIME_NAMESPACE_KEY = Buffer.from(bigIntToVmNumber(SHARED_PRIME_ID));
const SHARED_PRIME = Buffer.from('47fd7cd8168c203c8dca7168916a81975d588181b64550b829a031e1724e6430', 'hex');
const SHARED_PRIME_BODY = Buffer.concat([Buffer.from([SHARED_PRIME.length]), SHARED_PRIME]);
const SHARED_PRIME_CALL = Buffer.from([...SHARED_PRIME_KEY, OpcodesBCH.OP_INVOKE]);
const SHARED_PRIME_HELPERS = new Map([
  ['c800', {oldBytes: 262, oldSha256: '4e3b86b609032b3cda1823349f40433ef8912c082951bba7d42fbfecef0ceaca', sites: 4, newBytes: 142, newSha256: '8bacc2b3e0ecb73e367094f7871d470f3975e8c0e74ad63648d6be28e25e3140'}],
  ['c900', {oldBytes: 747, oldSha256: '7fa0b44ce7ca69604aaed156c32264d4251083d8157903ae0d076a337d79a303', sites: 1, newBytes: 717, newSha256: 'c460fb54b43e02d585058264c1ce885dc7952642b2d4e2c34e022452955483af'}],
  ['ca00', {oldBytes: 235, oldSha256: 'd08b357f43e3b9df7c7ae60f997042f69761de6a491d4275a4e9683d654f59db', sites: 1, newBytes: 205, newSha256: '494bcc157ffb0df016844324327fac3c663ab9ec79d52d0aa1f10bb5fc94463f'}],
  ['cb00', {oldBytes: 747, oldSha256: '5090c25c63de08861f8c123e200f8855356e2a935a896a65d5a9433765975221', sites: 1, newBytes: 717, newSha256: 'c743f37b48c6a3403b6a66003d89fb12d42b58c4a46ef5128c222c738ddc8fa4'}],
]);
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const sourceIds = source => source.functions.map(f => f.originalId);
if (sharedPrimeEnabled) {
  const existingIds = [...sourceIds(shared), ...sourceIds(genesis), ...sourceIds(terminal), -1, 100, Number(LOADER_ID), MSM_ID_OFFSET];
  assert(!existingIds.includes(Number(SHARED_PRIME_ID)), 'function37 namespace key is already occupied');
}
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
function sharePrimeDefinition(bytecode) {
  if (!sharedPrimeEnabled) return bytecode;
  const instructions = decodeAuthenticationInstructions(bytecode);
  assert(Array.isArray(instructions));
  const before = new Map();
  const helperIndices = new Set();
  for (let i = 0; i + 2 < instructions.length && instructions[i + 2].opcode === OpcodesBCH.OP_DEFINE; i += 3) {
    const id = Buffer.from(instructions[i + 1].data ?? []).toString('hex');
    assert.notEqual(id, SHARED_PRIME_NAMESPACE_KEY.toString('hex'), 'function37 key unexpectedly occupied in helper block');
    if (!SHARED_PRIME_HELPERS.has(id)) continue;
    assert(!before.has(id), `duplicate shared-prime helper ${id}`);
    const body = Buffer.from(instructions[i].data ?? []);
    const expected = SHARED_PRIME_HELPERS.get(id);
    assert.equal(body.length, expected.oldBytes, `unexpected ${id} helper length`);
    assert.equal(sha256(body), expected.oldSha256, `unexpected ${id} helper hash`);
    before.set(id, body);
    helperIndices.add(i);
  }
  assert.deepEqual([...before.keys()].sort(), [...SHARED_PRIME_HELPERS.keys()].sort(), 'shared-prime helper set changed');
  let changed = 0;
  const rewritten = instructions.map((instruction, i) => {
    if (!helperIndices.has(i)) return instruction;
    const id = Buffer.from(instructions[i + 1].data).toString('hex');
    const expected = SHARED_PRIME_HELPERS.get(id);
    const body = decodeAuthenticationInstructions(Buffer.from(instruction.data));
    assert(Array.isArray(body));
    let local = 0;
    const next = body.flatMap(item => {
      if (item.data && Buffer.from(item.data).equals(SHARED_PRIME)) {
        local += 1; changed += 1;
        return decodeAuthenticationInstructions(SHARED_PRIME_CALL);
      }
      return [item];
    });
    assert.equal(local, expected.sites, `unexpected ${id} literal count`);
    const encodedBody = Buffer.from(encodeAuthenticationInstructions(next));
    const candidate = Buffer.from(encodeDataPush(encodedBody));
    assert.equal(encodedBody.length, expected.newBytes, `unexpected ${id} candidate body length`);
    assert.equal(sha256(encodedBody), expected.newSha256, `unexpected ${id} candidate body hash`);
    const expanded = [];
    const candidateInstructions = decodeAuthenticationInstructions(encodedBody);
    for (let j = 0; j < candidateInstructions.length; j += 1) {
      const item = candidateInstructions[j];
      if (item.data && Buffer.from(item.data).equals(Buffer.from([0x25])) && candidateInstructions[j + 1]?.opcode === OpcodesBCH.OP_INVOKE) {
        expanded.push({opcode: SHARED_PRIME.length, data: SHARED_PRIME});
        j += 1;
      } else expanded.push(item);
    }
    assert(Buffer.from(encodeAuthenticationInstructions(expanded)).equals(before.get(id)), `${id} macro expansion changed`);
    return decodeAuthenticationInstructions(candidate)[0];
  });
  assert.equal(changed, 7, 'shared-prime candidate must rewrite seven helper literals');
  let firstMain = 0;
  while (firstMain + 2 < rewritten.length && rewritten[firstMain + 2].opcode === OpcodesBCH.OP_DEFINE) firstMain += 3;
  const prefix = Buffer.concat(rewritten.slice(0, firstMain).map(instruction => Buffer.from(encodeAuthenticationInstructions([instruction]))));
  const main = Buffer.concat(rewritten.slice(firstMain).map(instruction => Buffer.from(encodeAuthenticationInstructions([instruction]))));
  return Buffer.concat([
    prefix,
    Buffer.from(encodeDataPush(SHARED_PRIME_BODY)),
    Buffer.from(encodeDataPush(bigIntToVmNumber(SHARED_PRIME_ID))),
    Buffer.from([OpcodesBCH.OP_DEFINE]),
    main,
  ]);
}

// SU-a2 final candidate: reuse the already carried function-37 prime in the final MSM body.
// This is opt-in only; the reviewed source profiles retain their exact bytecode.
function reuseFinalPrimeCalls(bytecode) {
  if (!sharedPrimeEnabled) return bytecode;
  const instructions = decodeAuthenticationInstructions(bytecode);
  let definitionEnd = 0;
  while (definitionEnd + 2 < instructions.length && instructions[definitionEnd + 2].opcode === OpcodesBCH.OP_DEFINE) definitionEnd += 3;
  let replaced = 0;
  const next = instructions.flatMap((instruction, i) => {
    if (i < definitionEnd || instruction.data === undefined || !Buffer.from(instruction.data).equals(SHARED_PRIME)) return [instruction];
    replaced += 1;
    return decodeAuthenticationInstructions(SHARED_PRIME_CALL);
  });
  assert.equal(replaced, 5, 'SU-a1 final MSM must contain exactly five P literals');
  return Buffer.from(encodeAuthenticationInstructions(next));
}
const cashCache = new Map();
const cash = (source) => {
  if (!cashCache.has(source)) {
    const bytecode = cachePrimeDefinition(cachePrimeDefinition(remapFunctionIds(compileCash(source), MSM_ID_OFFSET), 202n), 200n);
    const compressed = orbitProfile ? compressOrbitTables(bytecode, cacheProfile === 'orbit-retained') : bytecode;
    cashCache.set(source, sharePrimeDefinition(compressed));
  }
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

const rawPushKey = instruction => {
  if (instruction.opcode === OpcodesBCH.OP_0) return Buffer.alloc(0);
  if (instruction.opcode === OpcodesBCH.OP_1NEGATE) return Buffer.from([0x81]);
  if (instruction.opcode >= OpcodesBCH.OP_1 && instruction.opcode <= OpcodesBCH.OP_16) return Buffer.from([instruction.opcode - OpcodesBCH.OP_1 + 1]);
  if (instruction.data !== undefined && instruction.opcode <= OpcodesBCH.OP_PUSHDATA_4) return Buffer.from(instruction.data);
  throw new Error(`malformed function namespace push opcode: ${instruction.opcode}`);
};
const functionKeys = bytecode => {
  const instructions = decodeAuthenticationInstructions(bytecode);
  const keys = [];
  for (let i = 0; i + 2 < instructions.length && instructions[i + 2].opcode === OpcodesBCH.OP_DEFINE; i += 3) {
    keys.push(rawPushKey(instructions[i + 1]).toString('hex'));
  }
  return keys;
};
const assertPinFunctionNamespace = (ids, bytecodes) => {
  const used = bytecodes.flatMap(functionKeys);
  const selected = [ids.sign, ids.number].map(id => Buffer.from(bigIntToVmNumber(BigInt(id))).toString('hex'));
  assert.equal(new Set(selected).size, selected.length, 'selected pin function identifiers must be distinct');
  for (const key of selected) assert(!used.includes(key), `selected pin function identifier collides with compiled namespace: ${key}`);
};

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
  programs.msmExec = compactExecutorCleanup(programs.msmExec);
  programs.executor = Buffer.concat([execPadded ? Buffer.from([OpcodesBCH.OP_NIP]) : Buffer.alloc(0),
    carrier(programs.loader, programs.msmExec, 1)]);
  const workerLockings = [programs.executor, programs.executor, programs.executor, programs.genesis]
    .map(redeem => assemble(p2sh, new Map(), {redeemHash256: hash256(redeem)}));
  constants.workerLockingRoot = hash256(Buffer.concat(workerLockings.map(hash256)));
  // terminal: the densless terminal, then the final MSM stage on its parked pushes (zInv, state)
  ({declarations: declarations.terminal, program: programs.terminalBase} = compileModule(terminal, constants));
  programs.msmFinal = stage(cash(sourceFinal({from: CUTS[3]})), definitions, programs.msmA.length);
  programs.msmFinal = compactInverseCopy(programs.msmFinal);
  programs.msmFinal = reuseFinalPrimeCalls(programs.msmFinal);
  assertPinFunctionNamespace(selectedPinIds, [programs.shared, programs.genesis, programs.loader, programs.msmA, programs.msmExec, programs.msmFinal, programs.terminalBase]);
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
    : compileTerminalPins(layoutExec, 10, selectedPinIds);
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

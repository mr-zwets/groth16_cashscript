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
export const MSM_SIGNED_RESIDUE = process.env.MSM_SIGNED_RESIDUE ?? 'off';
assert(['off', 'madd-ny'].includes(MSM_SIGNED_RESIDUE), 'unknown signed-residue profile');
assert(MSM_SIGNED_RESIDUE === 'off' || sharedPrimeEnabled, 'signed-residue requires shared prime');
// Opt-in WIP compiler profile: the current cached/signed helper library stays exact.
const msmCompilerEntry = process.env.MSM_CASHC;
const msmConstantHoisting = process.env.MSM_CONSTANT_HOISTING ?? 'off';
const packedDigits = process.env.MSM_PACKED_DIGITS === '1';
assert(!packedDigits || msmCompilerEntry && msmConstantHoisting === 'all',
  'packed MSM digits require the qualified hoisted compiler profile');
assert(['off', 'all'].includes(msmConstantHoisting), 'unknown MSM constant-hoisting profile');
assert(msmConstantHoisting === 'off' || msmCompilerEntry,
  'MSM constant hoisting requires the scheduled compiler');
assert(!msmCompilerEntry || sharedPrimeEnabled && MSM_SIGNED_RESIDUE === 'madd-ny',
  'scheduled MSM mains require the qualified retained-orbit signed profile');
const msmCompiler = msmCompilerEntry ? await import(pathToFileURL(msmCompilerEntry).href) : null;
const originalMsmCompiler = msmCompilerEntry ? await import('cashc') : null;
if (msmCompiler) assert.equal(typeof msmCompiler.compileString, 'function',
  'scheduled MSM compiler entry changed');

const selectedPinIds = sharedPrimeEnabled ? compactPinIds : defaultPinIds;
if (sharedPrimeEnabled) {
  assert.equal(cacheProfile, 'orbit-retained', 'shared-prime requires retained-orbit cache');
  assert.equal(MSM_SPLIT, 37, 'shared-prime requires split37');
  assert.deepEqual(CUTS, [27, 36, 47, 55], 'shared-prime requires the reviewed cuts');
  assert.equal(PIN_MODE, 'full', 'shared-prime requires full pins');
  assert.equal(STAGE_PADS.length, 4, 'unexpected stage pad count');
  assert.deepEqual(STAGE_PADS.slice(0, 3), [0, 0, 0], 'shared-prime requires zero executor pads');
  assert(Number.isInteger(STAGE_PADS[3]) && STAGE_PADS[3] >= 0 &&
    STAGE_PADS[3] <= (msmConstantHoisting === 'all' ? 64 : 0),
  'unexpected shared-prime terminal padding');
  if(packedDigits)assert(Number.isInteger(GENESIS_PAD)&&GENESIS_PAD>=0&&GENESIS_PAD<=23,
    'packed MSM genesis pad must be within0..23');
  else assert.equal(GENESIS_PAD, MSM_SIGNED_RESIDUE === 'madd-ny' ? 23 : 0, 'unexpected shared-prime genesis pad');
}
const SHARED_PRIME_ID = 11n;
const DISPLACED_PRIME_ID = 37;
const SHARED_PRIME_KEY = Buffer.from(encodeDataPush(bigIntToVmNumber(SHARED_PRIME_ID)));
const SHARED_PRIME_NAMESPACE_KEY = Buffer.from(bigIntToVmNumber(SHARED_PRIME_ID));
const SHARED_PRIME = Buffer.from('47fd7cd8168c203c8dca7168916a81975d588181b64550b829a031e1724e6430', 'hex');
const SHARED_PRIME_BODY = Buffer.concat([Buffer.from([SHARED_PRIME.length]), SHARED_PRIME]);
const SHARED_PRIME_CALL = Buffer.from([...SHARED_PRIME_KEY, OpcodesBCH.OP_INVOKE]);
const SCALAR_ORDER_ID = sharedPrimeEnabled ? 34n : 38n;
const TERMINAL_SEQUENCE0_ID = 38n;
const SCALAR_ORDER_KEY = Buffer.from(encodeDataPush(bigIntToVmNumber(SCALAR_ORDER_ID)));
const SCALAR_ORDER_BYTES = Buffer.from(bigIntToVmNumber(SCALAR_FIELD));
const SCALAR_ORDER_CALL = Buffer.from([...SCALAR_ORDER_KEY, OpcodesBCH.OP_INVOKE]);
const SHARED_PRIME_HELPERS = new Map([
  ['c800', {oldBytes: 262, oldSha256: '4e3b86b609032b3cda1823349f40433ef8912c082951bba7d42fbfecef0ceaca', sites: 4, newBytes: 138, newSha256: 'd6ecc3dbfe51ea41765084768b2fd72c5274487ce8f6c7b59e2355108b245369'}],
  ['c900', {oldBytes: 683, oldSha256: '05736bde068f4f8d8a0595cd3a06a36351d19d02509e22dd5379021d60f4457e', sites: 1, newBytes: 652, newSha256: '1edf97182891b362488cd2f99485c84bd328d3252905bc573e4035d0301004da'}],
  ['ca00', {oldBytes: 235, oldSha256: 'd08b357f43e3b9df7c7ae60f997042f69761de6a491d4275a4e9683d654f59db', sites: 1, newBytes: 204, newSha256: 'b1fe20e8f1f9b5a3a696de6cc34baa2964ede6f5f2eb71b8345079f2998368f5'}],
  ['cb00', {oldBytes: 683, oldSha256: '25b32d3d5d4e7949676c91c9ba2e78a40e02e7988d1779df852bf2204de58d19', sites: 1, newBytes: 652, newSha256: 'f2cb2c2ab48660947ca7deac7c3db51d94a77035b56b06d3f955da4f3185589d'}],
]);
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const sourceIds = source => source.functions.map(f => f.originalId);
// Relocate the occupied short key symbolically, including every nested CALL.
// The reviewed genesis slicer already omits its uncalled key11 declaration.
const primeSourceForProfile = source => sharedPrimeEnabled ? {
  ...source,
  functions: source.functions.map(f => f.originalId === Number(SHARED_PRIME_ID)
    ? {...f, originalId: DISPLACED_PRIME_ID} : f),
} : source;
// Only the retained shared-prime profile compacts these reviewed opaque rotations.
const rotateHelperBodies = (source, expected) => {
  if (!sharedPrimeEnabled) return source;
  const pattern = 'OP_SWAP OP_TOALTSTACK OP_SWAP OP_FROMALTSTACK';
  const remaining = new Set(Object.keys(expected));
  const functions = source.functions.map(f => {
    if (!Object.hasOwn(expected, f.name)) return f;
    assert(remaining.delete(f.name), `duplicate helper ${f.name}`);
    const [id, digest, count] = expected[f.name];
    const body = f.body.trim().split(/\s+/).join(' ');
    assert.equal(f.originalId, id, `unexpected helper key ${f.name}`);
    assert.equal(createHash('sha256').update(body).digest('hex'), digest, `unexpected helper body ${f.name}`);
    assert.equal(body.split(pattern).length - 1, count, `unexpected rotation count ${f.name}`);
    return {...f, body: body.replaceAll(pattern, 'OP_ROT OP_ROT')};
  });
  assert.equal(remaining.size, 0, 'missing rotation helper');
  return {...source, functions};
};
const sharedSource = primeSourceForProfile(rotateHelperBodies(shared, {
  millerEvent: [16, '60fd4eddbe305d33a07a5275d0e6e348fd67ff06372b3e386e8ba08548788cff', 3],
  sharedSequence10: [19, '8ced1f9b3d18ec16e2ae94e6ded7e4934bb7dab6963ff903db6de5c31d23ab1a', 2],
  sharedSequence11: [0, '10d38744632c996cd081cc046b2b5a2f299148ee5ec4f5a8ebdf1efc076d3eae', 1],
}));
if (sharedPrimeEnabled) {
  const cycleHelpers = sharedSource.functions.filter(f => f.name === 'sharedSequence28');
  assert.equal(cycleHelpers.length, 1, 'shared eleven-cycle helper count changed');
  assert.equal(cycleHelpers[0].originalId, 22, 'shared eleven-cycle helper key changed');
  const cycleBody = cycleHelpers[0].body.trim().split(/\s+/).join(' ');
  assert.equal(sha256(cycleBody), 'd32590810168d3028ae743b4fe41e2c60fbf0a7425b0a628f0e98357177c5c52', 'shared eleven-cycle helper body changed');
  const cycle = Array(11).fill('OP_10 OP_ROLL').join(' ');
  assert.equal(cycleBody, `OP_PICK CALL sharedSequence10 ${cycle}`, 'shared eleven-cycle prefix or tail changed');
  sharedSource.functions = sharedSource.functions.map(f => f === cycleHelpers[0]
    ? {...f, body: 'OP_PICK CALL sharedSequence10 OP_10 OP_PICK OP_DROP'} : f);
  const remainderHelpers = sharedSource.functions.filter(f => f.name === 'sharedSequence14');
  assert.equal(remainderHelpers.length, 1, 'shared discarded-remainder helper count changed');
  assert.equal(remainderHelpers[0].originalId, 24, 'shared discarded-remainder helper key changed');
  const remainderBody = remainderHelpers[0].body.trim().split(/\s+/).join(' ');
  assert.equal(sha256(remainderBody), 'c72297ab9035dfc154f1a2580df875f1095b310d1bfc9128df7545d6fe1e7e5f', 'shared discarded-remainder helper body changed');
  const discardedRemainder = 'OP_OVER OP_MOD OP_DUP OP_NUMEQUALVERIFY';
  assert.equal(remainderBody.split(discardedRemainder).length - 1, 1, 'shared discarded-remainder count changed');
  sharedSource.functions = sharedSource.functions.map(f => f === remainderHelpers[0]
    ? {...f, body: remainderBody.replace(discardedRemainder, 'OP_DROP')} : f);
  const sliceHelpers = sharedSource.functions.filter(f => f.name === 'sharedSequence20');
  assert.equal(sliceHelpers.length, 1, 'shared fixed-prefix helper count changed');
  assert.equal(sliceHelpers[0].originalId, DISPLACED_PRIME_ID, 'shared fixed-prefix helper key changed');
  assert.equal(sliceHelpers[0].body.trim().split(/\s+/).join(' '),
    'OP_PUSHBYTES_1 0x20 OP_SPLIT OP_SWAP OP_SIZE OP_NIP OP_PUSHBYTES_1 0x20 OP_NUMEQUALVERIFY',
    'shared fixed-prefix helper body changed');
  sharedSource.functions = sharedSource.functions.map(f => f === sliceHelpers[0]
    ? {...f, body: 'OP_PUSHBYTES_1 0x20 OP_SPLIT OP_NIP'} : f);
  const emptyCheck = 'OP_SIZE OP_NIP OP_0 OP_NUMEQUALVERIFY';
  const emptyBytes = 'OP_0 OP_EQUALVERIFY';
  const eventHelpers = sharedSource.functions.filter(f => f.name === 'millerEvent');
  assert.equal(eventHelpers.length, 1, 'shared event helper count changed');
  assert.equal(eventHelpers[0].originalId, 16, 'shared event helper key changed');
  assert.equal(eventHelpers[0].body.split(emptyCheck).length - 1, 3, 'shared event empty checks changed');
  sharedSource.functions = sharedSource.functions.map(f => f === eventHelpers[0]
    ? {...f, body: f.body.replaceAll(emptyCheck, emptyBytes)} : f);
  assert.equal(sharedSource.main.split(emptyCheck).length - 1, 2, 'shared parser empty checks changed');
  sharedSource.main = sharedSource.main.replaceAll(emptyCheck, emptyBytes);
  const sizeCheck = 'OP_PUSHBYTES_1 0x20 OP_SPLIT OP_DUP OP_SIZE OP_NIP OP_PUSHBYTES_1 0x20 OP_NUMEQUALVERIFY';
  const compactSizeCheck = 'OP_PUSHBYTES_1 0x20 OP_SPLIT OP_SIZE OP_PUSHBYTES_1 0x20 OP_NUMEQUALVERIFY';
  const sizeHelpers = sharedSource.functions.filter(f => f.name === 'sharedSequence10');
  assert.equal(sizeHelpers.length, 1, 'shared size helper count changed');
  assert.equal(sizeHelpers[0].originalId, 19, 'shared size helper key changed');
  assert.equal(sizeHelpers[0].body.split(sizeCheck).length - 1, 1, 'shared helper size check changed');
  sharedSource.functions = sharedSource.functions.map(f => f === sizeHelpers[0]
    ? {...f, body: f.body.replace(sizeCheck, compactSizeCheck)} : f);
  assert.equal(sharedSource.main.split(sizeCheck).length - 1, 1, 'shared main size check changed');
  sharedSource.main = sharedSource.main.replace(sizeCheck, compactSizeCheck);
  const exhausted = 'OP_SWAP OP_SIZE OP_NIP OP_0 OP_NUMEQUAL OP_SWAP OP_SIZE OP_NIP OP_0 OP_NUMEQUAL OP_BOOLAND OP_VERIFY';
  const emptyPair = 'OP_SWAP OP_0 OP_EQUAL OP_SWAP OP_0 OP_EQUAL OP_BOOLAND OP_VERIFY';
  assert.equal(sharedSource.main.split(exhausted).length - 1, 1, 'shared buffer exhaustion predicate changed');
  sharedSource.main = sharedSource.main.replace(exhausted, emptyPair);
  const loops = sharedSource.main.match(/\bOP_BEGIN\b[\s\S]*?\bOP_UNTIL\b/g) ?? [];
  assert.equal(loops.length, 1, 'shared Miller loop count changed');
  let pairs = 0, doubles = 0;
  let loop = loops[0].replace(/OP_SWAP (OP_TOALTSTACK OP_TOALTSTACK OP_FROMALTSTACK OP_FROMALTSTACK|OP_TOALTSTACK OP_FROMALTSTACK)/g, (_, moves) => {
    if (moves.split(' ').length === 4) doubles += 1;
    else pairs += 1;
    return 'OP_SWAP';
  });
  assert.equal(pairs, 8, 'shared Miller stack pair count changed');
  assert.equal(doubles, 1, 'shared Miller double stack pair count changed');
  const permutation = 'OP_PICK OP_SWAP OP_TOALTSTACK OP_2 OP_FROMALTSTACK';
  assert.equal(loop.split(permutation).length - 1, 2, 'shared Miller guarded permutation count changed');
  loop = loop.replaceAll(permutation, 'OP_PICK OP_2 OP_ROT');
  sharedSource.main = sharedSource.main.replace(loops[0], loop);
}
const terminalSourceForProfile = source => {
  if (!sharedPrimeEnabled) return source;
  const identifiers = new Map([
    ['terminalSequence0', Number(TERMINAL_SEQUENCE0_ID)],
    ['terminalSubsequenceA', 10],
    ['terminalSequence12', 33],
    ['terminalSequence29', 35],
  ]);
  const functions = source.functions.map(f => identifiers.has(f.name)
    ? {...f, originalId: identifiers.get(f.name)}
    : f);
  assert(!functions.some(f => f.name === 'terminalScalarOrder'), 'terminal scalar helper already present');
  functions.push({
    name: 'terminalScalarOrder',
    originalId: Number(SCALAR_ORDER_ID),
    body: `OP_PUSHBYTES_${SCALAR_ORDER_BYTES.length} 0x${SCALAR_ORDER_BYTES.toString('hex')}`,
  });
  return {...source, functions};
};
const terminalSource = terminalSourceForProfile(primeSourceForProfile(rotateHelperBodies(terminal, {
  terminalSequence21: [6, '1a333aa618a0b9fd48d05f73a1fdd766a5f17d6240a17e7c5d6d8eed172607de', 1],
})));
if (sharedPrimeEnabled) {
  const existingIds = [...sourceIds(sharedSource), ...sourceIds(terminalSource), -1, 100, Number(LOADER_ID), MSM_ID_OFFSET];
  assert(!existingIds.includes(Number(SHARED_PRIME_ID)), 'shared-prime namespace key is already occupied');
  assert.equal(sourceIds(terminalSource).filter(id => id === Number(SCALAR_ORDER_ID)).length, 1, 'terminal scalar identifier must be unique');
  assert.equal(sourceIds(terminalSource).filter(id => id === Number(TERMINAL_SEQUENCE0_ID)).length, 1, 'terminal sequence0 id38 must be unique');
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
    assert.notEqual(id, SHARED_PRIME_NAMESPACE_KEY.toString('hex'), 'shared-prime key unexpectedly occupied in helper block');
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
      if (candidateInstructions[j + 1]?.opcode === OpcodesBCH.OP_INVOKE && rawPushKey(item).equals(SHARED_PRIME_NAMESPACE_KEY)) {
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
  assert.equal(replaced, msmConstantHoisting === 'all' ? 1 : 5, 'unexpected final MSM P literal count for selected compiler');
  return Buffer.from(encodeAuthenticationInstructions(next));
}
function reuseTerminalScalarOrder(bytecode) {
  if (!sharedPrimeEnabled) return bytecode;
  const instructions = decodeAuthenticationInstructions(bytecode);
  let replaced = 0;
  const next = instructions.flatMap(instruction => {
    if (instruction.data === undefined || !Buffer.from(instruction.data).equals(SCALAR_ORDER_BYTES)) return [instruction];
    replaced += 1;
    return decodeAuthenticationInstructions(SCALAR_ORDER_CALL);
  });
  assert.equal(replaced, msmConstantHoisting === 'all' ? 1 : 4, 'unexpected terminal scalar-order literal count for selected compiler');
  return Buffer.from(encodeAuthenticationInstructions(next));
}
// Canonical ny uses a signed remainder and the retained prime instead of a P-squared bias.
function normalizeMixedAddNy(bytecode) {
  if (MSM_SIGNED_RESIDUE === 'off') return bytecode;
  const instructions = decodeAuthenticationInstructions(bytecode);
  let changed = 0;
  let definitionEnd = 0;
  while (definitionEnd + 2 < instructions.length && instructions[definitionEnd + 2].opcode === OpcodesBCH.OP_DEFINE) definitionEnd += 3;
  const next = instructions.map((instruction, i) => {
    if (i >= definitionEnd || i % 3 !== 0 || instructions[i + 2]?.opcode !== OpcodesBCH.OP_DEFINE ||
        Buffer.from(instructions[i + 1].data ?? []).toString('hex') !== 'ca00') return instruction;
    const body = Buffer.from(instruction.data);
    assert.equal(body.length, 204, 'unexpected MADD body length');
    assert.equal(sha256(body), 'b1fe20e8f1f9b5a3a696de6cc34baa2964ede6f5f2eb71b8345079f2998368f5', 'unexpected MADD body');
    const normalizer = Buffer.from('76009f63789368', 'hex');
    const candidate = Buffer.concat([body.subarray(0, 121), body.subarray(187, 197), normalizer, body.subarray(197)]);
    assert.equal(candidate.length, 145);
    assert.equal(sha256(candidate), '6d5cbba716993b231aafad6de09d139ffcfa365d73a79c937e7802030bc870ef');
    const inverse = Buffer.concat([candidate.subarray(0, 121), body.subarray(121, 187), candidate.subarray(121, 131), candidate.subarray(138)]);
    assert(inverse.equals(body), 'MADD inverse changed');
    changed += 1;
    return decodeAuthenticationInstructions(encodeDataPush(candidate))[0];
  });
  assert.equal(changed, 1, 'expected one MADD definition');
  return Buffer.from(encodeAuthenticationInstructions(next));
}
// Retain the qualified arithmetic implementation; schedule only the stage mains.
const compileMsm = (source) => {
  const original = compileCash(source);
  if (!msmCompiler) return original;
  const before = originalMsmCompiler.compileString(source, {
    rescheduleStacks: true, disableInlining: true,
  });
  assert(original.equals(Buffer.from(before.debug.bytecode, 'hex')),
    'original MSM compiler metadata differs from the active compiler');
  const candidate = msmCompiler.compileString(source, {
    rescheduleStacks: true, disableInlining: true, renumberFunctionIds: false,
    ...(msmConstantHoisting === 'all' ? {constantHoisting: 'all'} : {}),
  });
  assert.deepEqual(candidate.abi, before.abi, 'MSM spend interface changed');
  assert.deepEqual(candidate.constructorInputs, before.constructorInputs,
    'MSM constructor interface changed');
  const [originalDefinitions] = splitDefinitions(original);
  assert.equal(originalDefinitions.length, 3016, 'original MSM helper prefix length changed');
  assert.equal(sha256(originalDefinitions), '07e596d5b6a7dac66d7a2cc51621c42e5dc5f063bb98e0474e791114b83aaa54',
    'original MSM helper prefix changed');
  const [definitions, main] = splitDefinitions(Buffer.from(candidate.debug.bytecode, 'hex'));
  assert.equal(decodeAuthenticationInstructions(definitions).length, 12,
    'scheduled MSM definition framing changed');
  const declared = artifact => artifact.debug.functions.filter(fn => Number.isInteger(fn.id));
  const oldFunctions = declared(before), newFunctions = declared(candidate);
  const oldByName = new Map(oldFunctions.map(fn => [fn.name, fn]));
  assert.equal(oldByName.size, 4, 'original MSM helper set changed');
  assert.equal(oldFunctions.length, 4, 'original MSM helper names are not unique');
  assert.equal(newFunctions.length, 4, 'scheduled MSM helper set changed');
  assert.equal(new Set(newFunctions.map(fn => fn.name)).size, 4,
    'scheduled MSM helper names are not unique');
  const keyFor = id => Buffer.from(bigIntToVmNumber(BigInt(id))).toString('hex');
  const mapping = new Map(), inverse = new Map();
  newFunctions.forEach(fn => {
    const old = oldByName.get(fn.name);
    assert(old, `unknown scheduled MSM helper: ${fn.name}`);
    assert.deepEqual(fn.inputs, old.inputs, `scheduled MSM helper interface changed: ${fn.name}`);
    mapping.set(keyFor(fn.id), old.id);
    inverse.set(keyFor(old.id), fn.id);
  });
  assert.equal(mapping.size, 4, 'scheduled MSM helper keys are not unique');
  assert.equal(inverse.size, 4, 'original MSM helper keys are not unique');
  const rename = (bytecode, identifiers) => {
    const instructions = decodeAuthenticationInstructions(bytecode);
    for (let index = 0; index < instructions.length; index += 1) {
      assert.notEqual(instructions[index].opcode, OpcodesBCH.OP_DEFINE,
        'scheduled MSM main unexpectedly defines a function');
      if (instructions[index].opcode !== OpcodesBCH.OP_INVOKE) continue;
      assert(index > 0, 'scheduled MSM call has no key');
      const key = rawPushKey(instructions[index - 1]).toString('hex');
      assert(identifiers.has(key), 'scheduled MSM main contains an unknown call key');
      instructions[index - 1] = decodeAuthenticationInstructions(encodeDataPush(
        bigIntToVmNumber(BigInt(identifiers.get(key))),
      ))[0];
    }
    return Buffer.from(encodeAuthenticationInstructions(instructions));
  };
  const renamed = rename(main, mapping);
  assert(rename(renamed, inverse).equals(main), 'scheduled MSM namespace inverse changed');
  return Buffer.concat([originalDefinitions, renamed]);
};

const cashCache = new Map();
const cash = (source) => {
  if (!cashCache.has(source)) {
    const bytecode = cachePrimeDefinition(cachePrimeDefinition(remapFunctionIds(compileMsm(source), MSM_ID_OFFSET), 202n), 200n);
    const compressed = orbitProfile ? compressOrbitTables(bytecode, cacheProfile === 'orbit-retained', sharedPrimeEnabled) : bytecode;
    cashCache.set(source, normalizeMixedAddNy(sharePrimeDefinition(compressed)));
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

const compileModule = (source, constants, extraNumbers = {}) => {
  const identifiers = new Map(source.functions.map(f => [f.name, f.originalId]));
  assert.equal(identifiers.size, source.functions.length, 'duplicate function name');
  const keys = [...identifiers.values()].map(id => Buffer.from(bigIntToVmNumber(BigInt(id))).toString('hex'));
  assert.equal(new Set(keys).size, source.functions.length, 'duplicate function identifier');
  const declarations = source.functions.map(f => ({
    name: f.name, id: f.originalId, bytecode: assemble(f.body, identifiers, constants, extraNumbers),
  }));
  const program = Buffer.concat([
    assemble(source.prefix, identifiers, constants, extraNumbers),
    ...declarations.map(f => Buffer.from([
      ...encodeDataPush(f.bytecode), ...encodeDataPush(bigIntToVmNumber(BigInt(f.id))), OpcodesBCH.OP_DEFINE,
    ])),
    assemble(source.main, identifiers, constants, extraNumbers),
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
  const used = [...bytecodes.flatMap(functionKeys), Buffer.from(bigIntToVmNumber(LOADER_ID)).toString('hex')];
  const selected = [ids.sign, ids.number].map(id => Buffer.from(bigIntToVmNumber(BigInt(id))).toString('hex'));
  assert.equal(new Set(selected).size, selected.length, 'selected pin function identifiers must be distinct');
  for (const key of selected) assert(!used.includes(key), `selected pin function identifier collides with compiled namespace: ${key}`);
};

function buildWith({backExec, backTerminal}) {
  const programs = {}, declarations = {}, constants = {deploymentTag};
  ({declarations: declarations.shared, program: programs.shared} = compileModule(sharedSource, constants));
  // Keep the first two carriers fixed; derive the final fragment and every reader
  // from the assembled shared program, rather than duplicating its byte growth.
  const fragmentLengths = [...layout.fragmentLengths];
  if (sharedPrimeEnabled) fragmentLengths[2] = programs.shared.length - fragmentLengths[0] - fragmentLengths[1];
  const wireLayout = {...layout, fragmentLengths};
  const layoutExec = [
    { shared: fragmentLengths[0], witness: 2560, table: 928 },
    { shared: fragmentLengths[1], witness: 2304, table: 832 },
    { shared: fragmentLengths[2], witness: 2560, table: 928 },
  ];
  const last = layoutExec[2];
  const tableOffset = wireLayout.fragmentOffset + last.shared + redeemPushBytes(last.witness)
    + redeemPushBytes(last.table) - last.table;
  const extraNumbers = {
    ...Object.fromEntries(fragmentLengths.map((length, i) => [`FRAGMENT_${i}_BYTES`, BigInt(length)])),
    TABLE_2_OFFSET: BigInt(tableOffset),
    QUOTIENT_2_OFFSET: BigInt(tableOffset + last.table
      + redeemPushBytes(wireLayout.quotientLengths[2]) - wireLayout.quotientLengths[2]),
  };
  let terminalWithLayout = terminalSource;
  if (sharedPrimeEnabled) {
    const tableReader = 'OP_PUSHBYTES_2 0xa003 OP_PUSHBYTES_2 0x630d OP_2 CALL readBoundedInputSlice';
    const quotientReader = 'OP_INPUTBYTECODE OP_PUSHBYTES_2 0x0611 OP_SPLIT OP_NIP OP_PUSHBYTES_2 0xe004 OP_SPLIT OP_DROP';
    assert.equal(sharedSource.main.split(tableReader).length, 2, 'shared input2 table reader changed');
    assert.equal(terminalSource.main.split(quotientReader).length, 2, 'terminal input2 quotient reader changed');
    const sharedWithLayout = {...sharedSource, main: sharedSource.main.replace(tableReader,
      'OP_PUSHBYTES_2 0xa003 NUM TABLE_2_OFFSET OP_2 CALL readBoundedInputSlice')};
    terminalWithLayout = {...terminalSource, main: terminalSource.main.replace(quotientReader,
      'OP_INPUTBYTECODE NUM QUOTIENT_2_OFFSET OP_SPLIT OP_NIP OP_PUSHBYTES_2 0xe004 OP_SPLIT OP_DROP')};
    const length = programs.shared.length;
    ({declarations: declarations.shared, program: programs.shared} = compileModule(sharedWithLayout, constants, extraNumbers));
    assert.equal(programs.shared.length, length, 'shared reader offset changed its encoded width');
  }
  constants.sharedHash256 = hash256(programs.shared);
  ({declarations: declarations.genesis, program: programs.genesisUnsliced} = compileModule(genesis, constants));
  // genesis: the sliced program (dead vk_x auxiliary predicate dropped, see genesis-slice.mjs),
  // then MSM part A on its parked pushes (wa, n1, n0); part A pins input 0's state push
  programs.msmA = cash(sourceA({split: MSM_SPLIT, ownInputs: true, noPad: true, packedDigits,
    pinEnd: {idx: 0, back: backExec, size: EXEC_STATE_BYTES}, pinN: {idx: 4, back: backTerminal}}));
  const slicedGenesis = sliceGenesis(programs.genesisUnsliced);
  if (sharedPrimeEnabled) {
    assert.equal(slicedGenesis[0], OpcodesBCH.OP_DROP);
    assert(!functionKeys(slicedGenesis.subarray(1)).includes(SHARED_PRIME_NAMESPACE_KEY.toString('hex')),
      'shared-prime key occupied in the emitted genesis namespace');
  }
  programs.genesis = carrier(slicedGenesis, programs.msmA, 0);
  delete programs.genesisUnsliced;
  const [definitions] = splitDefinitions(programs.msmA);
  // executors: the shared-program loader, then the executor MSM stage on its parked state push
  // (and, with stage pads, the pad below it dropped first)
  const loaderIdentifiers = new Map([['fragmentReader', -1], ['sharedProgram', 100]]);
  const globalFunctionKeys = [
    ...loaderIdentifiers.values(),
    ...sharedSource.functions.map(f => f.originalId),
  ].map(id => Buffer.from(bigIntToVmNumber(BigInt(id))).toString('hex'));
  assert.equal(new Set(globalFunctionKeys).size, globalFunctionKeys.length,
    'loader/shared function identifier byte collision');
  const fragmentReaderBytecode = assemble(fragmentReader, loaderIdentifiers, constants);
  const fragmentReaderDeclaration = Buffer.from([
    ...encodeDataPush(fragmentReaderBytecode),
    ...encodeDataPush(bigIntToVmNumber(-1n)),
    OpcodesBCH.OP_DEFINE,
  ]);
  programs.loader = Buffer.concat([fragmentReaderDeclaration, assemble(executor, loaderIdentifiers, constants, extraNumbers)]);
  programs.msmExec = stage(cash(sourceExec({cuts: CUTS, backExec, backTerminal, packedDigits})), definitions, programs.msmA.length);
  // The selected compiler emits its own stage cleanup; legacy rewrites retain their guards.
  if (!msmCompiler) programs.msmExec = compactExecutorCleanup(programs.msmExec);
  programs.executor = Buffer.concat([execPadded ? Buffer.from([OpcodesBCH.OP_NIP]) : Buffer.alloc(0),
    carrier(programs.loader, programs.msmExec, 1)]);
  const workerLockings = [programs.executor, programs.executor, programs.executor, programs.genesis]
    .map(redeem => assemble(p2sh, new Map(), {redeemHash256: hash256(redeem)}));
  constants.workerLockingRoot = hash256(Buffer.concat(workerLockings.map(hash256)));
  // terminal: the densless terminal, then the final MSM stage on its parked pushes (zInv, state)
  ({declarations: declarations.terminal, program: programs.terminalBase} = compileModule(terminalWithLayout, constants, extraNumbers));
  programs.msmFinal = stage(cash(sourceFinal({from: CUTS[3], packedDigits})), definitions, programs.msmA.length);
  if (msmConstantHoisting === 'off') programs.msmFinal = compactInverseCopy(programs.msmFinal);
  programs.msmFinal = reuseFinalPrimeCalls(programs.msmFinal);
  programs.msmFinal = reuseTerminalScalarOrder(programs.msmFinal);
  // Pins coexist with the terminal module, imported MSM definitions, and stage loader only.
  assertPinFunctionNamespace(selectedPinIds, [programs.terminalBase, definitions]);
  // Malleability pins (length / order / sign-bit) run before the densless terminal, paid once.
  const pinMode = PIN_MODE;
  const pins = pinMode === '0' ? Buffer.alloc(0)
    : pinMode === 'lenonly' ? compileTerminalPinsLenOnly()
    : pinMode === 'lensign' ? compileTerminalPinsLenSign(layoutExec)
    : pinMode === 'orderonly' ? compileTerminalPinsOrderOnly()
    : pinMode === 'lenorder' ? compileTerminalPinsLenOrder(layoutExec)
    : compileTerminalPins(layoutExec, 10, selectedPinIds, sharedPrimeEnabled);
  programs.terminalBase = Buffer.concat([pins, programs.terminalBase]);
  // The hoisted profile's pad sits below n1, n0, zInv and the carried state.
  const terminalPadPrefix = msmConstantHoisting === 'all'
    ? Buffer.from([OpcodesBCH.OP_4, OpcodesBCH.OP_ROLL, OpcodesBCH.OP_DROP])
    : Buffer.from([OpcodesBCH.OP_ROT, OpcodesBCH.OP_DROP]);
  programs.terminal = Buffer.concat([terminalPadded ? terminalPadPrefix : Buffer.alloc(0),
    carrier(programs.terminalBase, programs.msmFinal, 4)]);
  delete programs.terminalBase;
  return {programs, declarations, layout: wireLayout};
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

function finish({programs, declarations, layout}) {
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

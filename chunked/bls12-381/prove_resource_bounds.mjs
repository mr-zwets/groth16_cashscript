// Proof-independent BCH_2026 resource certificate for the generated one-transaction
// BLS12-381 verifier. The builder emits exact transformed sources and ABI shapes;
// this script recompiles each redeem, pins its program/control layout, substitutes
// the integer envelopes proven by bound_analysis.mjs, and solves the coupled
// operation-density padding fixed point.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { compileFile, utils } from 'cashc';
import {
  OpcodesBchSpec,
  bigIntToVmNumber,
  binToHex,
  createInstructionSetBch2026,
  createVirtualMachine,
  decodeAuthenticationInstructions,
  encodeAuthenticationInstructions,
  encodeDataPush,
  encodeLockingBytecodeP2sh32,
  encodeTransactionBch,
  executionIsActive,
  hash256,
  hexToBin,
  ripemd160,
  secp256k1,
  sha1,
  sha256,
  stackItemIsTruthy,
  vmNumberToBigInt,
} from '@bitauth/libauth';

const here = dirname(fileURLToPath(import.meta.url));
const generated = join(here, 'generated', 'linked-residue');
const manifestPath = join(generated, 'resource_bounds_inputs.json');
const manifestBytes = readFileSync(manifestPath);
const manifest = JSON.parse(manifestBytes);
const sha256Hex = (value) => createHash('sha256').update(value).digest('hex');
const bodyHash = (instructions) => sha256Hex(encodeAuthenticationInstructions(instructions));
const { asmToBytecode } = utils;
const P = 4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787n;
const GLV_INPUT_COUNT = 1;

const EXPECTED_BOUND_ANALYSIS_SHA256 = 'caa73accba876075490abe6e89d7a7c1575932d5331a0635a976dda0bdfd6bb4';
const EXPECTED_MANIFEST_SHA256 = '23e5086a2cc2b319edd048855d24c75a63659defbdb9bfac050e1d60712be5f8';
const EXPECTED_PROGRAM_FINGERPRINTS = [
  'f91cafec5b97c496ab2e86484cfe8cad4d9f4ac59d1b2c38717604f9b932b8a9',
  'bee1048ec686d38dad7748f9d8d2c6ae76f0f5e2f2b526b6a8c3328869503267',
  '970d9e75ce727706471e7cb5a4b604cf8de292192d10e391fdea197468ec2154',
  'f708674121df6a2addea7bda5e10609e94ca2ad14f2d62022987a68c3350169c',
  '1852470a39acd08df0634109f05414076e44fd748e317e49e88f404a99400b21',
  'd746669f2702f62e9583d0ffc8039eaad6a4cfcbfff61e00e26f60d96ccc9b04',
  '0d801737c6451a2ba07e41dfd44f509b60dcfa0647d60f7c9b647c0e9cdb3209',
  'd4b6eb5cbc9dec6ccc2e21e9cd984682ac96db76ef39b37965d7f9af99abb082',
  'ce324c04b4669a74dc8fde7431839a2fa42aa957c4bc5ebb51ec0afbb0129ac3',
  '8b11437361cb72ec7ece5038b4ba5010c0cbdcd8f837cddf8e1c8187597cc583',
  'e93ce50e0117485520c0284b5ec6a2714e0ca97eb63785dfbc5c2518d2e89240',
];
const EXPECTED_NUMERIC_FINGERPRINTS = [
  'b5b771cd50bf72dc818d443e317cff8f0d414e1d6aa7f08e9322eebe9e37a7d1',
  '7a606c823af43a1ab3e3ab0c9cbf132382357045af70e44318a28bc7ee18360a',
  '11521fca95fd2fd8e959bdf2fbe76485afc88e09e9f8a0ea3129c74885475c47',
  'a04e222313c3a1d753931fb01f7c7f9a07ff5f18326e8dae2b3da93a6df52058',
  '685a1c828c3f4d94de9c82231f8102386d2a64dc82d3d73512d0b63b49e80b35',
  'c3597d5600daf85ff5d698b62288d86dad65a4b165894b58be0327ad010aee72',
  '6290eb2e537733ab14f4cd32fdb89e73d55264c02666eedef6445645917cb190',
  '91b879254ad5736b4daeee959a1431714098e0159ac0e32148ac4493df1e81d1',
  'c7bbd14d6f2fbb013c0ac32b0e348a46a112212c4ee742a522e5415b463a423f',
  '998a6e4d4c0194a0bf991a10082c90cad922265ac7071e29aa694445ad600b1d',
  '7e85c1fbf3a464b33ed9dbd3b394601fdf481a2a93f0f791e3a1ad7ac6645eaa',
];

assert.equal(manifest.version, 1);
assert.equal(manifest.curve, 'BLS12-381');
assert.equal(manifest.bchVm, 'BCH_2026');
assert.equal(manifest.fixedCombWidth, 6);
assert.equal(manifest.inputs.length, 11);
const expectedSlopeWitness = {
  bytesPerSlope: 48,
  totalSlopeCount: 85,
  local: { windowStart: 1, windowEndExclusive: 15, slopeCount: 28, length: 1344 },
  carriers: [
    {
      windowStart: 15, windowEndExclusive: 29, slopeCount: 28, millerOffset: 3,
      includesFinalAddition: false, inputIndex: 4, unlockingBytecodeOffset: 774, length: 1344,
    },
    {
      windowStart: 29, windowEndExclusive: 43, slopeCount: 29, millerOffset: 5,
      includesFinalAddition: true, inputIndex: 6, unlockingBytecodeOffset: 774, length: 1392,
    },
  ],
};
assert.deepEqual(manifest.slopeWitness, expectedSlopeWitness, 'fixed-comb slope witness layout');
assert.equal(
  sha256Hex(readFileSync(join(here, '..', '..', 'singleton', 'bls12-381', 'bound_analysis.mjs'))),
  EXPECTED_BOUND_ANALYSIS_SHA256,
  'integer-bound certificate drift',
);

const parseSourceMap = (sourceMap) => {
  let previous = [0, 0, 0, 0, 0];
  return sourceMap.split(';').map((entry) => {
    const fields = entry.split(':');
    previous = previous.map((value, index) => fields[index] === undefined || fields[index] === ''
      ? value
      : Number(fields[index]));
    return previous.slice();
  });
};

const sourceTextAt = (source, location) => {
  if (source === undefined || location === undefined) return '';
  const [startLine, startColumn, endLine, endColumn] = location;
  const lines = source.split('\n');
  if (startLine === endLine) return lines[startLine - 1]?.slice(startColumn, endColumn) ?? '';
  return lines.slice(startLine - 1, endLine).join('\n');
};

const artifacts = manifest.inputs.map((input) => {
  const sourcePath = join(generated, input.sourceFile);
  const sourceBytes = readFileSync(sourcePath);
  assert.equal(sha256Hex(sourceBytes), input.sourceSha256, `input ${input.index} source hash`);
  const compilerOptions = input.compilerMode === 'raw' ? {} : { rescheduleStacks: true };
  const artifact = compileFile(sourcePath, compilerOptions);
  const compiled = asmToBytecode(artifact.bytecode);
  const redeem = Uint8Array.from([OpcodesBchSpec.OP_DROP, ...compiled]);
  assert.equal(redeem.length, input.redeemBytes, `input ${input.index} redeem length`);
  assert.equal(sha256Hex(redeem), input.redeemSha256, `input ${input.index} redeem hash`);

  const metadata = new Map();
  const addBody = (name, source, bytecode, sourceMap, prefix = false) => {
    const instructions = decodeAuthenticationInstructions(bytecode);
    const locations = parseSourceMap(sourceMap);
    assert.equal(instructions.length - (prefix ? 1 : 0), locations.length, `${name} source map length`);
    const hash = bodyHash(instructions);
    metadata.set(hash, {
      hash,
      name,
      source,
      locations: prefix ? [undefined, ...locations] : locations,
    });
  };
  addBody('main', artifact.source, redeem, artifact.debug.sourceMap, true);
  for (const frame of artifact.debug.functions ?? []) {
    addBody(frame.name, frame.source ?? artifact.source, hexToBin(frame.bytecode), frame.sourceMap);
  }

  const controlSites = [];
  const numericSites = [];
  for (const [hash, body] of [...metadata].sort(([a], [b]) => a.localeCompare(b))) {
    const instructions = hash === bodyHash(decodeAuthenticationInstructions(redeem))
      ? decodeAuthenticationInstructions(redeem)
      : (() => {
          const frame = (artifact.debug.functions ?? []).find((candidate) =>
            sha256Hex(hexToBin(candidate.bytecode)) === hash);
          assert(frame !== undefined, `missing frame ${body.name}`);
          return decodeAuthenticationInstructions(hexToBin(frame.bytecode));
        })();
    instructions.forEach((instruction, pc) => {
      if ('data' in instruction) return;
      const opcode = instruction.opcode;
      const site = {
        body: body.name,
        bodyHash: hash,
        pc,
        opcode: OpcodesBchSpec[opcode] ?? String(opcode),
        location: body.locations[pc] ?? null,
      };
      if ([OpcodesBchSpec.OP_IF, OpcodesBchSpec.OP_NOTIF, OpcodesBchSpec.OP_BEGIN, OpcodesBchSpec.OP_UNTIL].includes(opcode)) {
        controlSites.push(site);
      }
      if ([
        OpcodesBchSpec.OP_ADD, OpcodesBchSpec.OP_SUB, OpcodesBchSpec.OP_MUL,
        OpcodesBchSpec.OP_DIV, OpcodesBchSpec.OP_MOD, OpcodesBchSpec.OP_NEGATE,
        OpcodesBchSpec.OP_ABS, OpcodesBchSpec.OP_1ADD, OpcodesBchSpec.OP_1SUB,
        OpcodesBchSpec.OP_LSHIFTNUM, OpcodesBchSpec.OP_RSHIFTNUM,
      ].includes(opcode)) numericSites.push(site);
    });
  }
  return {
    ...input,
    artifact,
    controlSites,
    controlFingerprint: sha256Hex(JSON.stringify(controlSites)),
    bodyCache: new WeakMap(),
    metadata,
    numericFingerprint: sha256Hex(JSON.stringify(numericSites)),
    redeem,
  };
});

const computedManifestSha256 = sha256Hex(manifestBytes);
if (process.env.PRINT_RESOURCE_FINGERPRINTS === '1') {
  console.log(JSON.stringify({
    sourceManifestSha256: computedManifestSha256,
    integerBoundCertificateSha256: EXPECTED_BOUND_ANALYSIS_SHA256,
    programFingerprints: artifacts.map(({ controlFingerprint }) => controlFingerprint),
    numericFingerprints: artifacts.map(({ numericFingerprint }) => numericFingerprint),
  }, null, 2));
  process.exit(0);
}
assert.equal(computedManifestSha256, EXPECTED_MANIFEST_SHA256, 'resource manifest drift');
assert.deepEqual(artifacts.map(({ controlFingerprint }) => controlFingerprint), EXPECTED_PROGRAM_FINGERPRINTS, 'control PC drift');
assert.deepEqual(artifacts.map(({ numericFingerprint }) => numericFingerprint), EXPECTED_NUMERIC_FINGERPRINTS, 'numeric PC drift');

const variableLinkedParts = manifest.inputs.flatMap((input) => input.argumentPushes
  .filter(({ name, fixedValueHex }) => name === 'linkedData' && fixedValueHex === undefined)
  .map((argument) => ({ inputIndex: input.index, bytes: argument.bytes })));
assert.deepEqual(variableLinkedParts, expectedSlopeWitness.carriers.map(({ inputIndex, length }) => ({
  inputIndex,
  bytes: length,
})), 'fixed-comb slope carrier arguments');
const fixedTableParts = manifest.inputs.flatMap((input) => input.argumentPushes
  .filter(({ name, fixedValueHex }) => name === 'linkedData' && fixedValueHex !== undefined)
  .map((argument) => ({ inputIndex: input.index, ...argument })));
assert.deepEqual(fixedTableParts.map(({ inputIndex }) => inputIndex), [5, 7, 9], 'fixed-table carrier layout');
const fixedTable = Uint8Array.from(fixedTableParts.flatMap((argument) => {
  assert.equal(typeof argument.fixedValueHex, 'string', `input ${argument.inputIndex} fixed table bytes`);
  const value = hexToBin(argument.fixedValueHex);
  assert.equal(value.length, argument.bytes, `input ${argument.inputIndex} fixed table length`);
  return [...value];
}));
assert.equal(fixedTable.length, 63 * 96, 'width-6 fixed table length');
const tableEntries = Array.from({ length: 63 }, (_, index) => {
  const entry = fixedTable.slice(index * 96, (index + 1) * 96);
  return [entry.slice(0, 48), entry.slice(48)].map((encoded) => {
    const value = vmNumberToBigInt(encoded, { requireMinimalEncoding: false });
    assert.equal(typeof value, 'bigint', `fixed table entry ${index + 1} decode`);
    assert(value >= 0n && value < P, `fixed table entry ${index + 1} canonical coordinate`);
    return value;
  });
});
const fixedTableWidthProfile = ([x, y]) => {
  const doubleY = y + y;
  const xSquared = x * x;
  const tripleXSquared = 3n * (xSquared % P);
  const doubleX = x + x;
  return [
    x,
    y,
    doubleY,
    doubleY % P,
    xSquared,
    xSquared % P,
    tripleXSquared,
    tripleXSquared % P,
    doubleX,
    doubleX % P,
  ].map((value) => bigIntToVmNumber(value).length);
};
const fixedTableProfiles = tableEntries.map(fixedTableWidthProfile);
const fixedTableMaximumProfile = fixedTableProfiles.reduce((maximum, profile) =>
  maximum.map((width, index) => Math.max(width, profile[index])));
const fixedTableEntry63Profile = fixedTableProfiles[62];
assert.deepEqual(
  fixedTableEntry63Profile,
  fixedTableMaximumProfile,
  'fixed table entry 63 must dominate every selectable pre-widening VM-number width',
);

const intervalByEncoding = new Map();
const markerByInterval = new Map();
let markerId = 1;
const intervalWidth = ({ lo, hi }) => Math.max(bigIntToVmNumber(lo).length, bigIntToVmNumber(hi).length);
const intervalKey = ({ lo, hi }) => `${lo}:${hi}`;
const intervalMarker = (interval) => {
  if (interval.lo === interval.hi) return bigIntToVmNumber(interval.lo);
  const key = intervalKey(interval);
  const existing = markerByInterval.get(key);
  if (existing !== undefined) return existing;
  const width = intervalWidth(interval);
  if (width < 4) {
    return bigIntToVmNumber((-interval.lo) > interval.hi ? interval.lo : interval.hi);
  }
  const marker = new Uint8Array(width);
  marker[0] = markerId & 0xff;
  marker[1] = (markerId >>> 8) & 0xff;
  marker[2] = (markerId >>> 16) & 0xff;
  marker[width - 1] = 1;
  markerId += 1;
  intervalByEncoding.set(binToHex(marker), interval);
  markerByInterval.set(key, marker);
  return marker;
};
const intervalOf = (item) => {
  const tagged = intervalByEncoding.get(binToHex(item));
  if (tagged !== undefined) return tagged;
  const value = vmNumberToBigInt(item, { requireMinimalEncoding: false });
  assert.equal(typeof value, 'bigint', 'VM number interval decode');
  return { lo: value, hi: value };
};
const fieldMarker = intervalMarker({ lo: 0n, hi: P - 1n });
const fieldBlob = (bytes) => {
  const value = new Uint8Array(bytes);
  for (let offset = 0; offset < bytes; offset += 48) {
    value.set(fieldMarker.slice(0, Math.min(48, bytes - offset)), offset);
  }
  return value;
};
const padPush = (fixedBytes, targetBytes) => {
  const budget = Math.max(2, targetBytes - fixedBytes);
  const dataBytes = budget <= 76 ? budget - 1 : budget <= 257 ? budget - 2 : budget - 3;
  return encodeDataPush(new Uint8Array(dataBytes));
};
const concat = (...items) => Uint8Array.from(items.flatMap((item) => [...item]));
const argumentValue = (argument) => {
  if (argument.type === 'int') return fieldMarker;
  if (argument.fixedValueHex === undefined) return fieldBlob(argument.bytes);
  const value = hexToBin(argument.fixedValueHex);
  assert.equal(value.length, argument.bytes, `${argument.name} fixed argument length`);
  return value;
};
const fixedUnlockingBytes = artifacts.map((artifact) => artifact.argumentPushes.reduce((total, argument) =>
  total + encodeDataPush(argumentValue(argument)).length, 0) +
  encodeDataPush(artifact.redeem).length);

const buildUnlocking = (artifact, targetBytes) => {
  const arguments_ = artifact.argumentPushes.map((argument) => encodeDataPush(argumentValue(argument)));
  const fixed = arguments_.reduce((total, argument) => total + argument.length, 0) + encodeDataPush(artifact.redeem).length;
  const unlocking = concat(...arguments_, padPush(fixed, targetBytes), encodeDataPush(artifact.redeem));
  assert.equal(unlocking.length, targetBytes);
  return unlocking;
};

const arithmeticOpcodes = new Set([
  OpcodesBchSpec.OP_ADD, OpcodesBchSpec.OP_SUB, OpcodesBchSpec.OP_MUL,
  OpcodesBchSpec.OP_DIV, OpcodesBchSpec.OP_MOD, OpcodesBchSpec.OP_NEGATE,
  OpcodesBchSpec.OP_ABS, OpcodesBchSpec.OP_1ADD, OpcodesBchSpec.OP_1SUB,
]);
const shiftOpcodes = new Set([OpcodesBchSpec.OP_LSHIFTNUM, OpcodesBchSpec.OP_RSHIFTNUM]);
const comparisonOpcodes = new Set([
  OpcodesBchSpec.OP_EQUAL, OpcodesBchSpec.OP_NUMEQUAL, OpcodesBchSpec.OP_NUMNOTEQUAL,
  OpcodesBchSpec.OP_LESSTHAN, OpcodesBchSpec.OP_GREATERTHAN,
  OpcodesBchSpec.OP_LESSTHANOREQUAL, OpcodesBchSpec.OP_GREATERTHANOREQUAL,
  OpcodesBchSpec.OP_WITHIN,
]);
const controlCoverage = artifacts.map(() => new Map());

const metadataAt = (artifact, state) => {
  let body = artifact.bodyCache.get(state.instructions);
  if (body === undefined) {
    body = artifact.metadata.get(bodyHash(state.instructions));
    if (body !== undefined) artifact.bodyCache.set(state.instructions, body);
  }
  if (body === undefined) return undefined;
  const location = body.locations[state.ip];
  return {
    body: body.name,
    bodyHash: body.hash,
    location,
    pc: state.ip,
    sourceLine: location === undefined ? '' : body.source?.split('\n')[location[0] - 1] ?? '',
    sourceText: sourceTextAt(body.source, location),
  };
};

const branchDecision = (context, mode, opcode) => {
  if (context === undefined) return undefined;
  const { body, location, sourceLine, sourceText } = context;
  const pc = location === undefined ? -1 : location[0] * 10000 + location[1];
  if (body === 'main' && sourceText.trimStart().startsWith('for (')) return undefined;
  if (body === 'select16') return mode.selectNonzero;
  if (body === 'affineDouble') return mode.doubleIdentity;
  if (body === 'affineAdd') {
    const decisions = {
      qIdentity: [true],
      pIdentity: [false, true],
      double: [false, false, true, true],
      inverse: [false, false, true, false],
      general: [false, false, false],
    }[mode.add];
    const indexByPc = new Map([[580019, 0], [600026, 1], [620024, 2], [630021, 3]]);
    const index = indexByPc.get(pc);
    assert(index !== undefined && decisions[index] !== undefined, `uncovered affineAdd branch at ${pc}`);
    return decisions[index];
  }
  if (body === 'canonicalFp') return mode.canonicalBelowZero;
  if (body === 'main' && sourceLine.includes('dIdentity')) return mode.dIdentity;
  if (body === 'main' && sourceLine.includes('bIdentity')) {
    const identity = mode.bIdentity;
    return opcode === OpcodesBchSpec.OP_NOTIF ? identity : identity;
  }
  throw new Error(`uncovered branch ${body} ${JSON.stringify(location)} ${sourceText}`);
};

const intervalResult = (opcode, operands) => {
  const [a, b] = operands;
  if (opcode === OpcodesBchSpec.OP_ADD) return { lo: a.lo + b.lo, hi: a.hi + b.hi };
  if (opcode === OpcodesBchSpec.OP_SUB) return { lo: a.lo - b.hi, hi: a.hi - b.lo };
  if (opcode === OpcodesBchSpec.OP_MUL) {
    const products = [a.lo * b.lo, a.lo * b.hi, a.hi * b.lo, a.hi * b.hi];
    return { lo: products.reduce((x, y) => x < y ? x : y), hi: products.reduce((x, y) => x > y ? x : y) };
  }
  if (opcode === OpcodesBchSpec.OP_DIV) {
    assert(b.lo === b.hi && b.lo !== 0n, 'interval division requires an exact nonzero divisor');
    const quotients = [a.lo / b.lo, a.hi / b.lo];
    return { lo: quotients.reduce((x, y) => x < y ? x : y), hi: quotients.reduce((x, y) => x > y ? x : y) };
  }
  if (opcode === OpcodesBchSpec.OP_MOD) {
    assert(b.lo === b.hi && b.lo > 0n, 'interval modulo requires an exact positive divisor');
    if (a.lo >= 0n) return { lo: 0n, hi: b.lo - 1n };
    if (a.hi <= 0n) return { lo: 1n - b.lo, hi: 0n };
    return { lo: 1n - b.lo, hi: b.lo - 1n };
  }
  if (opcode === OpcodesBchSpec.OP_NEGATE) return { lo: -a.hi, hi: -a.lo };
  if (opcode === OpcodesBchSpec.OP_ABS) {
    const maximum = (-a.lo) > a.hi ? -a.lo : a.hi;
    return { lo: 0n, hi: maximum };
  }
  if (opcode === OpcodesBchSpec.OP_1ADD) return { lo: a.lo + 1n, hi: a.hi + 1n };
  if (opcode === OpcodesBchSpec.OP_1SUB) return { lo: a.lo - 1n, hi: a.hi - 1n };
  if (opcode === OpcodesBchSpec.OP_LSHIFTNUM) {
    assert(a.lo >= 0n && b.lo === b.hi && b.lo >= 0n, 'left-shift interval domain');
    return { lo: a.lo << b.lo, hi: a.hi << b.lo };
  }
  if (opcode === OpcodesBchSpec.OP_RSHIFTNUM) {
    assert(a.lo >= 0n && b.lo === b.hi && b.lo >= 0n, 'right-shift interval domain');
    return { lo: a.lo >> b.lo, hi: a.hi >> b.lo };
  }
  throw new Error(`missing interval transfer for ${OpcodesBchSpec[opcode]}`);
};

const modesFor = (inputIndex) => {
  if (inputIndex < GLV_INPUT_COUNT) {
    const modes = [];
    for (const selectNonzero of [false, true]) {
      for (const doubleIdentity of [false, true]) {
        for (const add of ['qIdentity', 'pIdentity', 'double', 'inverse', 'general']) {
          for (const dIdentity of inputIndex === GLV_INPUT_COUNT - 1 ? [false, true] : [false]) {
            modes.push({ selectNonzero, doubleIdentity, add, dIdentity });
          }
        }
      }
    }
    return modes;
  }
  return [false, true].flatMap((bIdentity) => [false, true].map((canonicalBelowZero) => ({
    bIdentity,
    canonicalBelowZero,
  })));
};

const runAbstract = (inputIndex, unlockBytes, mode) => {
  const artifact = artifacts[inputIndex];
  const base = createInstructionSetBch2026(false, { ripemd160, secp256k1, sha1, sha256 });
  const operations = Object.fromEntries(Object.entries(base.operations).map(([opcodeText, operation]) => {
    const opcode = Number(opcodeText);
    return [opcode, (state) => {
      if (!executionIsActive(state)) return operation(state);
      const context = metadataAt(artifact, state);
      if (context !== undefined && [OpcodesBchSpec.OP_BEGIN, OpcodesBchSpec.OP_UNTIL].includes(opcode)) {
        const key = `${context.bodyHash}:${context.pc}:${opcode}`;
        const edges = controlCoverage[inputIndex].get(key) ?? new Set();
        edges.add(opcode === OpcodesBchSpec.OP_BEGIN ? 'entered' : stackItemIsTruthy(state.stack.at(-1)));
        controlCoverage[inputIndex].set(key, edges);
      }
      if (opcode === OpcodesBchSpec.OP_IF || opcode === OpcodesBchSpec.OP_NOTIF) {
        const decision = branchDecision(context, mode, opcode);
        if (context !== undefined) {
          const key = `${context.bodyHash}:${context.pc}:${opcode}`;
          const edges = controlCoverage[inputIndex].get(key) ?? new Set();
          edges.add(decision ?? stackItemIsTruthy(state.stack.at(-1)));
          controlCoverage[inputIndex].set(key, edges);
        }
        if (context?.body === 'canonicalFp' && decision !== undefined) {
          state.stack[state.stack.length - 2] = intervalMarker(decision
            ? { lo: 1n - P, hi: -1n }
            : { lo: 0n, hi: P - 1n });
        }
        if (decision !== undefined) state.stack[state.stack.length - 1] = decision ? Uint8Array.of(1) : new Uint8Array(0);
        return operation(state);
      }
      if (opcode === OpcodesBchSpec.OP_VERIFY) {
        state.stack[state.stack.length - 1] = Uint8Array.of(1);
        return operation(state);
      }
      if (opcode === OpcodesBchSpec.OP_EQUALVERIFY || opcode === OpcodesBchSpec.OP_NUMEQUALVERIFY) {
        state.stack[state.stack.length - 1] = state.stack[state.stack.length - 2].slice();
        return operation(state);
      }
      const loopComparison = context?.body === 'main' && /^k\s*<\s*\d+$/.test(context.sourceText.trim());
      if (comparisonOpcodes.has(opcode) && !loopComparison) {
        const beforePush = state.metrics.stackPushedBytes;
        const result = operation(state);
        result.stack[result.stack.length - 1] = Uint8Array.of(1);
        result.metrics.stackPushedBytes = beforePush + 1;
        return result;
      }
      if (context?.body === 'select16' && opcode === OpcodesBchSpec.OP_SUB) {
        const beforeArithmetic = state.metrics.arithmeticCost;
        const beforePush = state.metrics.stackPushedBytes;
        const result = operation(state);
        result.stack[result.stack.length - 1] = Uint8Array.of(1);
        result.metrics.arithmeticCost = beforeArithmetic + 1;
        result.metrics.stackPushedBytes = beforePush + 1;
        return result;
      }
      if (context?.body === 'select16' && opcode === OpcodesBchSpec.OP_MUL) {
        const beforeArithmetic = state.metrics.arithmeticCost;
        const beforePush = state.metrics.stackPushedBytes;
        const result = operation(state);
        // 5952 is the last valid 96-byte table-entry offset; its two-byte
        // encoding also covers the widest possible width-6 selector offset.
        result.stack[result.stack.length - 1] = Uint8Array.of(0x40, 0x17);
        result.metrics.arithmeticCost = beforeArithmetic + 3;
        result.metrics.stackPushedBytes = beforePush + 2;
        return result;
      }
      if (opcode === OpcodesBchSpec.OP_BIN2NUM) {
        const interval = intervalByEncoding.get(binToHex(state.stack.at(-1)));
        const result = operation(state);
        if (interval !== undefined) result.stack[result.stack.length - 1] = intervalMarker(interval);
        return result;
      }
      if (!arithmeticOpcodes.has(opcode) && !shiftOpcodes.has(opcode)) return operation(state);
      const arity = [OpcodesBchSpec.OP_NEGATE, OpcodesBchSpec.OP_ABS, OpcodesBchSpec.OP_1ADD, OpcodesBchSpec.OP_1SUB].includes(opcode) ? 1 : 2;
      const items = state.stack.slice(-arity);
      const tagged = items.some((item) => intervalByEncoding.has(binToHex(item)));
      const mathFunction = inputIndex < GLV_INPUT_COUNT
        ? ['addFp', 'subFp', 'mulFp', 'sqrFp'].includes(context?.body)
        : context !== undefined && context.body !== 'main';
      if (!tagged && !mathFunction) return operation(state);
      const operands = items.map(intervalOf);
      const interval = intervalResult(opcode, operands);
      const resultWidth = intervalWidth(interval);
      assert(resultWidth <= 98, `integer envelope exceeded 98 bytes in ${context?.body}: ${intervalKey(interval)}`);
      const beforeArithmetic = state.metrics.arithmeticCost;
      const beforePush = state.metrics.stackPushedBytes;
      const result = operation(state);
      if (result.error !== undefined) return result;
      result.stack[result.stack.length - 1] = intervalMarker(interval);
      const operandWidths = operands.map(intervalWidth);
      const arithmeticCost = shiftOpcodes.has(opcode)
        ? 0
        : [OpcodesBchSpec.OP_MUL, OpcodesBchSpec.OP_DIV, OpcodesBchSpec.OP_MOD].includes(opcode)
        ? operandWidths[0] * operandWidths[1] + resultWidth
        : resultWidth;
      result.metrics.arithmeticCost = beforeArithmetic + arithmeticCost;
      result.metrics.stackPushedBytes = beforePush + resultWidth;
      return result;
    }];
  }));
  const vm = createVirtualMachine({ ...base, operations });
  const unlockings = artifacts.map((candidate, index) => buildUnlocking(candidate, unlockBytes[index]));
  const lockings = artifacts.map(({ redeem }) => encodeLockingBytecodeP2sh32(hash256(redeem)));
  const program = {
    inputIndex,
    sourceOutputs: lockings.map((lockingBytecode) => ({ lockingBytecode, valueSatoshis: 10_000n })),
    transaction: {
      version: 2,
      inputs: unlockings.map((unlockingBytecode, index) => ({
        outpointTransactionHash: new Uint8Array(32),
        outpointIndex: index,
        sequenceNumber: 0,
        unlockingBytecode,
      })),
      outputs: [{ lockingBytecode: Uint8Array.of(OpcodesBchSpec.OP_RETURN), valueSatoshis: 0n }],
      locktime: 0,
    },
  };
  const state = vm.evaluate(program);
  assert.equal(state.error, undefined, `input ${inputIndex} abstract execution ${JSON.stringify(mode)} at ${JSON.stringify(metadataAt(artifact, state))} pc=${state.ip}`);
  const metrics = state.metrics;
  const common = metrics.evaluatedInstructionCount * 100 + metrics.arithmeticCost + metrics.stackPushedBytes;
  return {
    consensusOperationCost: common + metrics.hashDigestIterations * 64 + metrics.signatureCheckCount * 26_000,
    standardOperationCost: common + metrics.hashDigestIterations * 192 + metrics.signatureCheckCount * 26_000,
    standardHashDensityLimit: Math.floor(0.5 * (41 + unlockBytes[inputIndex])),
    metrics,
    mode,
    program,
  };
};

let unlockingBytes = artifacts.map(() => 10_000);
let maxima;
for (let iteration = 0; iteration < 100; iteration += 1) {
  const iterationRuns = artifacts.map((_, inputIndex) => modesFor(inputIndex)
    .map((mode) => runAbstract(inputIndex, unlockingBytes, mode)));
  maxima = iterationRuns.map((runs) => runs
    .reduce((maximum, run) => run.standardOperationCost > maximum.standardOperationCost ? run : maximum));
  const next = maxima.map((maximum, inputIndex) => Math.max(
    fixedUnlockingBytes[inputIndex] + 3,
    Math.ceil(maximum.standardOperationCost / 800) - 41,
    2 * Math.max(...iterationRuns[inputIndex].map((run) => run.metrics.hashDigestIterations)) - 41,
  ));
  if (process.env.RESOURCE_PROFILE === '1') console.error(`resource iteration ${iteration}: ${next.join(',')}`);
  if (next.every((value, index) => value === unlockingBytes[index])) break;
  assert(next.every((value, index) => value <= unlockingBytes[index]),
    `resource fixed point did not tighten: ${JSON.stringify({ unlockingBytes, next })}`);
  unlockingBytes = next;
  if (iteration === 99) throw new Error('resource fixed point did not converge');
}

controlCoverage.forEach((coverage) => coverage.clear());
const finalRuns = artifacts.map((_, inputIndex) => modesFor(inputIndex).map((mode) =>
  runAbstract(inputIndex, unlockingBytes, mode)));
finalRuns.forEach((runs, inputIndex) => runs.forEach((run) => {
  assert(
    run.metrics.hashDigestIterations <= run.standardHashDensityLimit,
    `input ${inputIndex} standard hash density for ${JSON.stringify(run.mode)}`,
  );
}));
let coveredControlSites = 0;
let coveredControlEdges = 0;
artifacts.forEach((artifact, inputIndex) => artifact.controlSites.forEach((site) => {
  const opcode = OpcodesBchSpec[site.opcode];
  const edges = controlCoverage[inputIndex].get(`${site.bodyHash}:${site.pc}:${opcode}`);
  assert(edges !== undefined, `input ${inputIndex} control site not visited: ${JSON.stringify(site)}`);
  const expectedEdges = opcode === OpcodesBchSpec.OP_BEGIN ? ['entered'] : [false, true];
  assert.deepEqual(
    [...edges].sort(),
    expectedEdges,
    `input ${inputIndex} control edges incomplete: ${JSON.stringify(site)}`,
  );
  coveredControlSites += 1;
  coveredControlEdges += edges.size;
}));
const bounds = finalRuns.map((runs, inputIndex) => {
  const consensus = runs.reduce((maximum, run) =>
    run.consensusOperationCost > maximum.consensusOperationCost ? run : maximum);
  const standard = runs.reduce((maximum, run) =>
    run.standardOperationCost > maximum.standardOperationCost ? run : maximum);
  const hashDensity = runs.reduce((maximum, run) =>
    run.metrics.hashDigestIterations > maximum.metrics.hashDigestIterations ? run : maximum);
  const budget = (41 + unlockingBytes[inputIndex]) * 800;
  assert(unlockingBytes[inputIndex] <= 10_000, `input ${inputIndex} unlocking limit`);
  assert(consensus.consensusOperationCost <= budget, `input ${inputIndex} consensus density`);
  assert(standard.standardOperationCost <= budget, `input ${inputIndex} standard density`);
  return {
    inputIndex,
    label: artifacts[inputIndex].label,
    redeemBytes: artifacts[inputIndex].redeemBytes,
    redeemSha256: artifacts[inputIndex].redeemSha256,
    unlockingBytes: unlockingBytes[inputIndex],
    budget,
    consensusOperationCost: consensus.consensusOperationCost,
    standardOperationCost: standard.standardOperationCost,
    margin: budget - standard.standardOperationCost,
    hashDigestIterations: hashDensity.metrics.hashDigestIterations,
    standardHashDensityLimit: hashDensity.standardHashDensityLimit,
    hashDensityMargin: hashDensity.standardHashDensityLimit - hashDensity.metrics.hashDigestIterations,
    consensusMode: consensus.mode,
    standardMode: standard.mode,
  };
});

const transaction = finalRuns[0][0].program.transaction;
transaction.inputs.forEach((input, index) => { input.unlockingBytecode = buildUnlocking(artifacts[index], unlockingBytes[index]); });
const wireBytes = encodeTransactionBch(transaction).length;
assert.equal(wireBytes, unlockingBytes.reduce((sum, bytes) => sum + bytes, 0) + 43 * artifacts.length + 20);
assert(wireBytes <= 100_000, 'one-transaction standard size');

console.log(JSON.stringify({
  certificate: 'BLS12-381 one-transaction BCH_2026 resource bounds',
  sourceManifestSha256: EXPECTED_MANIFEST_SHA256,
  integerBoundCertificateSha256: EXPECTED_BOUND_ANALYSIS_SHA256,
  proofIndependent: true,
  integerEnvelopes: {
    canonicalFpBytes: 48,
    lazyFpBytes: 49,
    directProductBytes: 98,
    maxLazyInput: '310p',
    maxDirectProduct: '76880p^2',
  },
  fixedTableEntry63WidthProfile: fixedTableEntry63Profile,
  controlCoverage: {
    sites: coveredControlSites,
    edges: coveredControlEdges,
  },
  transaction: {
    inputs: artifacts.length,
    wireBytes,
    standardLimit: 100_000,
    margin: 100_000 - wireBytes,
  },
  bounds,
}, null, 2));

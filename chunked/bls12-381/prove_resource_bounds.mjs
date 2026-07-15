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

const EXPECTED_BOUND_ANALYSIS_SHA256 = 'caa73accba876075490abe6e89d7a7c1575932d5331a0635a976dda0bdfd6bb4';
const EXPECTED_MANIFEST_SHA256 = '79d7a7ca0b9795ac90e95cf1fb37782c0a2ac7a79d5d7b3779babf124623fcf7';
const EXPECTED_PROGRAM_FINGERPRINTS = [
  '455bcdcddf884339ab5ce0ebf73ee4d8a7a6ec0ff248a87b9d2384ad8edaf04c',
  '06adfe5f123a4e9556bbf2edff5c156ef64326fd4ea3265b9f6f9715b1510e6b',
  '2cf59746b7019284ca2b43f060e136cabc189757b1968e7623d13680962c71bd',
  'dc92fbffa06c723fdd7daec27c49667ce488a3cf8f0928ab2a178c946d866593',
  '2aabc57a0f6a9f301edbf8d443ee2eee8b42104c791c0df28037dfd00fc6dd4f',
  'cb4d8001c48d4e7be1b82d902ef9b3d9b28be872a3cbc05dd7357ef9fdbdd442',
  '52a21ab04eb470d660dd44309aaf93068057a0386454f7e0b5ed2fe9e7f1cc66',
  'fa2aacc3882935020e2ab59cd2601fb1c36e7f7e34ed2105c50ad7af4f5e4bdc',
  '7e9df45e9ebbd3301fd1cc82025aed77ba8c6c3f660024d288fb2492960bfdea',
  '2a684403ee1958d58fb053e73af29af53e49d069df731df0bbb3b3eca6fedea0',
  'd7578681b38f2e8f91628c8002d62c41d647afa5481061464de745bb4419438e',
  'fa2bda13bc007ae8d204ac0d7c54fb7dfd27ad37d126ea0dbbd6f76a59895305',
];
const EXPECTED_NUMERIC_FINGERPRINTS = [
  '3d58545e2ae72890664418b991367beaaa72a918e784775f2ce43fd59add23ba',
  'bc2b87341610ce696fdd77d953c7bd1a7a234212794d9930f563ea9ed2407ea5',
  'b15631bfaa4df147e7b517d63ff18a023138196179d2a5e8cd67d9ef1d0b8fca',
  '7bc08f9555a395a5448ae4796c85daa088062ef2296fe566c12566bd9fb19ea0',
  '28bb377c97f4a9a0ace0bd59f16244e04fcffba4ba4ef34c17e19f4b17a45ea6',
  '21b160e0f699cdb6a649718063a5de6d1980f2cb3804ec974d101192be0032c6',
  'c6b2c4a1b23c67229c3132a52f32b95590e7007dfce0eeecce6120e0fd51fb6d',
  '194e89328337a3d4cc6778a131fc5b3ffb0d00fefb1142e57fe2ff39af21b1b2',
  '877f368c995cd9105c5b921ef33829ee4ae447c4fe3f07e506c1dd7aa52a456c',
  '055e328fd4b5900f5d3992ed669c0307e69ffa0bf3f93f789b3eda818d67f3b5',
  '63affa5799165f1bad12d06a83799b7143b279047a63017e4d6cd814a09a6922',
  '969438c764f12aa08e56fc9d8a161baf31e0f1b8aa422845eaf69de1cdf90623',
];

assert.equal(manifest.version, 1);
assert.equal(manifest.curve, 'BLS12-381');
assert.equal(manifest.bchVm, 'BCH_2026');
assert.equal(manifest.fixedCombWidth, 6);
assert.equal(manifest.inputs.length, 12);
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

const fixedTableParts = manifest.inputs.flatMap((input) => input.argumentPushes
  .filter(({ name }) => name === 'linkedData')
  .map((argument) => ({ inputIndex: input.index, ...argument })));
assert.deepEqual(fixedTableParts.map(({ inputIndex }) => inputIndex), [6, 8, 10], 'fixed-table carrier layout');
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
  if (inputIndex < 2) {
    const modes = [];
    for (const selectNonzero of [false, true]) {
      for (const doubleIdentity of [false, true]) {
        for (const add of ['qIdentity', 'pIdentity', 'double', 'inverse', 'general']) {
          for (const dIdentity of inputIndex === 1 ? [false, true] : [false]) {
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
      const mathFunction = inputIndex < 2
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

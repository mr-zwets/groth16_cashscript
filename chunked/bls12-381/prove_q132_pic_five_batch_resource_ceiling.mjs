// Trace-driven abstract resource ceiling for the q132 BLS12-381 transaction
// profiles. The concrete trace pins byte-string lengths and control flow;
// the shadow stack replaces every canonical numeric witness with its complete
// type range and propagates operation-cost ceilings.
//
// The concrete BCH2026 debug trace supplies the compiler's exact stack schedule,
// fixed instruction/base/hash costs, and fixed byte-string lengths. The shadow
// stack replaces every proof-controlled field element with the full canonical
// range [-(p-1), p-1], propagates magnitude bounds through arithmetic, and adds
// the resulting worst-case arithmetic-encoding and stack-push deltas.
//
// The shadow rejects any unclassified conditional or BIN2NUM provenance. The
// only proof-controlled branches in the pinned locking graph are canonical field
// normalization and final seam normalization. Miller genesis binds normalized
// vk_x coordinates to the projective GLV hand-off with branch-free cross
// products. Both forms of every normalization are charged. Ceiling values are
// derived from the supplied resource bytecodes; an optional expected-certificate
// artifact pins the complete derived result for replay.

import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import {
  OpcodesBCH,
  createVirtualMachineBch2026,
  decodeAuthenticationInstructions,
  encodeAuthenticationInstructions,
  hexToBin,
  vmNumberToBigInt,
} from '@bitauth/libauth';

const corpusPath = resolve('q132-corpus-resource-fixtures.json');
const fixtureName = process.env.RESOURCE_FIXTURE ?? 'committed';
const probe = process.env.RESOURCE_PROBE === '1';
const resourceProfile = process.env.RESOURCE_PROFILE ?? 'baseline23';
const qsplitProfile = resourceProfile === 'qsplit22' ||
  resourceProfile === 'qsplit22-tail22';
const expectedInputCount = resourceProfile === 'baseline23'
  ? 23
  : qsplitProfile
    ? 22
    : undefined;
if (expectedInputCount === undefined) {
  throw new Error(`unknown resource profile: ${resourceProfile}`);
}
const corpusDocument = process.env.RESOURCE_SINGLE === '1'
  ? [{
    fixture: process.env.RESOURCE_FIXTURE ?? 'committed',
    ...JSON.parse(readFileSync(resolve(process.env.RESOURCE_SINGLE_PATH ??
      (process.env.RESOURCE_PROBE === '1'
        ? 'q132-resource-probe-fixture.json'
        : 'q132-resource-fixture.json')), 'utf8')),
  }]
  : JSON.parse(readFileSync(resolve(
    process.env.RESOURCE_CORPUS_PATH ?? corpusPath,
  ), 'utf8'));
const corpus = Array.isArray(corpusDocument) ? corpusDocument : corpusDocument.fixtures;
if (!Array.isArray(corpus)) throw new Error('resource corpus has no fixture array');
const fixture = corpus.find((candidate) => candidate.fixture === fixtureName);
if (fixture === undefined) throw new Error(`unknown resource fixture: ${fixtureName}`);
if (!Array.isArray(fixture.inputs) || fixture.inputs.length === 0 ||
  (!probe && fixture.inputs.length !== expectedInputCount)) {
  throw new Error(probe
    ? 'expected a non-empty q132 resource fixture'
    : `expected the exact ${expectedInputCount}-input ${resourceProfile} resource fixture`);
}
const inputs = fixture.inputs.map((input) => ({
  locking: hexToBin(input.locking),
  unlocking: hexToBin(input.unlocking),
}));
const vm = createVirtualMachineBch2026(true);
const P = 4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787n;
const R = 52435875175126190479447740508185965837690552500527637822603658699938581184513n;
const BYTE_UNKNOWN = 0;
const BYTE_FIELD = 1;
const BYTE_FIXED = 2;

const data = {
  sourceOutputs: inputs.map((input) => ({
    lockingBytecode: input.locking,
    valueSatoshis: 1000n,
  })),
  transaction: {
    version: 2,
    inputs: inputs.map((input, index) => ({
      outpointTransactionHash: new Uint8Array(32),
      outpointIndex: index,
      sequenceNumber: 0,
      unlockingBytecode: input.unlocking,
    })),
    outputs: [{ lockingBytecode: Uint8Array.of(0x6a), valueSatoshis: 1000n }],
    locktime: 0,
  },
};

const abs = (value) => value < 0n ? -value : value;
const vmLength = (maximumAbsoluteValue) => {
  if (maximumAbsoluteValue === 0n) return 0;
  const bits = maximumAbsoluteValue.toString(2).length;
  return Math.floor(bits / 8) + 1;
};
const actualNumber = (item) => vmNumberToBigInt(item, { requireMinimalEncoding: false });
const bytesTagged = (length, tag) => new Uint8Array(length).fill(tag);
const concreteItem = (item, byteTags = bytesTagged(item.length, BYTE_FIXED)) => ({
  length: item.length,
  byteTags,
  ...(item.length <= 10_000
    ? { minimum: actualNumber(item), maximum: actualNumber(item) }
    : {}),
});
let nextLineage = 0;
const numericItem = (minimum, maximum = minimum) => ({
  length: vmLength(abs(minimum) > abs(maximum) ? abs(minimum) : abs(maximum)),
  minimum,
  maximum,
  lineage: nextLineage++,
  byteTags: new Uint8Array(vmLength(abs(minimum) > abs(maximum) ? abs(minimum) : abs(maximum))),
});
const requireInterval = (item) => {
  if (item.minimum === undefined || item.maximum === undefined) {
    throw new Error('numeric operation received a byte string without an interval');
  }
  return item;
};
const multiplyIntervals = (a, b) => {
  const products = [
    a.minimum * b.minimum,
    a.minimum * b.maximum,
    a.maximum * b.minimum,
    a.maximum * b.maximum,
  ];
  return [products.reduce((min, value) => value < min ? value : min),
    products.reduce((max, value) => value > max ? value : max)];
};

const IDENTITY_BRANCH = [
  'OP_6', 'OP_PICK', 'OP_0', 'OP_NUMEQUALVERIFY',
  'OP_5', 'OP_PICK', 'OP_0', 'OP_NUMEQUALVERIFY',
  'OP_4', 'OP_PICK', 'OP_0', 'OP_NUMEQUALVERIFY',
  'OP_3', 'OP_PICK', 'OP_0', 'OP_NUMEQUALVERIFY',
  'OP_2', 'OP_PICK', 'OP_0', 'OP_NUMEQUALVERIFY',
  'OP_OVER', 'OP_0', 'OP_NUMEQUALVERIFY',
];
const STATE_SWAP_BRANCH = ['OP_NIP', 'OP_OVER', 'OP_NIP', 'OP_1'];
const SELECT_BRANCH = [
  'OP_3', 'OP_PICK', 'OP_ROT', 'OP_DROP',
  'OP_SWAP', 'OP_4', 'OP_PICK', 'OP_NIP',
];
const SECOND_SPLIT_SELECT_BRANCH = [
  'OP_7', 'OP_PICK', 'OP_ROT', 'OP_DROP',
  'OP_SWAP', 'OP_8', 'OP_PICK', 'OP_NIP',
];
const TERMINAL_RESET_BRANCH = ['OP_0', 'OP_ROT', 'OP_DROP', 'OP_NIP', 'OP_1'];
const SPLIT_RESET_BRANCH = ['OP_0', 'OP_ROT', 'OP_DROP', 'OP_NIP', 'OP_0'];
const PIC_ORDER_TRUE_BRANCH = [
  'OP_DUP', 'OP_6', 'OP_PICK', 'OP_CAT', 'OP_3', 'OP_PICK', 'OP_CAT', 'OP_SHA256',
  'OP_6', 'OP_ROLL', 'OP_DROP', 'OP_SWAP', 'OP_TOALTSTACK', 'OP_SWAP',
  'OP_TOALTSTACK', 'OP_SWAP', 'OP_TOALTSTACK', 'OP_SWAP', 'OP_TOALTSTACK',
  'OP_SWAP', 'OP_FROMALTSTACK', 'OP_FROMALTSTACK', 'OP_FROMALTSTACK', 'OP_FROMALTSTACK',
];
const PIC_ORDER_FALSE_BRANCH = [
  'OP_DUP', 'OP_3', 'OP_PICK', 'OP_CAT', 'OP_6', 'OP_PICK', 'OP_CAT', 'OP_SHA256',
  'OP_6', 'OP_ROLL', 'OP_DROP', 'OP_SWAP', 'OP_TOALTSTACK', 'OP_SWAP',
  'OP_TOALTSTACK', 'OP_SWAP', 'OP_TOALTSTACK', 'OP_SWAP', 'OP_TOALTSTACK',
  'OP_SWAP', 'OP_FROMALTSTACK', 'OP_FROMALTSTACK', 'OP_FROMALTSTACK', 'OP_FROMALTSTACK',
];
const B_IDENTITY_TRUE_BRANCH = [
  'OP_12', 'OP_PICK', 'OP_5', 'OP_PICK', 'OP_NUMEQUALVERIFY',
  'OP_11', 'OP_PICK', 'OP_4', 'OP_PICK', 'OP_NUMEQUALVERIFY',
  'OP_10', 'OP_PICK', 'OP_3', 'OP_PICK', 'OP_NUMEQUALVERIFY',
  'OP_9', 'OP_PICK', 'OP_2', 'OP_PICK', 'OP_NUMEQUALVERIFY',
];
const B_IDENTITY_FALSE_BRANCH = [
  'OP_DUP', 'OP_0', 'OP_NUMNOTEQUAL', 'OP_VERIFY',
  'OP_11', 'OP_PICK', 'OP_13', 'OP_PICK', 'OP_0', 'OP_INVOKE',
  'OP_13', 'OP_PICK', 'OP_15', 'OP_PICK', 'OP_2OVER', 'OP_SWAP',
  'OP_3', 'OP_PICK', 'OP_2', 'OP_PICK', 'OP_3', 'OP_INVOKE',
  'OP_3', 'OP_PICK', 'OP_2', 'OP_PICK', 'OP_3', 'OP_INVOKE',
  'OP_2', 'OP_INVOKE', 'OP_2SWAP', 'OP_3', 'OP_INVOKE',
  'OP_2SWAP', 'OP_3', 'OP_INVOKE', 'OP_1', 'OP_INVOKE',
  'OP_4', 'OP_2', 'OP_PICK', 'OP_1', 'OP_INVOKE',
  'OP_4', 'OP_2', 'OP_PICK', 'OP_1', 'OP_INVOKE',
  'OP_15', 'OP_PICK', 'OP_PUSHBYTES_1', 'OP_PICK', 'OP_0', 'OP_INVOKE',
  'OP_OVER', 'OP_4', 'OP_PICK', 'OP_NUMEQUALVERIFY',
  'OP_DUP', 'OP_3', 'OP_PICK', 'OP_NUMEQUALVERIFY',
  'OP_2DROP', 'OP_2DROP', 'OP_2DROP', 'OP_2DROP',
];
const VARIABLE_CONDITIONAL_CLASSES = [
  { kind: 'pic-order', trueBranch: PIC_ORDER_TRUE_BRANCH,
    falseBranch: PIC_ORDER_FALSE_BRANCH, untakenTrueCost: 0 },
  { kind: 'b-identity', trueBranch: B_IDENTITY_TRUE_BRANCH,
    falseBranch: B_IDENTITY_FALSE_BRANCH, untakenTrueCost: 0 },
  { kind: 'split-reset', trueBranch: SPLIT_RESET_BRANCH,
    falseBranch: [], untakenTrueCost: 0 },
  { kind: 'identity', trueBranch: IDENTITY_BRANCH,
    falseBranch: [], untakenTrueCost: 299 },
  { kind: 'state-swap', trueBranch: STATE_SWAP_BRANCH,
    falseBranch: [], untakenTrueCost: 49 },
  { kind: 'select', trueBranch: SELECT_BRANCH,
    falseBranch: [], untakenTrueCost: 98 },
  { kind: 'select', trueBranch: SECOND_SPLIT_SELECT_BRANCH,
    falseBranch: [], untakenTrueCost: 98 },
  { kind: 'terminal-reset', trueBranch: TERMINAL_RESET_BRANCH,
    falseBranch: [], untakenTrueCost: 1 },
];
const branchShape = (instructions, ifIp) => {
  let depth = 0;
  let elseIp = -1;
  let endIp = -1;
  for (let ip = ifIp + 1; ip < instructions.length; ip += 1) {
    const opcode = instructions[ip].opcode;
    if (opcode === 99 || opcode === 100) depth += 1;
    else if (opcode === 104 && depth === 0) { endIp = ip; break; }
    else if (opcode === 104) depth -= 1;
    else if (opcode === 103 && depth === 0) elseIp = ip;
  }
  if (endIp < 0) throw new Error('conditional has no matching OP_ENDIF');
  const names = (start, end) => instructions.slice(start, end)
    .map((instruction) => OpcodesBCH[instruction.opcode]);
  return {
    trueBranch: names(ifIp + 1, elseIp < 0 ? endIp : elseIp),
    falseBranch: elseIp < 0 ? [] : names(elseIp + 1, endIp),
  };
};
const sameNames = (left, right) => left.length === right.length &&
  left.every((name, index) => name === right[index]);
const classifyVariableConditional = (instructions, ifIp) => {
  const actualShape = branchShape(instructions, ifIp);
  const specification = VARIABLE_CONDITIONAL_CLASSES.find((candidate) =>
    sameNames(actualShape.trueBranch, candidate.trueBranch) &&
    sameNames(actualShape.falseBranch, candidate.falseBranch));
  return { actualShape, specification };
};
const BASELINE_CONDITIONAL_COUNTS = [
  { fixed: 236, picOrder: 176, identity: 0, stateSwap: 0, select: 0, terminalReset: 0 },
  { fixed: 1, picOrder: 0, identity: 1, stateSwap: 0, select: 1, terminalReset: 0 },
  { fixed: 90, picOrder: 64, identity: 1, stateSwap: 1, select: 1, terminalReset: 0 },
  { fixed: 162, picOrder: 112, identity: 1, stateSwap: 1, select: 1, terminalReset: 0 },
  ...Array.from({ length: 12 }, (_, offset) => offset === 1
    ? { fixed: 1, picOrder: 0, identity: 1, stateSwap: 1, select: 1, terminalReset: 0 }
    : { fixed: 10, picOrder: 0, identity: 1, stateSwap: 1, select: 1, terminalReset: 0 }),
  { fixed: 110, picOrder: 80, identity: 1, stateSwap: 1, select: 1, terminalReset: 0 },
  ...Array.from({ length: 4 }, () =>
    ({ fixed: 10, picOrder: 0, identity: 1, stateSwap: 1, select: 1, terminalReset: 0 })),
  { fixed: 110, picOrder: 80, identity: 1, stateSwap: 1, select: 1, terminalReset: 1 },
  { fixed: 133, picOrder: 0, identity: 0, stateSwap: 0, select: 0, terminalReset: 0 },
].map((counts, inputIndex) => ({
  ...counts,
  ...([1, 16].includes(inputIndex) ? { identity: 2, select: 2, terminalReset: 1 } : {}),
  bIdentity: inputIndex === 0 ? 1 : 0,
  splitReset: inputIndex >= 1 && inputIndex <= 21 ? 1 : 0,
}));
const QSPLIT_CONDITIONAL_COUNTS = [
  { fixed: 236, picOrder: 176, identity: 0, stateSwap: 0, select: 0, terminalReset: 0 },
  { fixed: 1, picOrder: 0, identity: 2, stateSwap: 0, select: 2, terminalReset: 1 },
  { fixed: 90, picOrder: 64, identity: 1, stateSwap: 1, select: 1, terminalReset: 0 },
  { fixed: 183, picOrder: 128, identity: 1, stateSwap: 1, select: 1, terminalReset: 0 },
  ...Array.from({ length: 12 }, (_, offset) => ({
    fixed: offset === 1 ? 134 : 10,
    picOrder: 0,
    identity: 1,
    stateSwap: 1,
    select: 1,
    terminalReset: 0,
  })),
  { fixed: 89, picOrder: 64, identity: 2, stateSwap: 1, select: 2, terminalReset: 1 },
  ...Array.from({ length: 4 }, () =>
    ({ fixed: 10, picOrder: 0, identity: 1, stateSwap: 1, select: 1, terminalReset: 0 })),
  { fixed: 110, picOrder: 80, identity: 1, stateSwap: 1, select: 1, terminalReset: 1 },
].map((counts, inputIndex) => ({
  ...counts,
  bIdentity: inputIndex === 0 ? 1 : 0,
  splitReset: inputIndex >= 1 ? 1 : 0,
}));
const expectedConditionalCounts = qsplitProfile
  ? QSPLIT_CONDITIONAL_COUNTS
  : BASELINE_CONDITIONAL_COUNTS;
const bIdentityTrace = fixtureName === 'b-identity' || fixtureName === 'all-identity';
if (!probe && expectedConditionalCounts.length !== expectedInputCount) {
  throw new Error(`resource certificate tables must cover all ${expectedInputCount} inputs`);
}

const sameStack = (left, right) => left.length === right.length && left.every((item, index) => {
  const other = right[index];
  return item.length === other.length && item.every((byte, offset) => byte === other[offset]);
});

const unlockingByteTags = inputs.map((input, inputIndex) => {
  const instructions = decodeAuthenticationInstructions(input.unlocking);
  const output = new Uint8Array(input.unlocking.length);
  let offset = 0;
  instructions.forEach((instruction, instructionIndex) => {
    const encoded = encodeAuthenticationInstructions([instruction]);
    const data = instruction.data;
    if (data !== undefined) {
      const dataOffset = offset + encoded.length - data.length;
      output.fill(BYTE_UNKNOWN, dataOffset, dataOffset + data.length);
    }
    offset += encoded.length;
  });
  if (offset !== input.unlocking.length) throw new Error(`input ${inputIndex} instruction encoding changed`);
  return output;
});

const redeemStack = (inputIndex, stack) => {
  const instructions = decodeAuthenticationInstructions(inputs[inputIndex].unlocking).slice(0, -1);
  if (instructions.length !== stack.length) throw new Error('redeem-entry witness stack shape mismatch');
  return stack.map((item, stackIndex) => {
    const instruction = instructions[stackIndex];
    if (instruction.data === undefined || instruction.data.length !== item.length) {
      throw new Error('redeem-entry witness push mismatch');
    }
    return { length: item.length, byteTags: bytesTagged(item.length, BYTE_UNKNOWN) };
  });
};

const traceCeiling = (inputIndex) => {
  const states = vm.debug({ inputIndex, ...data });
  if (states.at(-1).error !== undefined) throw new Error(states.at(-1).error);
  let abstractStack = states[0].stack.map(concreteItem);
  let abstractAlternateStack = states[0].alternateStack.map(concreteItem);
  let adjustment = 0;
  const abstractConditionals = [];
  const adjustmentByOpcode = new Map();
  const arithmeticShapes = new Map();
  const conditionalCounts = {
    fixed: 0,
    picOrder: 0,
    identity: 0,
    stateSwap: 0,
    select: 0,
    terminalReset: 0,
    bIdentity: 0,
    splitReset: 0,
  };
  const conditionalShapes = new Map();
  const addAdjustment = (opcode, amount) => {
    adjustment += amount;
    adjustmentByOpcode.set(opcode, (adjustmentByOpcode.get(opcode) ?? 0) + amount);
  };
  const pop = () => {
    const item = abstractStack.pop();
    if (item === undefined) throw new Error('abstract stack underflow');
    return item;
  };
  const popMany = (count) => {
    const start = abstractStack.length - count;
    if (start < 0) throw new Error('abstract stack underflow');
    return abstractStack.splice(start, count);
  };
  const push = (...items) => abstractStack.push(...items);
  const resultLength = (next) => next.stack.at(-1)?.length ?? 0;

  for (let index = 0; index < states.length - 1; index += 1) {
    const state = states[index];
    const next = states[index + 1];
    const instruction = state.instructions[state.ip];
    const opcode = instruction?.opcode;

    if (opcode === undefined) {
      // VM phase transition: unlocking -> P2SH locking -> P2SH redeem. At
      // redeem entry, all <=32-byte witness arguments may independently range
      // over canonical field values; larger byte strings have fixed lengths.
      const witnessPushCount = decodeAuthenticationInstructions(inputs[inputIndex].unlocking).length - 1;
      if (state.instructions.length === 3 && state.ip === 3 &&
        next.instructions.length > 3 && next.stack.length === witnessPushCount) {
        abstractStack = redeemStack(inputIndex, next.stack);
        abstractAlternateStack = next.alternateStack.map(concreteItem);
      } else {
        if (abstractStack.length !== next.stack.length ||
          abstractAlternateStack.length !== next.alternateStack.length) {
          throw new Error(`unclassified VM frame transition at input ${inputIndex}, trace ${index}`);
        }
      }
      continue;
    }
    if (abstractStack.length !== state.stack.length) {
      throw new Error(`stack mismatch before ${index}: abstract=${abstractStack.length} concrete=${state.stack.length}`);
    }
    const active = state.controlStack.every(Boolean);
    if (!active && opcode !== 99 && opcode !== 103 && opcode !== 104) {
      if (!sameStack(state.stack, next.stack)) {
        throw new Error(`inactive ${OpcodesBCH[opcode]} changed the concrete stack`);
      }
      continue;
    }

    // Data pushes and small-integer pushes are proof-independent constants.
    if ((opcode >= 0 && opcode <= 78) || (opcode >= 81 && opcode <= 96)) {
      const item = next.stack.at(-1);
      if (item === undefined) throw new Error(`push failed at ${index}`);
      push(concreteItem(item));
    } else if (opcode === 107) { // OP_TOALTSTACK
      abstractAlternateStack.push(pop());
    } else if (opcode === 108) { // OP_FROMALTSTACK
      const item = abstractAlternateStack.pop();
      if (item === undefined) throw new Error('abstract alternate stack underflow');
      push(item);
      addAdjustment(opcode, item.length - resultLength(next));
    } else if (opcode === 109) { // OP_2DROP
      popMany(2);
    } else if (opcode === 110) { // OP_2DUP
      const [a, b] = popMany(2); push(a, b, { ...a }, { ...b });
      addAdjustment(opcode, a.length + b.length - state.stack.at(-2).length - state.stack.at(-1).length);
    } else if (opcode === 112) { // OP_2OVER
      const [a, b, c, d] = popMany(4); push(a, b, c, d, { ...a }, { ...b });
      addAdjustment(opcode, a.length + b.length - state.stack.at(-4).length - state.stack.at(-3).length);
    } else if (opcode === 113) { // OP_2ROT
      const [a, b, c, d, e, f] = popMany(6); push(c, d, e, f, a, b);
      addAdjustment(opcode, a.length + b.length - state.stack.at(-6).length - state.stack.at(-5).length);
    } else if (opcode === 114) { // OP_2SWAP
      const [a, b, c, d] = popMany(4); push(c, d, a, b);
    } else if (opcode === 117) { // OP_DROP
      pop();
    } else if (opcode === 118) { // OP_DUP
      const item = pop(); push(item, { ...item });
      addAdjustment(opcode, item.length - state.stack.at(-1).length);
    } else if (opcode === 119) { // OP_NIP
      const [, b] = popMany(2); push(b);
    } else if (opcode === 120) { // OP_OVER
      const [a, b] = popMany(2); push(a, b, { ...a });
      addAdjustment(opcode, a.length - state.stack.at(-2).length);
    } else if (opcode === 121 || opcode === 122) { // OP_PICK / OP_ROLL
      const depth = Number(actualNumber(state.stack.at(-1)));
      pop();
      const selectedIndex = abstractStack.length - 1 - depth;
      const item = abstractStack[selectedIndex];
      if (item === undefined) throw new Error(`invalid abstract stack depth ${depth}`);
      if (opcode === 121) push({ ...item });
      else {
        abstractStack.splice(selectedIndex, 1);
        push(item);
      }
      const actualSelected = state.stack[state.stack.length - 2 - depth];
      addAdjustment(opcode, item.length - actualSelected.length);
    } else if (opcode === 123) { // OP_ROT
      const [a, b, c] = popMany(3); push(b, c, a);
    } else if (opcode === 124) { // OP_SWAP
      const [a, b] = popMany(2); push(b, a);
    } else if (opcode === 126) { // OP_CAT
      const [a, b] = popMany(2);
      const byteTags = new Uint8Array(a.length + b.length);
      byteTags.set(a.byteTags ?? bytesTagged(a.length, BYTE_UNKNOWN));
      byteTags.set(b.byteTags ?? bytesTagged(b.length, BYTE_UNKNOWN), a.length);
      const output = { length: a.length + b.length, byteTags };
      push(output);
      addAdjustment(opcode, output.length - resultLength(next));
    } else if (opcode === 127) { // OP_SPLIT
      const splitAt = Number(actualNumber(state.stack.at(-1)));
      pop();
      const item = pop();
      const tags = item.byteTags ?? bytesTagged(item.length, BYTE_UNKNOWN);
      const left = { length: splitAt, byteTags: tags.slice(0, splitAt) };
      const right = { length: item.length - splitAt, byteTags: tags.slice(splitAt) };
      push(left, right);
      addAdjustment(opcode, item.length - (next.stack.at(-2).length + next.stack.at(-1).length));
    } else if (opcode === 128) { // OP_NUM2BIN
      const targetLength = Number(actualNumber(state.stack.at(-1)));
      pop();
      const value = pop();
      const fieldEncoded = value.minimum !== undefined && value.maximum !== undefined &&
        value.minimum >= 0n && value.maximum < P && targetLength === 48;
      push({
        length: targetLength,
        byteTags: bytesTagged(targetLength, fieldEncoded ? BYTE_FIELD : BYTE_UNKNOWN),
      });
      addAdjustment(opcode, targetLength - resultLength(next));
    } else if (opcode === 129) { // OP_BIN2NUM
      const item = pop();
      const tags = item.byteTags ?? bytesTagged(item.length, BYTE_UNKNOWN);
      const allTagged = (tag) => tags.every((value) => value === tag);
      let output;
      if (item.minimum !== undefined && item.maximum !== undefined) {
        output = numericItem(item.minimum, item.maximum);
      } else if (item.length === 48 || item.length === 49) {
        // Every accepted 48-byte numeric witness is range-checked as a
        // canonical BLS12-381 base-field element before arithmetic use. A
        // 49th zero byte is the explicit positive-sign extension.
        output = numericItem(0n, P - 1n);
      } else if (item.length === 33) {
        // Hash-to-scalar conversion appends a zero sign byte before BIN2NUM.
        output = numericItem(0n, (1n << 256n) - 1n);
      } else if (item.length > 0 && item.length <= 32) {
        const maximumMagnitude = (1n << BigInt(item.length * 8 - 1)) - 1n;
        output = numericItem(-maximumMagnitude, maximumMagnitude);
      } else if (allTagged(BYTE_FIXED)) {
        throw new Error('fixed BIN2NUM lost its concrete interval');
      } else {
        throw new Error(`unproved BIN2NUM provenance at input ${inputIndex}, trace ${index}, length ${item.length}`);
      }
      push(output);
      addAdjustment(opcode, output.length - resultLength(next));
    } else if (opcode === 130) { // OP_SIZE
      const item = pop();
      const size = numericItem(BigInt(item.length));
      push(item, size);
      addAdjustment(opcode, size.length - resultLength(next));
    } else if (opcode === 135) { // OP_EQUAL
      popMany(2); push(numericItem(0n, 1n));
      addAdjustment(opcode, 1 - resultLength(next));
    } else if (opcode === 136 || opcode === 157) { // EQUALVERIFY / NUMEQUALVERIFY
      popMany(2);
    } else if (opcode === 137) { // OP_DEFINE: function body, arity
      popMany(2);
    } else if (opcode === 138) { // OP_INVOKE: function index
      pop();
    } else if (opcode === 139 || opcode === 140) { // OP_1ADD / OP_1SUB
      const value = pop();
      requireInterval(value);
      const delta = opcode === 139 ? 1n : -1n;
      const output = numericItem(value.minimum + delta, value.maximum + delta);
      push(output);
      addAdjustment(opcode, 2 * (output.length - resultLength(next)));
    } else if (opcode === 142) { // OP_RSHIFTNUM
      const shift = BigInt(actualNumber(state.stack.at(-1)));
      pop();
      const value = pop();
      requireInterval(value);
      const output = numericItem(value.minimum >> shift, value.maximum >> shift);
      push(output);
      addAdjustment(opcode, output.length - resultLength(next));
    } else if (opcode === 143 || opcode === 144) { // OP_NEGATE / OP_ABS
      const value = pop();
      requireInterval(value);
      const output = opcode === 143
        ? numericItem(-value.maximum, -value.minimum)
        : numericItem(
          value.minimum <= 0n && value.maximum >= 0n
            ? 0n
            : (abs(value.minimum) < abs(value.maximum) ? abs(value.minimum) : abs(value.maximum)),
          abs(value.minimum) > abs(value.maximum) ? abs(value.minimum) : abs(value.maximum),
        );
      push(output);
      addAdjustment(opcode, 2 * (output.length - resultLength(next)));
    } else if (opcode === 145 || opcode === 146) { // OP_NOT / OP_0NOTEQUAL
      const value = requireInterval(pop());
      const definitelyZero = value.minimum === 0n && value.maximum === 0n;
      const definitelyNonzero = value.maximum < 0n || value.minimum > 0n;
      const output = opcode === 145
        ? (definitelyZero ? numericItem(1n) : definitelyNonzero ? numericItem(0n) : numericItem(0n, 1n))
        : (definitelyZero ? numericItem(0n) : definitelyNonzero ? numericItem(1n) : numericItem(0n, 1n));
      push(output);
      addAdjustment(opcode, 1 - resultLength(next));
    } else if (opcode === 147 || opcode === 148 || opcode === 149 || opcode === 151) {
      const [a, b] = popMany(2);
      requireInterval(a); requireInterval(b);
      let minimum;
      let maximum;
      if (opcode === 147) {
        minimum = a.minimum + b.minimum;
        maximum = a.maximum + b.maximum;
      } else if (opcode === 148) {
        minimum = a.minimum - b.maximum;
        maximum = a.maximum - b.minimum;
      } else if (opcode === 149) {
        [minimum, maximum] = multiplyIntervals(a, b);
      } else {
        const modulusMaximum = abs(b.minimum) > abs(b.maximum) ? abs(b.minimum) : abs(b.maximum);
        if (a.minimum === a.maximum && b.minimum === b.maximum && b.minimum !== 0n) {
          minimum = a.minimum % b.minimum;
          maximum = minimum;
        } else if (a.minimum >= 0n && b.minimum > 0n) {
          minimum = 0n; maximum = modulusMaximum - 1n;
        } else if (a.maximum <= 0n && b.minimum > 0n) {
          minimum = -(modulusMaximum - 1n); maximum = 0n;
        } else {
          minimum = -(modulusMaximum - 1n); maximum = modulusMaximum - 1n;
        }
      }
      const output = numericItem(minimum, maximum);
      push(output);
      if (opcode === 149 || opcode === 151) {
        const shape = `${OpcodesBCH[opcode]} ${state.stack.at(-2).length}x${state.stack.at(-1).length}->${resultLength(next)} => ${a.length}x${b.length}->${output.length}`;
        arithmeticShapes.set(shape, (arithmeticShapes.get(shape) ?? 0) + 1);
      }
      let delta = 2 * (output.length - resultLength(next));
      if (opcode === 149 || opcode === 151) {
        delta += a.length * b.length - state.stack.at(-2).length * state.stack.at(-1).length;
      }
      addAdjustment(opcode, delta);
    } else if (opcode === 154 || opcode === 155 || opcode === 156 || opcode === 158 ||
      opcode === 159 || opcode === 160 || opcode === 161 || opcode === 162) {
      const [left, right] = popMany(2);
      requireInterval(left); requireInterval(right);
      let known;
      if (opcode === 154 || opcode === 155) {
        const leftZero = left.minimum === 0n && left.maximum === 0n;
        const leftNonzero = left.maximum < 0n || left.minimum > 0n;
        const rightZero = right.minimum === 0n && right.maximum === 0n;
        const rightNonzero = right.maximum < 0n || right.minimum > 0n;
        if (opcode === 154 && (leftZero || rightZero)) known = 0n;
        else if (opcode === 154 && leftNonzero && rightNonzero) known = 1n;
        else if (opcode === 155 && leftZero && rightZero) known = 0n;
        else if (opcode === 155 && (leftNonzero || rightNonzero)) known = 1n;
      } else if (opcode === 156 || opcode === 158) {
        const equal = left.minimum === left.maximum && right.minimum === right.maximum &&
          left.minimum === right.minimum;
        const disjoint = left.maximum < right.minimum || right.maximum < left.minimum;
        if (equal) known = opcode === 156 ? 1n : 0n;
        else if (disjoint) known = opcode === 156 ? 0n : 1n;
      } else if (opcode === 159) {
        if (left.maximum < right.minimum) known = 1n;
        else if (left.minimum >= right.maximum) known = 0n;
      } else if (opcode === 160) {
        if (left.minimum > right.maximum) known = 1n;
        else if (left.maximum <= right.minimum) known = 0n;
      } else if (opcode === 161) {
        if (left.maximum <= right.minimum) known = 1n;
        else if (left.minimum > right.maximum) known = 0n;
      } else if (opcode === 162) {
        if (left.minimum >= right.maximum) known = 1n;
        else if (left.maximum < right.minimum) known = 0n;
      }
      const result = known === undefined ? numericItem(0n, 1n) : numericItem(known);
      if (opcode === 159 && right.minimum === 0n && right.maximum === 0n) {
        result.lessThanZeroLineage = left.lineage;
      }
      push(result);
      addAdjustment(opcode, 1 - resultLength(next));
    } else if (opcode === 165) { // OP_WITHIN
      popMany(3); push(numericItem(0n, 1n));
      addAdjustment(opcode, 1 - resultLength(next));
    } else if (opcode === 99) { // OP_IF
      if (!active) {
        abstractConditionals.push({ kind: 'inactive' });
      } else {
        const condition = requireInterval(pop());
        const site = `${state.instructions.length}:${state.ip}`;
        const taken = next.controlStack.at(-1) === true;
        const fixed = condition.minimum === condition.maximum;
        if (fixed) {
          if (taken !== (condition.minimum !== 0n)) {
            throw new Error(`fixed OP_IF decision differs from its abstract value at ${site}`);
          }
          conditionalCounts.fixed += 1;
          conditionalShapes.set(`${site}:fixed`,
            (conditionalShapes.get(`${site}:fixed`) ?? 0) + 1);
          abstractConditionals.push({ kind: 'fixed' });
        } else {
          if (condition.minimum !== 0n || condition.maximum !== 1n) {
            throw new Error(`non-boolean OP_IF range at ${site}: ` +
              `[${condition.minimum},${condition.maximum}]`);
          }
          const { actualShape, specification } = classifyVariableConditional(
            state.instructions,
            state.ip,
          );
          if (specification === undefined) {
            throw new Error(`unclassified variable OP_IF site ${site} at input ${inputIndex}: ` +
              JSON.stringify({ taken, ...actualShape }));
          }
          if (!taken && specification.untakenTrueCost !== 0) {
            addAdjustment(opcode, specification.untakenTrueCost);
          }
          const countKey = specification.kind === 'pic-order'
            ? 'picOrder'
            : specification.kind === 'b-identity'
              ? 'bIdentity'
              : specification.kind === 'split-reset'
                ? 'splitReset'
            : specification.kind === 'state-swap'
              ? 'stateSwap'
              : specification.kind === 'terminal-reset'
                ? 'terminalReset'
                : specification.kind;
          conditionalCounts[countKey] += 1;
          conditionalShapes.set(`${site}:${specification.kind}`,
            (conditionalShapes.get(`${site}:${specification.kind}`) ?? 0) + 1);
          abstractConditionals.push({ kind: specification.kind });
        }
      }
    } else if (opcode === 101) { // OP_BEGIN
      // control stack only
    } else if (opcode === 102) { // OP_UNTIL
      if (active) pop();
    } else if (opcode === 103 || opcode === 104) { // OP_ELSE / OP_ENDIF
      if (opcode === 104) {
        const context = abstractConditionals.pop();
        if (context === undefined) throw new Error('abstract conditional stack underflow');
        if (context.kind === 'state-swap' || context.kind === 'select' ||
          context.kind === 'terminal-reset') {
          if (abstractStack.length < 2) throw new Error(`${context.kind} merge underflow`);
          abstractStack[abstractStack.length - 2] = numericItem(0n, P - 1n);
          abstractStack[abstractStack.length - 1] = numericItem(0n, P - 1n);
        }
      }
    } else if (opcode === 105) { // OP_VERIFY
      pop();
    } else if (opcode === 168 || opcode === 170) { // OP_SHA256 / OP_HASH256
      pop(); push({ length: 32, byteTags: bytesTagged(32, BYTE_UNKNOWN) });
    } else if (opcode === 192) { // OP_INPUTINDEX
      push(numericItem(BigInt(inputIndex)));
    } else if (opcode === 195) { // OP_TXINPUTCOUNT
      push(numericItem(BigInt(inputs.length)));
    } else if (opcode === 196) { // OP_TXOUTPUTCOUNT
      push(numericItem(BigInt(data.transaction.outputs.length)));
    } else if (opcode === 199) { // OP_UTXOBYTECODE
      const target = Number(actualNumber(state.stack.at(-1)));
      pop();
      push({
        length: inputs[target].locking.length,
        byteTags: bytesTagged(inputs[target].locking.length, BYTE_FIXED),
      });
    } else if (opcode === 202) { // OP_INPUTBYTECODE
      const target = Number(actualNumber(state.stack.at(-1)));
      pop();
      push({ length: inputs[target].unlocking.length, byteTags: unlockingByteTags[target] });
    } else if (opcode === 205) { // OP_OUTPUTBYTECODE
      const target = Number(actualNumber(state.stack.at(-1)));
      pop();
      const output = data.transaction.outputs[target];
      if (output === undefined) throw new Error(`invalid output index ${target}`);
      push(concreteItem(output.lockingBytecode));
    } else {
      throw new Error(`unsupported opcode ${opcode} (${OpcodesBCH[opcode]}) at trace state ${index}`);
    }

    if (abstractStack.length !== next.stack.length) {
      throw new Error(`stack mismatch after ${index} ${OpcodesBCH[opcode]}: abstract=${abstractStack.length} concrete=${next.stack.length}`);
    }
  }

  if (abstractConditionals.length !== 0) throw new Error('unterminated abstract conditional');
  if (!probe && JSON.stringify(conditionalCounts) !==
    JSON.stringify(expectedConditionalCounts[inputIndex])) {
    throw new Error(`unexpected conditional inventory at input ${inputIndex}: ` +
      `${JSON.stringify(conditionalCounts)} shapes=${JSON.stringify([...conditionalShapes])}`);
  }
  const finalCost = states.at(-1).metrics.operationCost;
  return {
    inputIndex,
    finalCost,
    adjustment,
    ceiling: finalCost + adjustment,
    adjustmentByOpcode: [...adjustmentByOpcode]
      .filter(([, amount]) => amount !== 0)
      .sort((a, b) => b[1] - a[1])
      .map(([opcode, amount]) => `${OpcodesBCH[opcode]}:${amount}`),
    arithmeticShapes: [...arithmeticShapes]
      .sort((a, b) => b[1] - a[1])
      .slice(0, 20)
      .map(([shape, count]) => `${count} ${shape}`),
    conditionalCounts,
    conditionalShapes: [...conditionalShapes].sort(([left], [right]) => left.localeCompare(right)),
  };
};

const resourceResults = [];
for (let inputIndex = 0; inputIndex < inputs.length; inputIndex += 1) {
  const result = traceCeiling(inputIndex);
  resourceResults.push(result);
  if (process.env.COMPACT !== '1') {
    console.log(`input${inputIndex}: actual=${result.finalCost} adjustment=${result.adjustment} ` +
      `resource-ceiling=${result.ceiling}`);
    console.log(`  branches=${JSON.stringify(result.conditionalCounts)} ` +
      `shapes=${JSON.stringify(result.conditionalShapes)} ${result.adjustmentByOpcode.join(' ')}`);
    if (process.env.SHAPES === '1') console.log(`  ${result.arithmeticShapes.join('\n  ')}`);
  }
}
const ceilings = resourceResults.map((result) => result.ceiling);
const margins = resourceResults.map((result, inputIndex) =>
  (41 + inputs[inputIndex].unlocking.length) * 800 - result.ceiling);
if (!probe && margins.some((margin) => margin < 0)) {
  throw new Error(`q132 resource ceiling exceeds standard density: ${JSON.stringify(margins)}`);
}
const certificate = {
  resourceProfile,
  fixture: fixtureName,
  branchClass: bIdentityTrace ? 'B-identity' : 'B-nonidentity',
  probe,
  derivedFromResourceBytecodes: true,
  minimumUniversalMargin: Math.min(...margins),
  results: resourceResults.map(({ inputIndex, finalCost, adjustment, ceiling,
    conditionalCounts }) => ({
    inputIndex,
    finalCost,
    adjustment,
    ceiling,
    densityMargin: margins[inputIndex],
    conditionalCounts,
  })),
};
if (process.env.RESOURCE_EXPECTED_CERTIFICATE_PATH !== undefined) {
  const expectedCertificate = JSON.parse(readFileSync(resolve(
    process.env.RESOURCE_EXPECTED_CERTIFICATE_PATH,
  ), 'utf8'));
  if (JSON.stringify(certificate) !== JSON.stringify(expectedCertificate)) {
    throw new Error('derived resource certificate differs from the expected artifact');
  }
}
if (process.env.RESOURCE_RESULT_PATH !== undefined) {
  writeFileSync(process.env.RESOURCE_RESULT_PATH, `${JSON.stringify(certificate, null, 2)}\n`);
}
if (process.env.COMPACT === '1') {
  console.log(JSON.stringify(certificate));
} else {
  console.log(`proved q132 resource ceilings=${JSON.stringify(ceilings)} ` +
    `minimum-universal-margin=${Math.min(...margins)}`);
}

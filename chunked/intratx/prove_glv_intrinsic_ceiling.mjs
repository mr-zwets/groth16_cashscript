// Trace-driven abstract resource ceiling for the two grouped BN254 GLV inputs,
// plus an exact static replay of the equal-point branch surcharge.
//
// The concrete BCH2026 debug trace supplies the compiler's exact stack schedule,
// fixed instruction/base/hash costs, and fixed byte-string lengths. The shadow
// stack replaces every proof-controlled field element with the full canonical
// range [-(p-1), p-1], propagates magnitude bounds through arithmetic, and adds
// the resulting worst-case arithmetic-encoding and stack-push deltas.
//
// The full-valid resource fixture differs from the all-index-1 density trace in
// one final lookup. This script constructs that trace locally by changing only
// the two GLV inputs and their exact projective handoff. It verifies inputs 0 and
// 1 independently, and also asserts that the constructed trace is not a valid
// full transaction. It is a control-flow/operation-cost certificate, never a
// benchmark proof fixture.

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  OpcodesBCH,
  binToHex,
  createVirtualMachineBch2026,
  decodeAuthenticationInstructions,
  encodeAuthenticationInstructions,
  encodeDataPush,
  encodeTransactionBch,
  hexToBin,
  vmNumberToBigInt,
} from '@bitauth/libauth';
import {
  GLV_LAMBDA,
  GLV_R,
  VKXGLV_SPLIT_GROUPS,
  VKXGLV_SPLIT_ITERS,
  vkxGlvSplitStateAt,
} from '../pairing/gen_vkx_glv.mjs';
import { GLV_GROUPED_BOUNDS } from '../regen_vkx_windows.mjs';

const verifierDir = process.env.VERIFIER_DIR;
if (verifierDir === undefined) {
  throw new Error('VERIFIER_DIR must point to the matching zk-verifier-bench checkout');
}

const vectorPath = join(verifierDir, 'src/bch/groth16-intratx-residue-vectors.json');
const vectors = JSON.parse(readFileSync(vectorPath, 'utf8'));
const resourceSteps = vectors.resourceFixtureProof;
if (!Array.isArray(resourceSteps) || resourceSteps.length !== 11) {
  throw new Error('missing named 11-input full-valid resource fixture');
}
if (VKXGLV_SPLIT_GROUPS !== 2 || VKXGLV_SPLIT_ITERS !== 64 ||
  GLV_GROUPED_BOUNDS.length !== 3 || GLV_GROUPED_BOUNDS[0] !== 0 ||
  GLV_GROUPED_BOUNDS[1] !== 29 || GLV_GROUPED_BOUNDS[2] !== VKXGLV_SPLIT_ITERS) {
  throw new Error('GLV resource proof requires the 2x64 schedule with bounds [0,29,64]');
}

const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const R = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const GLV_BOUND = 1n << 128n;
const DEFAULT_MIN_RELAY_FEE_SATOSHIS_PER_BYTE = 1n;
const TRANSACTION_OUTPUT_SATOSHIS = 1000n;
if (R !== GLV_R) throw new Error('GLV scalar order changed');
const vm = createVirtualMachineBch2026(true);
const toInputs = (candidateSteps) => candidateSteps.map((step) => ({
  locking: hexToBin(step.locking),
  unlocking: hexToBin(step.unlocking),
}));
const verificationData = (candidateInputs) => {
  const transaction = {
    version: 2,
    inputs: candidateInputs.map((input, index) => ({
      outpointTransactionHash: new Uint8Array(32),
      outpointIndex: index,
      sequenceNumber: 0,
      unlockingBytecode: input.unlocking,
    })),
    outputs: [{
      lockingBytecode: Uint8Array.of(0x6a),
      valueSatoshis: TRANSACTION_OUTPUT_SATOSHIS,
    }],
    locktime: 0,
  };
  const wireBytes = encodeTransactionBch(transaction).length;
  const requiredInputValue = TRANSACTION_OUTPUT_SATOSHIS +
    BigInt(wireBytes) * DEFAULT_MIN_RELAY_FEE_SATOSHIS_PER_BYTE;
  const sourceOutputValue = (requiredInputValue + BigInt(candidateInputs.length) - 1n) /
    BigInt(candidateInputs.length);
  return {
    sourceOutputs: candidateInputs.map((input) => ({
      lockingBytecode: input.locking,
      valueSatoshis: sourceOutputValue,
    })),
    transaction,
  };
};
const resourceInputs = toInputs(resourceSteps);
const resourceData = verificationData(resourceInputs);
if (vm.verify(resourceData) !== true) throw new Error('resourceFixtureProof is not full-valid and standard');
const resourceFee = resourceData.sourceOutputs.reduce((total, output) => total + output.valueSatoshis, 0n) -
  resourceData.transaction.outputs.reduce((total, output) => total + output.valueSatoshis, 0n);
const resourceWireBytes = encodeTransactionBch(resourceData.transaction).length;
if (resourceFee < BigInt(resourceWireBytes) * DEFAULT_MIN_RELAY_FEE_SATOSHIS_PER_BYTE) {
  throw new Error('resourceFixtureProof does not fund the default minimum relay fee');
}

const fromLe = (bytes) => {
  let value = 0n;
  for (let index = bytes.length - 1; index >= 0; index -= 1) value = value << 8n | BigInt(bytes[index]);
  return value;
};
const toLe = (value, width) => {
  const output = new Uint8Array(width);
  let remaining = value;
  for (let index = 0; index < width; index += 1) {
    output[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  if (remaining !== 0n) throw new Error(`value does not fit ${width} bytes`);
  return output;
};
const firstPush = (unlocking) => {
  const instruction = decodeAuthenticationInstructions(unlocking)[0];
  if (instruction?.data === undefined) throw new Error('missing inBlob push');
  return instruction.data;
};
const replaceFirstPush = (unlocking, dataBytes) => {
  const instructions = decodeAuthenticationInstructions(unlocking);
  const replacement = decodeAuthenticationInstructions(encodeDataPush(dataBytes));
  if (replacement.length !== 1) throw new Error('replacement inBlob push is malformed');
  instructions[0] = replacement[0];
  return encodeAuthenticationInstructions(instructions);
};
const growPadding = (unlocking) => {
  const instructions = decodeAuthenticationInstructions(unlocking);
  const padding = instructions.at(-2);
  if (padding?.data === undefined) throw new Error('missing penultimate padding push');
  const replacement = decodeAuthenticationInstructions(encodeDataPush(
    new Uint8Array(padding.data.length + 1),
  ));
  if (replacement.length !== 1) throw new Error('replacement padding push is malformed');
  instructions[instructions.length - 2] = replacement[0];
  return encodeAuthenticationInstructions(instructions);
};
const serializeGenesis = (publicInputs, scalars) => {
  const output = new Uint8Array(2 * 32 + 4 * 17);
  publicInputs.forEach((value, index) => output.set(toLe(value, 32), index * 32));
  scalars.forEach((value, index) => output.set(toLe(value, 17), 64 + index * 17));
  return output;
};
const serializeState = (state, publicInputs, scalars) => {
  const output = new Uint8Array(5 * 32 + 4 * 17);
  state.forEach((value, index) => output.set(toLe(value, 32), index * 32));
  publicInputs.forEach((value, index) => output.set(toLe(value, 32), (3 + index) * 32));
  scalars.forEach((value, index) => output.set(toLe(value, 17), 160 + index * 17));
  return output;
};

const denseScalar = GLV_BOUND - 1n;
const resourceScalars = [denseScalar, 0n, 1n, 0n];
const resourcePublicInputs = [denseScalar, 1n];
const resourceGenesis = firstPush(resourceInputs[0].unlocking);
const parsedResourceInputs = [fromLe(resourceGenesis.slice(0, 32)), fromLe(resourceGenesis.slice(32, 64))];
const parsedResourceScalars = Array.from({ length: 4 }, (_, index) =>
  fromLe(resourceGenesis.slice(64 + index * 17, 81 + index * 17)));
if (JSON.stringify(parsedResourceInputs.map(String)) !== JSON.stringify(resourcePublicInputs.map(String)) ||
  JSON.stringify(parsedResourceScalars.map(String)) !== JSON.stringify(resourceScalars.map(String))) {
  throw new Error('resourceFixtureProof does not contain the pinned full-valid GLV witness');
}
resourcePublicInputs.forEach((value, index) => {
  const reconstructed = (resourceScalars[2 * index] + resourceScalars[2 * index + 1] * GLV_LAMBDA) % R;
  if (reconstructed !== value) throw new Error('resource fixture GLV witness does not reconstruct its input');
});

const densityScalars = [denseScalar, 0n, 0n, 0n];
const densityPublicInputs = [denseScalar, 0n];
const boundaryState = vkxGlvSplitStateAt(...densityScalars, GLV_GROUPED_BOUNDS[1]);
const finalState = vkxGlvSplitStateAt(...densityScalars, VKXGLV_SPLIT_ITERS);
const resourceFinalState = vkxGlvSplitStateAt(...resourceScalars, VKXGLV_SPLIT_ITERS);
const densitySteps = resourceSteps.map((step) => ({ ...step }));
densitySteps[0].unlocking = binToHex(replaceFirstPush(
  resourceInputs[0].unlocking,
  serializeGenesis(densityPublicInputs, densityScalars),
));
densitySteps[1].unlocking = binToHex(replaceFirstPush(
  resourceInputs[1].unlocking,
  serializeState(boundaryState, densityPublicInputs, densityScalars),
));
// The full-valid fixture saves one final table lookup, so its padding is one
// byte too short for the all-index-1 control trace. Grow only the local control;
// this also makes the exact successor-bytecode dependency visible to input 0.
densitySteps[1].unlocking = binToHex(growPadding(hexToBin(densitySteps[1].unlocking)));
const input2Blob = firstPush(resourceInputs[2].unlocking).slice();
const projectiveOffset = 8 * 32;
resourceFinalState.forEach((value, index) => {
  const carried = fromLe(input2Blob.slice(projectiveOffset + index * 32, projectiveOffset + (index + 1) * 32));
  if (carried !== value) throw new Error(`resource fixture projective handoff mismatch at limb ${index}`);
  input2Blob.set(toLe(finalState[index], 32), projectiveOffset + index * 32);
});
densitySteps[2].unlocking = binToHex(replaceFirstPush(resourceInputs[2].unlocking, input2Blob));

const steps = densitySteps;
const inputs = steps.map((step) => ({
  locking: hexToBin(step.locking),
  unlocking: hexToBin(step.unlocking),
}));
const BYTE_UNKNOWN = 0;
const BYTE_FIELD = 1;
const BYTE_FIXED = 2;
const BYTE_SCALAR = 3;

const data = verificationData(inputs);
for (const inputIndex of [0, 1]) {
  const state = vm.evaluate({ inputIndex, ...data });
  if (state.error !== undefined) throw new Error(`density trace input ${inputIndex} failed: ${state.error}`);
}
if (vm.verify(data) === true) throw new Error('density trace unexpectedly formed a valid full transaction');

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
const numericItem = (minimum, maximum = minimum) => ({
  length: vmLength(abs(minimum) > abs(maximum) ? abs(minimum) : abs(maximum)),
  minimum,
  maximum,
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

const sameStack = (left, right) => left.length === right.length && left.every((item, index) => {
  const other = right[index];
  return item.length === other.length && item.every((byte, offset) => byte === other[offset]);
});

const inBlobTags = (inputIndex, length) => {
  const tags = bytesTagged(length, BYTE_FIELD);
  if (inputIndex === 0) {
    if (length !== 132) throw new Error(`input 0 inBlob length changed: ${length}`);
    tags.fill(BYTE_SCALAR, 64);
  } else if (inputIndex === 1) {
    if (length !== 228) throw new Error(`input 1 inBlob length changed: ${length}`);
    tags.fill(BYTE_SCALAR, 160);
  } else if (length % 32 !== 0) {
    throw new Error(`input ${inputIndex} inBlob is not fixed-width field data`);
  }
  return tags;
};

const unlockingByteTags = inputs.map((input, inputIndex) => {
  const instructions = decodeAuthenticationInstructions(input.unlocking);
  const output = new Uint8Array(input.unlocking.length);
  let offset = 0;
  instructions.forEach((instruction, instructionIndex) => {
    const encoded = encodeAuthenticationInstructions([instruction]);
    const data = instruction.data;
    if (data !== undefined) {
      const dataOffset = offset + encoded.length - data.length;
      if (instructionIndex === 0) {
        output.set(inBlobTags(inputIndex, data.length), dataOffset);
      } else if (inputIndex === 1 && instructionIndex === 1 &&
        data.length === VKXGLV_SPLIT_GROUPS * 15 * 64) {
        output.fill(BYTE_FIELD, dataOffset, dataOffset + data.length);
      }
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
    if (stackIndex === 0) {
      return { length: item.length, byteTags: inBlobTags(inputIndex, item.length) };
    }
    if (inputIndex === 1 && stackIndex === 1 && item.length === VKXGLV_SPLIT_GROUPS * 15 * 64) {
      return {
        length: item.length,
        byteTags: bytesTagged(item.length, BYTE_FIELD),
      };
    }
    return concreteItem(item, bytesTagged(item.length, BYTE_UNKNOWN));
  });
};

const traceCeiling = (inputIndex) => {
  const states = vm.debug({ inputIndex, ...data });
  if (states.at(-1).error !== undefined) throw new Error(states.at(-1).error);
  const inventory = new Map();
  for (let index = 0; index < states.length - 1; index += 1) {
    const state = states[index];
    if (state.instructions[state.ip]?.opcode !== 99) continue;
    const key = `${state.instructions.length}:${state.ip}`;
    const counts = inventory.get(key) ?? [0, 0];
    counts[states[index + 1].controlStack.at(-1) === true ? 0 : 1] += 1;
    inventory.set(key, counts);
  }
  const actualInventory = [...inventory].sort(([left], [right]) => left.localeCompare(right));
  const expectedInventory = (inputIndex === 0 ? [
    ['137:9', [57, 1]], ['614:127', [29, 1]], ['614:135', [28, 2]],
    ['614:213', [29, 1]], ['614:250', [29, 1]], ['614:264', [0, 30]],
    ['614:388', [29, 1]], ['614:425', [29, 1]], ['614:439', [0, 30]],
  ] : [
    ['137:9', [70, 0]], ['504:145', [35, 1]], ['504:182', [35, 1]],
    ['504:196', [0, 36]], ['504:313', [35, 1]], ['504:350', [35, 1]],
    ['504:364', [0, 36]], ['504:66', [35, 1]], ['504:74', [35, 1]],
  ]).sort(([left], [right]) => left.localeCompare(right));
  if (JSON.stringify(actualInventory) !== JSON.stringify(expectedInventory)) {
    throw new Error(`input ${inputIndex} GLV conditional inventory changed: ${JSON.stringify(actualInventory)}`);
  }
  let abstractStack = states[0].stack.map(concreteItem);
  let abstractAlternateStack = states[0].alternateStack.map(concreteItem);
  let adjustment = 0;
  const abstractConditionals = [];
  const adjustmentByOpcode = new Map();
  const arithmeticShapes = new Map();
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
      abstractStack = next.instructions.length > 100 && next.stack.length === witnessPushCount
        ? redeemStack(inputIndex, next.stack)
        : next.stack.map((item) => concreteItem(item));
      abstractAlternateStack = next.alternateStack.map(concreteItem);
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
    } else if (opcode === 125) { // OP_TUCK
      const [a, b] = popMany(2); push({ ...b }, a, b);
      addAdjustment(opcode, b.length - state.stack.at(-1).length);
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
        value.minimum >= 0n && value.maximum < P && targetLength === 32;
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
      } else if (item.length === 17 && allTagged(BYTE_SCALAR)) {
        output = numericItem(0n, GLV_BOUND - 1n);
      } else if (item.length === 32 && allTagged(BYTE_FIELD)) {
        output = numericItem(0n, (P > R ? P : R) - 1n);
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
      pop(); push(numericItem(0n, 1n));
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
        if (a.minimum >= 0n && b.minimum > 0n) {
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
      popMany(2); push(numericItem(0n, 1n));
      addAdjustment(opcode, 1 - resultLength(next));
    } else if (opcode === 165) { // OP_WITHIN
      popMany(3); push(numericItem(0n, 1n));
      addAdjustment(opcode, 1 - resultLength(next));
    } else if (opcode === 99) { // OP_IF
      if (active) pop();
      abstractConditionals.push({});
    } else if (opcode === 101) { // OP_BEGIN
      // control stack only
    } else if (opcode === 102) { // OP_UNTIL
      if (active) pop();
    } else if (opcode === 103 || opcode === 104) { // OP_ELSE / OP_ENDIF
      if (opcode === 104) {
        const context = abstractConditionals.pop();
        if (context === undefined) throw new Error('abstract conditional stack underflow');
      }
    } else if (opcode === 105) { // OP_VERIFY
      pop();
    } else if (opcode === 168 || opcode === 170) { // OP_SHA256 / OP_HASH256
      pop(); push({ length: 32, byteTags: bytesTagged(32, BYTE_UNKNOWN) });
    } else if (opcode === 192) { // OP_INPUTINDEX
      push(numericItem(BigInt(inputIndex)));
    } else if (opcode === 195) { // OP_TXINPUTCOUNT
      push(numericItem(BigInt(inputs.length)));
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
    } else {
      throw new Error(`unsupported opcode ${opcode} (${OpcodesBCH[opcode]}) at trace state ${index}`);
    }

    if (abstractStack.length !== next.stack.length) {
      throw new Error(`stack mismatch after ${index} ${OpcodesBCH[opcode]}: abstract=${abstractStack.length} concrete=${next.stack.length}`);
    }
  }

  if (abstractConditionals.length !== 0) throw new Error('unterminated abstract conditional');
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
    conditionalInventory: actualInventory,
  };
};

const dependencyCost = (inputIndex) => {
  if (inputIndex === 0) return inputs[0].unlocking.length + 4 * inputs[1].unlocking.length;
  if (inputIndex === 1) return inputs[1].unlocking.length + 2 * inputs[2].unlocking.length;
  if (inputIndex === 2) return inputs[2].unlocking.length + 2 * inputs[3].unlocking.length;
  if (inputIndex < inputs.length - 1) {
    return 2 * inputs[2].unlocking.length + inputs[inputIndex].unlocking.length +
      2 * inputs[inputIndex + 1].unlocking.length;
  }
  return 2 * inputs[2].unlocking.length + inputs[inputIndex].unlocking.length;
};

const intrinsicCeilings = [];
for (let inputIndex = 0; inputIndex < 2; inputIndex += 1) {
  const result = traceCeiling(inputIndex);
  const intrinsic = result.ceiling - dependencyCost(inputIndex);
  intrinsicCeilings.push(intrinsic);
  console.log(`input${inputIndex}: actual=${result.finalCost} adjustment=${result.adjustment} ` +
    `total-ceiling=${result.ceiling} intrinsic-ceiling=${intrinsic}`);
  console.log(`  branches=${JSON.stringify(result.conditionalInventory)} ${result.adjustmentByOpcode.join(' ')}`);
  if (process.env.SHAPES === '1') console.log(`  ${result.arithmeticShapes.join('\n  ')}`);
}
console.log(`GLV generic intrinsic ceilings=${JSON.stringify(intrinsicCeilings)}`);

// The all-index-1 trace above exercises every generic affine-add slot, but an
// equal affine point takes a deliberately rare sentinel path: jacAddAffine
// returns three zeroes, then the caller invokes jacDouble and replaces them.
// Replay both compiled functions below so that this event's surcharge is tied
// to the exact bytecode rather than a source-level operation estimate.
const BASE_OPERATION_COST = 100;
const ADD_FUNCTION_LENGTH = 137;
const DOUBLE_FUNCTION_LENGTH = 68;
const EQUALITY_ZERO_MOD_IPS = new Set([31, 44, 49, 53, 59, 65, 81, 94, 101]);
const replayExact = (value, length = vmLength(abs(value))) => ({
  length,
  minimum: value,
  maximum: value,
});
const replayInterval = (minimum, maximum) => ({
  length: vmLength(abs(minimum) > abs(maximum) ? abs(minimum) : abs(maximum)),
  minimum,
  maximum,
});
const replayConcrete = (item) => replayExact(actualNumber(item), item.length);

const glvStates = vm.debug({ inputIndex: 0, ...data });
if (glvStates.at(-1).error !== undefined) throw new Error(glvStates.at(-1).error);
const addEntries = glvStates
  .map((state, index) => ({ state, index }))
  .filter(({ state }) => state.instructions.length === ADD_FUNCTION_LENGTH && state.ip === 0);
if (addEntries.length !== 58) {
  throw new Error(`all-index-1 input 0 must execute 58 generic-add slots, got ${addEntries.length}`);
}
// The first two calls include initialization special cases. The third is the
// first ordinary non-infinity add and supplies an exact concrete replay check.
const selectedAdd = addEntries[2];
const addEntry = selectedAdd.state;
const doubleInstructions = decodeAuthenticationInstructions(addEntry.functionTable['']);
if (doubleInstructions.length !== DOUBLE_FUNCTION_LENGTH) {
  throw new Error(`jacDouble instruction count changed: ${doubleInstructions.length}`);
}
const addReturn = glvStates.slice(selectedAdd.index + 1).find((state) =>
  state.instructions !== addEntry.instructions &&
  state.instructions.length !== DOUBLE_FUNCTION_LENGTH);
if (addReturn === undefined || addReturn.instructions.length !== 614 || addReturn.ip !== 261) {
  throw new Error('failed to locate the pinned ordinary-add return site');
}
const concreteAddCost = addReturn.metrics.operationCost - addEntry.metrics.operationCost;

const replayAddBranch = ({ abstract, equality = false, doubleOnly = false }) => {
  const stack = addEntry.stack.map(replayConcrete);
  if (abstract) {
    // jacAddAffine's five arguments are canonical X/Y/Z and affine X/Y limbs.
    for (let index = stack.length - 5; index < stack.length; index += 1) {
      stack[index] = replayInterval(0n, P - 1n);
    }
  }
  const alternate = addEntry.alternateStack.map(replayConcrete);
  let operationCost = 0;
  let forcedZeroMods = 0;
  const pop = () => {
    const item = stack.pop();
    if (item === undefined) throw new Error('branch replay stack underflow');
    return item;
  };
  const popMany = (count) => {
    const start = stack.length - count;
    if (start < 0) throw new Error('branch replay stack underflow');
    return stack.splice(start, count);
  };
  const push = (...items) => stack.push(...items);
  const chargePush = (...items) => {
    operationCost += items.reduce((sum, item) => sum + item.length, 0);
    push(...items);
  };
  const requireExact = (item) => {
    if (item.minimum !== item.maximum) throw new Error('branch control/depth item is not exact');
    return item.minimum;
  };

  const execute = (instructions) => {
    const controls = [];
    const active = () => controls.every(Boolean);
    for (let ip = 0; ip < instructions.length; ip += 1) {
      const instruction = instructions[ip];
      const opcode = instruction.opcode;
      operationCost += BASE_OPERATION_COST;

      if (opcode === 99) { // OP_IF
        const parentActive = active();
        if (!parentActive) {
          controls.push(false);
        } else {
          pop();
          if (instructions.length !== ADD_FUNCTION_LENGTH || ip !== 9) {
            throw new Error(`unexpected branch replay conditional at ${instructions.length}:${ip}`);
          }
          // Both compared paths add to a non-infinity Jacobian point.
          controls.push(true);
        }
        continue;
      }
      if (opcode === 103) { // OP_ELSE
        const current = controls.pop();
        if (current === undefined) throw new Error('branch replay conditional stack underflow');
        controls.push(controls.every(Boolean) && !current);
        continue;
      }
      if (opcode === 104) { // OP_ENDIF
        if (controls.pop() === undefined) throw new Error('branch replay conditional stack underflow');
        continue;
      }
      if (!active()) continue;

      if ((opcode >= 0 && opcode <= 78) || (opcode >= 81 && opcode <= 96)) {
        const value = opcode === 0
          ? 0n
          : opcode >= 81
            ? BigInt(opcode - 80)
            : actualNumber(instruction.data);
        chargePush(replayExact(value, instruction.data?.length ?? (opcode === 0 ? 0 : 1)));
      } else if (opcode === 107) { // OP_TOALTSTACK
        alternate.push(pop());
      } else if (opcode === 108) { // OP_FROMALTSTACK
        const item = alternate.pop();
        if (item === undefined) throw new Error('branch replay alternate-stack underflow');
        chargePush(item);
      } else if (opcode === 109) { // OP_2DROP
        popMany(2);
      } else if (opcode === 110) { // OP_2DUP
        const [a, b] = popMany(2);
        push(a, b);
        chargePush({ ...a }, { ...b });
      } else if (opcode === 113) { // OP_2ROT
        const [a, b, c, d, e, f] = popMany(6);
        push(c, d, e, f, a, b);
        operationCost += a.length + b.length;
      } else if (opcode === 117) { // OP_DROP
        pop();
      } else if (opcode === 118) { // OP_DUP
        const item = pop();
        push(item);
        chargePush({ ...item });
      } else if (opcode === 119) { // OP_NIP
        const [, b] = popMany(2);
        push(b);
      } else if (opcode === 120) { // OP_OVER
        const [a, b] = popMany(2);
        push(a, b);
        chargePush({ ...a });
      } else if (opcode === 121 || opcode === 122) { // OP_PICK / OP_ROLL
        const depth = Number(requireExact(pop()));
        const selectedIndex = stack.length - 1 - depth;
        const item = stack[selectedIndex];
        if (item === undefined) throw new Error(`invalid branch replay depth ${depth}`);
        if (opcode === 121) {
          chargePush({ ...item });
        } else {
          stack.splice(selectedIndex, 1);
          operationCost += item.length + depth;
          push(item);
        }
      } else if (opcode === 123) { // OP_ROT
        const [a, b, c] = popMany(3);
        push(b, c, a);
      } else if (opcode === 124) { // OP_SWAP
        const [a, b] = popMany(2);
        push(b, a);
      } else if (opcode === 125) { // OP_TUCK
        const [a, b] = popMany(2);
        operationCost += b.length;
        push({ ...b }, a, b);
      } else if (opcode === 135) { // OP_EQUAL
        const [a, b] = popMany(2);
        const equal = a.minimum === a.maximum && b.minimum === b.maximum && a.minimum === b.minimum;
        chargePush(replayExact(equal ? 1n : 0n, 1));
      } else if (opcode === 138) { // OP_INVOKE
        pop();
        execute(doubleInstructions);
      } else if (opcode === 147 || opcode === 148 || opcode === 149 || opcode === 151) {
        const [a, b] = popMany(2);
        let minimum;
        let maximum;
        if (!abstract && a.minimum === a.maximum && b.minimum === b.maximum) {
          const value = opcode === 147
            ? a.minimum + b.minimum
            : opcode === 148
              ? a.minimum - b.minimum
              : opcode === 149
                ? a.minimum * b.minimum
                : a.minimum % b.minimum;
          minimum = value;
          maximum = value;
        } else if (opcode === 147) {
          minimum = a.minimum + b.minimum;
          maximum = a.maximum + b.maximum;
        } else if (opcode === 148) {
          minimum = a.minimum - b.maximum;
          maximum = a.maximum - b.minimum;
        } else if (opcode === 149) {
          [minimum, maximum] = multiplyIntervals(a, b);
        } else {
          const modulusMaximum = abs(b.minimum) > abs(b.maximum) ? abs(b.minimum) : abs(b.maximum);
          if (a.minimum >= 0n && b.minimum > 0n) {
            minimum = 0n;
            maximum = modulusMaximum - 1n;
          } else if (a.maximum <= 0n && b.minimum > 0n) {
            minimum = -(modulusMaximum - 1n);
            maximum = 0n;
          } else {
            minimum = -(modulusMaximum - 1n);
            maximum = modulusMaximum - 1n;
          }
        }
        const forceEqualityZero = equality && instructions.length === ADD_FUNCTION_LENGTH &&
          opcode === 151 && EQUALITY_ZERO_MOD_IPS.has(ip);
        if (forceEqualityZero) forcedZeroMods += 1;
        const output = forceEqualityZero
          ? replayExact(0n)
          : replayInterval(minimum, maximum);
        if (opcode === 149 || opcode === 151) operationCost += a.length * b.length;
        operationCost += 2 * output.length;
        push(output);
      } else if (opcode >= 154 && opcode <= 162 && opcode !== 157) {
        const [a, b] = popMany(2);
        if (!abstract && a.minimum === a.maximum && b.minimum === b.maximum) {
          const value = opcode === 154
            ? a.minimum !== 0n && b.minimum !== 0n
            : opcode === 155
              ? a.minimum !== 0n || b.minimum !== 0n
              : opcode === 156
                ? a.minimum === b.minimum
                : opcode === 158
                  ? a.minimum !== b.minimum
                  : opcode === 159
                    ? a.minimum < b.minimum
                    : opcode === 160
                      ? a.minimum > b.minimum
                      : opcode === 161
                        ? a.minimum <= b.minimum
                        : a.minimum >= b.minimum;
          chargePush(replayExact(value ? 1n : 0n, 1));
        } else {
          chargePush(replayExact(1n, 1));
        }
      } else {
        throw new Error(`unsupported branch replay ${OpcodesBCH[opcode]} at ${instructions.length}:${ip}`);
      }
    }
    if (controls.length !== 0) throw new Error('unterminated branch replay conditional');
  };

  if (doubleOnly) {
    push(replayInterval(0n, P - 1n), replayInterval(0n, P - 1n), replayInterval(0n, P - 1n));
    execute(doubleInstructions);
  } else {
    execute(addEntry.instructions);
  }
  return {
    operationCost,
    forcedZeroMods,
    outputLengths: stack.slice(-3).map((item) => item.length),
  };
};

const concreteGenericAdd = replayAddBranch({ abstract: false });
if (concreteGenericAdd.operationCost !== concreteAddCost) {
  throw new Error(`GLV add static replay mismatch: ${concreteGenericAdd.operationCost} != ${concreteAddCost}`);
}
const abstractGenericAdd = replayAddBranch({ abstract: true });
const abstractEqualityAdd = replayAddBranch({ abstract: true, equality: true });
const abstractDouble = replayAddBranch({ abstract: true, doubleOnly: true });
if (abstractEqualityAdd.forcedZeroMods !== EQUALITY_ZERO_MOD_IPS.size) {
  throw new Error(`equal-point replay forced ${abstractEqualityAdd.forcedZeroMods} zero residues`);
}
if (JSON.stringify(abstractEqualityAdd.outputLengths) !== JSON.stringify([0, 0, 0]) ||
  JSON.stringify(abstractDouble.outputLengths) !== JSON.stringify([32, 32, 32])) {
  throw new Error('equal-point sentinel or jacDouble output widths changed');
}

const callerBodyNames = addReturn.instructions.slice(261, 295)
  .map((instruction) => OpcodesBCH[instruction.opcode]);
const expectedCallerBodyNames = [
  'OP_OVER', 'OP_0', 'OP_NUMEQUAL', 'OP_IF',
  'OP_10', 'OP_PICK', 'OP_12', 'OP_PICK', 'OP_14', 'OP_PICK', 'OP_0', 'OP_INVOKE',
  'OP_3', 'OP_ROLL', 'OP_DROP', 'OP_SWAP', 'OP_TOALTSTACK', 'OP_SWAP', 'OP_FROMALTSTACK',
  'OP_3', 'OP_ROLL', 'OP_DROP', 'OP_SWAP', 'OP_TOALTSTACK', 'OP_SWAP', 'OP_FROMALTSTACK',
  'OP_3', 'OP_ROLL', 'OP_DROP', 'OP_SWAP', 'OP_TOALTSTACK', 'OP_SWAP', 'OP_FROMALTSTACK',
  'OP_ENDIF',
];
if (JSON.stringify(callerBodyNames) !== JSON.stringify(expectedCallerBodyNames)) {
  throw new Error(`equal-point caller body changed: ${JSON.stringify(callerBodyNames)}`);
}
// Only variable costs are additional here: inactive branch opcodes already pay
// their 100-unit base costs on the generic trace. Three depth pushes plus PICKs
// copy the canonical inputs; INVOKE returns three canonical limbs; each rewrite
// pushes depth 3, rolls a zero-byte sentinel, and copies one 32-byte result.
const callerPickCost = 3 * (1 + 32);
const callerInvokeReturnCost = abstractDouble.outputLengths.reduce((sum, length) => sum + length, 0);
const callerRewriteCost = abstractEqualityAdd.outputLengths.reduce(
  (sum, sentinelLength, index) => sum + 1 + 3 + sentinelLength + abstractDouble.outputLengths[index],
  0,
);
const equalPointCallerVariableCost = callerPickCost + callerInvokeReturnCost + callerRewriteCost;
const equalPointSurcharge = abstractEqualityAdd.operationCost + abstractDouble.operationCost +
  equalPointCallerVariableCost - abstractGenericAdd.operationCost;

export const GLV_GENERIC_INTRINSIC = [5_845_761, 7_033_265];
export const GLV_EQUAL_POINT_SURCHARGE = 12_099;
if (JSON.stringify(intrinsicCeilings) !== JSON.stringify(GLV_GENERIC_INTRINSIC)) {
  throw new Error(`GLV generic intrinsic ceilings changed: ${JSON.stringify(intrinsicCeilings)}`);
}
if (equalPointCallerVariableCost !== 303 || equalPointSurcharge !== GLV_EQUAL_POINT_SURCHARGE) {
  throw new Error(`GLV equal-point accounting changed: caller=${equalPointCallerVariableCost}, ` +
    `surcharge=${equalPointSurcharge}`);
}
console.log(`GLV equal-point replay: concrete=${concreteGenericAdd.operationCost} ` +
  `generic=${abstractGenericAdd.operationCost} equality=${abstractEqualityAdd.operationCost} ` +
  `double=${abstractDouble.operationCost} caller=${equalPointCallerVariableCost} ` +
  `surcharge=${equalPointSurcharge}`);

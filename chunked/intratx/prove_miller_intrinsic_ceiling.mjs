// Trace-driven abstract resource ceiling for the BN254 Miller inputs.
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
// products. Both forms of every normalization are charged.

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  OpcodesBCH,
  createVirtualMachineBch2026,
  decodeAuthenticationInstructions,
  encodeAuthenticationInstructions,
  hexToBin,
  vmNumberToBigInt,
} from '@bitauth/libauth';

const verifierDir = process.env.VERIFIER_DIR;
if (verifierDir === undefined) {
  throw new Error('VERIFIER_DIR must point to the matching zk-verifier-bench checkout');
}

const vectorPath = join(verifierDir, 'src/bch/groth16-intratx-residue-vectors.json');
const vectors = JSON.parse(readFileSync(vectorPath, 'utf8'));
const steps = vectors.worstCaseProof;
if (!Array.isArray(steps)) throw new Error('missing worstCaseProof resource fixture');
const inputs = steps.map((step) => ({
  locking: hexToBin(step.locking),
  unlocking: hexToBin(step.unlocking),
}));
const vm = createVirtualMachineBch2026(true);
const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const R = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
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

const unlockingByteTags = inputs.map((input, inputIndex) => {
  const instructions = decodeAuthenticationInstructions(input.unlocking);
  const output = new Uint8Array(input.unlocking.length);
  let offset = 0;
  instructions.forEach((instruction, instructionIndex) => {
    const encoded = encodeAuthenticationInstructions([instruction]);
    const data = instruction.data;
    if (data !== undefined) {
      const dataOffset = offset + encoded.length - data.length;
      const isFieldData = inputIndex >= 2 && (
        instructionIndex === 0 ||
        instructionIndex < instructions.length - 2 && data.length <= 32
      );
      output.fill(isFieldData ? BYTE_FIELD : BYTE_UNKNOWN, dataOffset, dataOffset + data.length);
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
    const isPadding = stackIndex === stack.length - 1;
    const isField = !isPadding && inputIndex >= 2 &&
      (stackIndex === 0 || instruction.data.length <= 32);
    if (stackIndex === 0) {
      return { length: item.length, byteTags: bytesTagged(item.length, BYTE_FIELD) };
    }
    if (isField) {
      return {
        length: item.length,
        byteTags: bytesTagged(item.length, BYTE_FIELD),
        minimum: 0n,
        maximum: (P > R ? P : R) - 1n,
      };
    }
    return concreteItem(item, bytesTagged(item.length, BYTE_UNKNOWN));
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
  const conditionalCounts = { canonical: 0, seam: 0 };
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
      const nextOpcode = state.instructions[state.ip + 1]?.opcode;
      const canonical = state.instructions.length === 13 && state.ip === 7;
      const previousName = OpcodesBCH[state.instructions[state.ip - 1]?.opcode];
      const seam = inputIndex >= 2 && state.instructions.length > 1000 &&
        state.ip >= state.instructions.length - 300 && previousName === 'OP_LESSTHAN';
      const preambleName = OpcodesBCH[state.instructions[state.ip - 3]?.opcode];
      const firstSeam = seam && (preambleName === 'OP_SWAP' || preambleName === 'OP_OVER');
      const classes = Number(canonical) + Number(seam);
      if (classes !== 1) {
        throw new Error(`unclassified OP_IF at input ${inputIndex}, trace ${index}, ` +
          `instructions ${state.instructions.length}, ip ${state.ip}`);
      }
      const className = canonical ? 'canonical' : 'seam';
      conditionalCounts[className] += 1;
      const context = { canonical, seam, firstSeam };
      if (process.env.DUMP_IF === '1') {
        console.log(`if input=${inputIndex} trace=${index} class=${className} taken=${next.controlStack.at(-1) === true}`);
      }
      abstractConditionals.push(context);
      const taken = next.controlStack.at(-1) === true;
      if (!taken && (canonical || seam)) {
        // The base instruction cost of inactive branch instructions is already
        // charged by BCH. Add only the stack/arithmetic work of the more costly
        // normalization branch. Both forms implement x<0 ? x+p : x.
        if (firstSeam) {
          // The first seam correction also rewrites the deepest pending output.
          // Input 2's first form is already taken by the hard trace. Later
          // inputs add exactly 197 variable operation-cost units when absent.
          addAdjustment(opcode, preambleName === 'OP_OVER' ? 256 : 197);
        } else {
          addAdjustment(opcode, nextOpcode === 110 ? 128 : 97);
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
        if (context.canonical || context.seam) {
          const normalized = pop();
          push({
            ...normalized,
            length: 32,
            minimum: 0n,
            maximum: P - 1n,
            byteTags: bytesTagged(32, BYTE_FIELD),
          });
        }
      }
    } else if (opcode === 105) { // OP_VERIFY
      pop();
    } else if (opcode === 168 || opcode === 170) { // OP_SHA256 / OP_HASH256
      pop(); push({ length: 32, byteTags: bytesTagged(32, BYTE_UNKNOWN) });
    } else if (opcode === 192) { // OP_INPUTINDEX
      push(numericItem(BigInt(inputIndex)));
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
  const expectedSeams = inputIndex >= 2 && inputIndex <= 9 ? 12 : 0;
  if (conditionalCounts.seam !== expectedSeams ||
    conditionalCounts.canonical === 0) {
    throw new Error(`unexpected conditional inventory at input ${inputIndex}: ${JSON.stringify(conditionalCounts)}`);
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
  };
};

export const MILLER_INTRINSIC_CEILINGS = [
  7_444_595, 7_451_929, 7_498_476, 7_497_296, 7_497_289,
  7_279_182, 7_314_412, 7_447_419, 7_055_553,
];
const dependencyCost = (inputIndex) => {
  if (inputIndex === 2) return inputs[2].unlocking.length + 2 * inputs[3].unlocking.length;
  if (inputIndex < inputs.length - 1) {
    return 2 * inputs[2].unlocking.length + inputs[inputIndex].unlocking.length +
      2 * inputs[inputIndex + 1].unlocking.length;
  }
  return 2 * inputs[2].unlocking.length + inputs[inputIndex].unlocking.length;
};

const intrinsicCeilings = [];
for (let inputIndex = 2; inputIndex < inputs.length; inputIndex += 1) {
  const result = traceCeiling(inputIndex);
  const intrinsic = result.ceiling - dependencyCost(inputIndex);
  intrinsicCeilings.push(intrinsic);
  console.log(`input${inputIndex}: actual=${result.finalCost} adjustment=${result.adjustment} ` +
    `total-ceiling=${result.ceiling} intrinsic-ceiling=${intrinsic}`);
  console.log(`  branches=${JSON.stringify(result.conditionalCounts)} ${result.adjustmentByOpcode.join(' ')}`);
  if (process.env.SHAPES === '1') console.log(`  ${result.arithmeticShapes.join('\n  ')}`);
}
if (JSON.stringify(intrinsicCeilings) !== JSON.stringify(MILLER_INTRINSIC_CEILINGS)) {
  throw new Error(`Miller intrinsic ceilings changed: ${JSON.stringify(intrinsicCeilings)}`);
}
console.log(`proved Miller intrinsic ceilings=${JSON.stringify(intrinsicCeilings)}`);

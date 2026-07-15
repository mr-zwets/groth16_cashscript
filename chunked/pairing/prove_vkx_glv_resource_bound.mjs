// Prove a proof-independent bound on the expensive equal-point branch in the
// frozen BN254 3x43 GLV schedule.
//
// Each fixed lookup point has a known discrete logarithm because IC1 and IC2
// are recorded as multiples of the G1 base in pairing-vectors.json. Therefore
// an equal-point addition is an equality of scalars modulo the prime G1 order.
// The meet-in-the-middle checks below reject a necessary 64-bit condition for:
//
//   * the first equal-point event in physical lookup slots 0 through 11; and
//   * two equal-point events separated by 1 through 12 physical lookup slots.
//
// Hence the first event is at slot 12 or later and subsequent events are at
// least 13 slots apart. The two generated GLV inputs cover physical slots
// 0..62 and 63..128, respectively, so their componentwise-maximal event-count
// allocations are (4,5) and (3,6), with at most 9 events in total.
//
// This exhaustive check is intentionally slow and memory-intensive at the
// largest cases. Run it from the repository root with VERIFIER_DIR pointing to
// the matching zk-verifier-bench checkout.

import { bn254, vec } from './_millermath.mjs';
import {
  GLV_LAMBDA,
  GLV_R,
  GLV_SPLIT_TABLE_HEX,
  VKXGLV_SPLIT_GROUPS,
  VKXGLV_SPLIT_ITERS,
} from './gen_vkx_glv.mjs';
import { GLV_GROUPED_BOUNDS } from '../regen_vkx_windows.mjs';

const TABLE_MASKS = 16;
const TABLE_ENTRY_BYTES = 64;
const FIRST_FORBIDDEN_SLOT = 11;
const MAX_FORBIDDEN_GAP = 12;
const MASK64 = (1n << 64n) - 1n;
const assert = (condition, message) => { if (!condition) throw new Error(message); };

assert(VKXGLV_SPLIT_GROUPS === 3, 'resource proof requires the frozen three-group schedule');
assert(VKXGLV_SPLIT_ITERS === 43, 'resource proof requires the frozen 43-iteration schedule');
assert(GLV_GROUPED_BOUNDS.length === 3 && GLV_GROUPED_BOUNDS[0] === 0 &&
  GLV_GROUPED_BOUNDS[1] === 21 && GLV_GROUPED_BOUNDS[2] === VKXGLV_SPLIT_ITERS,
'resource proof requires GLV input windows [0,21) and [21,43)');

const order = BigInt(vec.r);
const lambda = GLV_LAMBDA;
assert(order === GLV_R, 'pairing vectors and GLV generator disagree on the G1 order');
assert(order === bn254.G1.Point.Fn.ORDER, 'noble and the GLV generator disagree on the G1 order');
assert((order & 1n) === 1n, 'the G1 order must be odd');
assert(lambda !== 1n && lambda ** 3n % order === 1n, 'invalid GLV eigenvalue');

const ic1 = BigInt(vec.scalars.ic[1]);
const ic2 = BigInt(vec.scalars.ic[2]);
const laneScalars = [ic1, ic1 * lambda % order, ic2, ic2 * lambda % order];

const addMod = (left, right) => {
  const sum = left + right;
  return sum >= order ? sum - order : sum;
};
const double = (value, count) => {
  let result = value;
  for (let index = 0; index < count; index += 1) result = addMod(result, result);
  return result;
};
const table = Array.from({ length: VKXGLV_SPLIT_GROUPS }, (_, group) => {
  const shift = VKXGLV_SPLIT_ITERS * group;
  return Array.from({ length: TABLE_MASKS }, (_, mask) => {
    let scalar = 0n;
    laneScalars.forEach((laneScalar, lane) => {
      if (mask & (1 << lane)) scalar = addMod(scalar, laneScalar);
    });
    return scalar * (1n << BigInt(shift)) % order;
  });
});

const fromLe = (bytes) => {
  let value = 0n;
  for (let index = bytes.length - 1; index >= 0; index -= 1) {
    value = value << 8n | BigInt(bytes[index]);
  }
  return value;
};

// Bind the scalar model to every affine point serialized in the generated
// contracts. All table points are finite, in G1, and have nonzero Y. Starting
// from infinity, the accumulator therefore remains in the same odd-prime-order
// group. For the raw mixed-add formula, ay=0 has three possible geometric
// interpretations: equal points, inverse points, or a finite result with Y=0.
// Inverse points instead produce ay=-r^3 != 0, and a finite Y=0 point would be
// nontrivial 2-torsion, which this group does not have. Thus ay=0 selects exactly
// the equal-point case on every reachable state.
const serializedTable = Buffer.from(GLV_SPLIT_TABLE_HEX.slice(2), 'hex');
assert(serializedTable.length ===
  VKXGLV_SPLIT_GROUPS * (TABLE_MASKS - 1) * TABLE_ENTRY_BYTES,
'serialized GLV table length mismatch');
for (let group = 0; group < VKXGLV_SPLIT_GROUPS; group += 1) {
  for (let mask = 1; mask < TABLE_MASKS; mask += 1) {
    const offset = (group * (TABLE_MASKS - 1) + mask - 1) * TABLE_ENTRY_BYTES;
    const x = fromLe(serializedTable.subarray(offset, offset + 32));
    const y = fromLe(serializedTable.subarray(offset + 32, offset + 64));
    assert(y !== 0n, `table point ${group}:${mask} has zero Y`);
    const encoded = bn254.G1.Point.fromAffine({ x, y });
    const expected = bn254.G1.Point.BASE.multiplyUnsafe(table[group][mask]);
    assert(encoded.equals(expected), `scalar/table mismatch at ${group}:${mask}`);
  }
}

const product = (options) => options.reduce((count, values) => count * values.length, 1);
const enumerateLow64 = (options, complement = false, initial = 0n) => {
  const output = new BigUint64Array(product(options));
  let write = 0;
  const walk = (depth, sum) => {
    if (depth === options.length) {
      const value = complement && sum !== 0n ? order - sum : sum;
      output[write] = value & MASK64;
      write += 1;
      return;
    }
    for (const option of options[depth]) walk(depth + 1, addMod(sum, option));
  };
  walk(0, initial);
  assert(write === output.length, 'meet-in-the-middle enumeration length mismatch');
  output.sort();
  return output;
};
const intersection = (left, right) => {
  let leftIndex = 0;
  let rightIndex = 0;
  while (leftIndex < left.length && rightIndex < right.length) {
    if (left[leftIndex] === right[rightIndex]) return left[leftIndex];
    if (left[leftIndex] < right[rightIndex]) leftIndex += 1;
    else rightIndex += 1;
  }
  return null;
};
const bestSplit = (options, minimum = 0, maximum = options.length) => {
  let split = minimum;
  let work = Infinity;
  for (let candidate = minimum; candidate <= maximum; candidate += 1) {
    const candidateWork = product(options.slice(0, candidate)) + product(options.slice(candidate));
    if (candidateWork < work) {
      split = candidate;
      work = candidateWork;
    }
  }
  return split;
};

// Equality at `slot` requires the weighted sum of all earlier optional table
// digits to equal the nonzero table digit selected at `slot`.
const initialOptions = (slot) => {
  const options = [];
  for (let earlier = 0; earlier < slot; earlier += 1) {
    let futureDoubles = 0;
    for (let position = earlier + 1; position <= slot; position += 1) {
      if (position % VKXGLV_SPLIT_GROUPS === 0) futureDoubles += 1;
    }
    options.push(table[earlier % VKXGLV_SPLIT_GROUPS]
      .map((value) => double(value, futureDoubles)));
  }
  options.push(table[slot % VKXGLV_SPLIT_GROUPS].slice(1)
    .map((value) => order - value));
  return options;
};

console.log(`checking first equal-point event through physical slot ${FIRST_FORBIDDEN_SLOT}`);
for (let slot = 0; slot <= FIRST_FORBIDDEN_SLOT; slot += 1) {
  const options = initialOptions(slot);
  const split = bestSplit(options);
  const left = enumerateLow64(options.slice(0, split));
  const right = enumerateLow64(options.slice(split), true);
  const collision = intersection(left, right);
  console.log(`  slot=${slot} states=${left.length}+${right.length} low64-intersection=${collision !== null}`);
  assert(collision === null,
    `necessary-condition collision at initial slot ${slot}; exact refinement is required`);
}

// Immediately after equality at start slot s, the branch replaces the raw
// result with 2*T_s. The intervening optional digits and scheduled group-zero
// doublings below reconstruct the accumulator immediately before slot s+gap;
// equality requires that accumulator to equal the nonzero endpoint digit.
const recurrenceOptions = (startType, gap) => {
  const endType = (startType + gap) % VKXGLV_SPLIT_GROUPS;
  let totalDoubles = 0;
  for (let relative = 1; relative <= gap; relative += 1) {
    if ((startType + relative) % VKXGLV_SPLIT_GROUPS === 0) totalDoubles += 1;
  }
  const options = [table[startType].slice(1)
    .map((value) => double(value, totalDoubles + 1))];
  for (let relative = 1; relative < gap; relative += 1) {
    const type = (startType + relative) % VKXGLV_SPLIT_GROUPS;
    let futureDoubles = 0;
    for (let later = relative + 1; later <= gap; later += 1) {
      if ((startType + later) % VKXGLV_SPLIT_GROUPS === 0) futureDoubles += 1;
    }
    options.push(table[type].map((value) => double(value, futureDoubles)));
  }
  options.push(table[endType].slice(1).map((value) => order - value));
  return options;
};

console.log(`checking equal-point recurrence gaps 1 through ${MAX_FORBIDDEN_GAP}`);
for (let gap = 1; gap <= MAX_FORBIDDEN_GAP; gap += 1) {
  for (let startType = 0; startType < VKXGLV_SPLIT_GROUPS; startType += 1) {
    const options = recurrenceOptions(startType, gap);
    const split = bestSplit(options, 1, options.length - 1);
    const left = enumerateLow64(options.slice(0, split));
    const rightOptions = options.slice(split);
    const rightStates = product(rightOptions);
    let collision = null;
    if (rightStates <= 20_000_000) {
      collision = intersection(left, enumerateLow64(rightOptions, true));
    } else {
      // Bound peak memory for gap 12 by partitioning the 251M-state side.
      for (const first of rightOptions[0]) {
        const block = enumerateLow64(rightOptions.slice(1), true, first);
        collision = intersection(left, block);
        if (collision !== null) break;
      }
    }
    console.log(
      `  gap=${gap} start-type=${startType} states=${left.length}+${rightStates} ` +
      `low64-intersection=${collision !== null}`,
    );
    assert(collision === null,
      `necessary-condition collision at gap ${gap}, start type ${startType}; exact refinement is required`);
  }
}

const firstEventSlot = FIRST_FORBIDDEN_SLOT + 1;
const minimumSeparation = MAX_FORBIDDEN_GAP + 1;
const firstInputLastSlot = GLV_GROUPED_BOUNDS[1] * VKXGLV_SPLIT_GROUPS - 1;
const finalSlot = VKXGLV_SPLIT_ITERS * VKXGLV_SPLIT_GROUPS - 1;
const maxEvents = (first, last) => Math.floor((last - first) / minimumSeparation) + 1;
const firstInputEvents = maxEvents(firstEventSlot, firstInputLastSlot);
const secondInputEvents = maxEvents(firstInputLastSlot + 1, finalSlot);
const totalEvents = maxEvents(firstEventSlot, finalSlot);
const maximalAllocations = [
  [firstInputEvents, totalEvents - firstInputEvents],
  [totalEvents - secondInputEvents, secondInputEvents],
];

assert(firstEventSlot === 12 && minimumSeparation === 13, 'unexpected event-spacing result');
assert(firstInputLastSlot === 62 && finalSlot === 128, 'unexpected physical GLV slot ranges');
assert(firstInputEvents === 4 && secondInputEvents === 6 && totalEvents === 9,
  'unexpected equal-point event-count bound');
assert(JSON.stringify(maximalAllocations) === JSON.stringify([[4, 5], [3, 6]]),
  'unexpected componentwise-maximal allocation set');

console.log(`proved first-event-slot>=${firstEventSlot}`);
console.log(`proved minimum-slot-separation=${minimumSeparation}`);
console.log(`proved event bounds: input0<=${firstInputEvents}, input1<=${secondInputEvents}, total<=${totalEvents}`);
console.log(`componentwise-maximal allocations=${JSON.stringify(maximalAllocations)}`);

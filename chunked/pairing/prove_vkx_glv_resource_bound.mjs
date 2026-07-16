// Prove a key-agnostic bound on the expensive grouped-GLV fallback branch.
//
// Each loop iteration has exactly one optional affine-table addition for each
// of the three public table groups. Each addition can execute its fallback at
// most once, so charging every physical lookup slot is a universal ceiling. It
// does not require a discrete logarithm or any relation between IC1 and IC2.
//
// The two generated inputs cover iteration windows [0,21) and [21,43). Their
// fallback ceilings are therefore 21*3=63 and 22*3=66. The table contents,
// public inputs, and proof can only reduce those counts by selecting zero digits
// or taking the generic addition path.

import {
  GLV_SPLIT_TABLE_HEX,
  VKXGLV_SPLIT_GROUPS,
  VKXGLV_SPLIT_ITERS,
} from './gen_vkx_glv.mjs';
import { GLV_GROUPED_BOUNDS } from '../regen_vkx_windows.mjs';

const TABLE_MASKS = 16;
const TABLE_ENTRY_BYTES = 64;
const assert = (condition, message) => { if (!condition) throw new Error(message); };

assert(VKXGLV_SPLIT_GROUPS === 3, 'resource proof requires the frozen three-group schedule');
assert(VKXGLV_SPLIT_ITERS === 43, 'resource proof requires the frozen 43-iteration schedule');
assert(GLV_GROUPED_BOUNDS.length === 3 && GLV_GROUPED_BOUNDS[0] === 0 &&
  GLV_GROUPED_BOUNDS[1] === 21 && GLV_GROUPED_BOUNDS[2] === VKXGLV_SPLIT_ITERS,
'resource proof requires GLV input windows [0,21) and [21,43)');

const serializedTable = Buffer.from(GLV_SPLIT_TABLE_HEX.slice(2), 'hex');
assert(serializedTable.length ===
  VKXGLV_SPLIT_GROUPS * (TABLE_MASKS - 1) * TABLE_ENTRY_BYTES,
'serialized GLV table length mismatch');

export const GLV_FALLBACK_EVENT_CEILINGS = GLV_GROUPED_BOUNDS
  .slice(0, -1)
  .map((lo, inputIndex) =>
    (GLV_GROUPED_BOUNDS[inputIndex + 1] - lo) * VKXGLV_SPLIT_GROUPS);

assert(JSON.stringify(GLV_FALLBACK_EVENT_CEILINGS) === JSON.stringify([63, 66]),
  'unexpected key-agnostic grouped-GLV fallback ceilings');

console.log(
  `proved key-agnostic grouped-GLV fallback ceilings=${JSON.stringify(GLV_FALLBACK_EVENT_CEILINGS)}`,
);

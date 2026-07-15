// Hash-free BLS12-381 residue plan owned by the intra-transaction and grouped deployments.
// Covenant chunks keep their separately measured plan in generated/: these wider windows only
// fit after transform.mjs removes the per-input boundary hashes.
export const LINKED_RESIDUE_NAMESPACE = 'linked-residue';

export const LINKED_MILLER_BOUNDS = [
  0, 9, 19, 29, 38, 48, 57, 67, 76, 86, 96, 105, 115, 124, 134,
  143, 153, 162, 172, 181, 191, 200, 209, 219, 228, 238, 248, 258, 268, 277,
];

// The fixed-VK quotient construction has 207 operations. Its terminal quotient check fits with
// the preceding one-operation window after intra-transaction transformation, removing a whole
// input while keeping every transformed redeem and unlocking bytecode within standard limits.
export const LINKED_COLLAPSED_TORUS_MILLER_BOUNDS = [
  0, 19, 40, 60, 81, 102, 123, 144, 165, 186, 207,
];

export const LINKED_TAIL_BOUNDS = [0, 13, 28, 43, 57, 63];

// Highest standard-VM step cost in the deterministic 32-proof all-position audit for this plan.
// The builders derive the proof from these public inputs under the same fixed VK.
export const LINKED_HIGH_COST_INPUTS = [
  10887496253429993968285161559712180133151077831125426114576620198630367604819n,
  3290835902070091705768749685404810268243841867406982392037402666820255673610n,
];

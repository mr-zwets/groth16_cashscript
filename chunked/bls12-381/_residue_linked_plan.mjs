// Hash-free BLS12-381 residue plan owned by the intra-transaction and grouped deployments.
// Covenant chunks keep their separately measured plan in generated/: these wider windows only
// fit after transform.mjs removes the per-input boundary hashes.
export const LINKED_RESIDUE_NAMESPACE = 'linked-residue';

export const LINKED_MILLER_BOUNDS = [
  0, 9, 19, 29, 38, 48, 57, 67, 76, 86, 96, 105, 115, 124, 134,
  143, 153, 162, 172, 181, 191, 200, 209, 219, 228, 238, 248, 258, 268, 277,
];

// The quotient-torus terminal removes the separate tail and makes wider Miller windows fit the
// linked input layout. These boundaries are validated after transform.mjs removes covenant hashes;
// the path-specific GLV bounds also pass the linked builder's dense exact-locking fixture.
export const LINKED_TORUS_GLV_BOUNDS = [0, 23, 50, 77, 104, 128];
export const LINKED_TORUS_MILLER_BOUNDS = [
  0, 13, 26, 41, 56, 70, 85, 100, 115, 130, 145, 160, 175, 190, 205,
  219, 233, 248, 263, 277,
];

// Grouped transactions have a different fit envelope than the single-transaction path. Keep this
// schedule separate so each deployment can be reproduced without changing the other's vector.
export const GROUPED_TORUS_GLV_BOUNDS = [0, 23, 50, 77, 104, 128];
export const GROUPED_TORUS_MILLER_BOUNDS = [
  0, 13, 26, 39, 52, 65, 78, 91, 104, 117, 130, 143, 156, 169, 182, 196,
  210, 224, 238, 251, 265, 277,
];

export const LINKED_TAIL_BOUNDS = [0, 13, 28, 43, 57, 63];

// Highest standard-VM step cost in the deterministic 32-proof all-position audit for this plan.
// The builders derive the proof from these public inputs under the same fixed VK.
export const LINKED_HIGH_COST_INPUTS = [
  10887496253429993968285161559712180133151077831125426114576620198630367604819n,
  3290835902070091705768749685404810268243841867406982392037402666820255673610n,
];

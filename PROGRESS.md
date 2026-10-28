# PROGRESS (wip/pq-hash-verifier) -- work note, must never land on main

Verifier phase of the pq-hash track. Sources: research/pq-hash/verifier/ (this repo, groth16_cashscript).
Harness glue + report: zk-verifier-bench worktree work/pq-hash/verifier-bench, research/pq-hash/ (branch wip/pq-hash-verifier).
Inputs: SPEC (wip/pq-hash-design c3497a1), prover vectors (wip/pq-hash-prover f8d8a3f, research/pq-hash/prover/vectors),
kernels (wip/pq-hash-kernels 1abcccb).

Plan
1. layout (b): one P2SH32 input, code = redeem with OP_DEFINE functions; phases: transcript+AIR (1), Merkle (2), FRI queries (3).
   Merkle: sorted-order LIFO multiproof with hinted processing order (sigma, permutation by sum of 2^sigma) and hinted
   op stream (fresh runs / merge / dup / park / root); heap index k tracked so every merge is position-checked.
2. layout (a): multi-input standard (code from sibling inputs, pruned caps, TOP blobs), P128 two-tx NFT thread.
3. measure: libauth BCH_2026 loosened, bch-spec, TXv5-as-written (base 41) incl. pad, BCHN-adjusted op-cost.

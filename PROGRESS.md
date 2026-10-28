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

Status 1 (layout b done)
- gen.mjs compact generator: shared OP_DEFINE functions; redeem 5.9 KB (P128), 5.6-6.4 KB others.
- grade-b.mjs -> research/pq-hash/verifier/results/layout-b.json; test-b.mjs -> results/test-b.log (14 valid accepted,
  all prover tamper cases + 15 on-chain witness manipulations rejected, per set).
- P128: all 4 vectors fit one TXv5 input in a standard (<=100,000 B) tx: 96.5-99.96 KB, op 71.5-72.0M std,
  90-93% of TXv5-as-written budget (base 41), 82-84% of bch-spec; no pad needed. P100: 56-57.5 KB, 38.6M, 85%.
  U100 does not fit (unlocking > 100,000 B consensus cap). C100/C128 fit easily.
- careful: `git checkout <file>` reverts all uncommitted edits in that file (lost and reapplied once).
Next: layout (a) (standard rules, multi-input; P128 two tx with NFT thread).

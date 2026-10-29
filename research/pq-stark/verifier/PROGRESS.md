# PROGRESS (wip/pq-stark-verifier; this file stays off main)

## Done
- Branch from wip/pq-stark-field, merged wip/pq-stark-prover (vectors, verify.mjs, FORMAT.md). verify.mjs: one added
  export (`separators`), nothing else changed.
- model.mjs: the on-chain algorithm in JS; test-model 1159/1159 verdicts equal to verify.mjs, transcript inputs equal
  to Plonky3's recording.
- gen.mjs (layout b) and gen-a.mjs (layout a); air.mjs (per-AIR constraint descriptions).
- Layout (b): all 45 valid vectors accepted (TXv5 std+cons and bch-spec where the unlocking fits 100,000 B; loose VM
  otherwise); test-b 2302 cases (45 valid, 1114 tampered, 1143 witness manipulations), 0 unexpected.
- Layout (a): grade-a over all vectors; test-a on representative vectors.
- Security per set: zk-verifier-bench wip/pq-stark-verifier research/pq-stark/verifier/security.py (Soundness
  phase calculator, exact FriParameters per vector).

## Resume notes
- Runs are single-threaded node; keep them under `nice`. grade-a over all vectors takes ~10 min, test-b --wit over
  all vectors ~15 min. No Rust prover runs are needed in this phase.
- Results files merge by vector, so partial re-runs are safe.

## Open
- Folds are ~57% of the per-query op-cost at arity 16; Merkle ~25-40% of the total. Not optimized further.
- ZK mimc code needs 2-3 code blobs in layout (a).

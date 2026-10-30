# Track 8 (stark-usable) progress — wip/stark-usable only, never main

Design: bench `research/pq-stark/DESIGN-T8.md` (branch wip/stark-usable-design). Stages append below.

## S1 — Batch prover crate (done, 2026-10-30)

- **Crate:** `research/pq-stark-batch/prover`
  - Built on p3-batch-stark at the pin 0d80373: SHA-256 / Goldilocks / cubic trinomial.
  - `cap_height`, OOD PoW and lookup PoW are parameters.
  - Track 5 files are untouched.
- **Outputs:**
  - the p3b-v1 wire format with its FORMAT.md;
  - the shape derived from the VK (`src/shape.rs`);
  - the constraint-DAG JSON per table (`dag` in each vector);
  - transcript hash-input logs (`transcript_hash_inputs`).
- **Acceptance met.** `verify_batch` accepts the decoded p3b-v1 bytes for single_instance,
  three_instances_mixed_sizes, mixed_preprocessed, both_lookups_zk and periodic_air_zk, under each of these
  sets:
  - P3: Plonky3's own FRI shapes and ZK settings, at Plonky3's heights;
  - Z128: ZK, at heights raised to the strict FRI rule;
  - Z128 without ZK;
  - Z128 with cap 5;
  - Z128g.

  Plus 3 vectors at n = 2^10 with an arity-8 fold.
- **Checks:**
  - 28 vectors; `check` ran 1,538 cases with 0 unexpected;
  - tamper sweeps (per-section byte flips, non-canonical, truncate, extend, public value + 1) with 0 accepts;
  - decode(encode) is identical to Plonky3's serde tree;
  - the DAG row self-check passes.
- **Regenerate:** `CARGO_TARGET_DIR=<cache>/target ./gen-vectors.sh` (nice, 4 threads, about 1 minute).
- **Findings for S0, S2, S3 and S5** (details in the prover README):
  1. Under ZK the preprocessed commitment is salted, so it is not recomputable from the AIR. DESIGN §4 needs
     a correction.
  2. batch-stark does not bind periodic columns in its transcript. They must stay VK constants.
  3. Under Z128 without ZK the floor is n ≥ 2^9; with ZK it is 2^8.
  4. Lookup PoW bits are not fixed by the design; they are 0 for now.
  5. Multi-instance ZK proofs are not byte-reproducible from the seed. The stored vectors are the
     reference.
- **Next stage inputs:**
  - S3 reads `vectors/*/*.json`: `proof_hex`, `shape`, `dag`, `public_values`, `preprocessed_commitment`,
    `transcript_hash_inputs`, `tampered`.
  - S2 adds its AIRs as new `TestAir` variants or a sibling module, reusing `shape`, `wire` and `dag`.

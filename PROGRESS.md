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
# Track 8 progress (wip/stark-usable only; never merge to main)

## S0 - Specification and calculators (done, 2026-10-30)

Bench branch `wip/stark-usable-design`, commit b4cd81e, folder `research/pq-stark/design-t8/`:
- `AIR-SPEC.md`: the single source for the Rust (S2) and JS (S3) AIRs. Emission order is normative (alpha is folded by Horner).
  - M1: 17 columns, 11 periodic columns, 53 constraints, degree 4, 8 ZK chunks, t = 94.
  - M2: T_hash (2^10, 24 main + 1 preprocessed, 44 constraints, degree 4) and T_ctl (2^7, 13 main + 5 preprocessed, 35 constraints, degree 2). One global bus `P2`, W = 13. Batch order: T_hash, then T_ctl.
- `air8_ref.py`: a Python reference that checks the spec. All checks pass: Poseidon2 test vector, honest traces, native NF/ROOT, 100% single-cell mutation detection, degrees.
- `poseidon2-gl8-constants.json`: constants extracted from the pin.
- `bytes8.py`: the byte model. It reproduces Track 5 S128 at 78,569 vs 78,393 B (+0.23%) and S128z at 113,533 vs 112,501 B (+0.92%).
- `params8.py`: the multi-table soundness model. Its output is in `tables8-output.{txt,json}`.

Key numbers (expected sizes):

| case | proof | λ_IOP | binding round |
|---|--:|---|---|
| M1 / Z128 cap 0 | 73,435 B | 128.06 | fold1 |
| M1 / Z128 cap 5 | 75,968 B | 128.06 | fold1 |
| M2 / Z128-g, commit PoW 3 | 122,995 B | 128.70 | query |

For S1/S2:
- **Build M2 with commit_pow_bits = 3.** Z128-g as designed (commit PoW 2) gives 127.92, because the roll-in charge costs 0.19 bits.
- **Export the preprocessed salts or seed** with the verifying key. The hiding MMCS salts the preprocessed tree, so the root cannot be recomputed from the AIR alone.
- **Zero-bit PoW witnesses.** If p3b-v1 omits PoW witnesses at 0 bits, the decoder inserts 0.
- **Size variance.** A single proof's size varies about ±2–3% around the expected value (multiproof siblings).

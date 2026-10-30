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
## S0 - Specification and calculators (done, 2026-10-30)

Bench branch `wip/stark-usable-design`, commits b4cd81e and the follow-up S1 cross-check, folder `research/pq-stark/design-t8/`:
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
| M1 / Z128 cap 0 | 73,434 B | 128.06 | fold1 |
| M1 / Z128 cap 5 | 75,967 B | 128.06 | fold1 |
| M2 / Z128-g, commit PoW 3 | 122,993 B | 128.70 | query |

For S1/S2:
- **Build M2 with commit_pow_bits = 3.** Z128-g as designed (commit PoW 2) gives 127.92, because the roll-in charge costs 0.19 bits.
- **Export the preprocessed salts or seed** with the verifying key. The hiding MMCS salts the preprocessed tree, so the root cannot be recomputed from the AIR alone.
- **Zero-bit PoW witnesses.** If p3b-v1 omits PoW witnesses at 0 bits, the decoder inserts 0.
- **Size variance.** A single proof's size varies about ±2–3% around the expected value (multiproof siblings).
- **Cross-check against S1.** bytes8 was checked against S1's 28 p3b-v1 vectors. Every deterministic section matches exactly, and the fold schedules are equal. The expected-sibling model overshoots by +1.06% on average, so it is conservative.

## S2 - Statement AIRs M1 and M2 (done, 2026-10-30)

Crate `research/pq-stark-batch/prover`: `src/stmt.rs` holds the AIRs, Poseidon2 and the witness/trace generator; `src/s2.rs` holds the checks. Regenerate with `gen-s2.sh` (about 4 min, nice, 4 threads). Vectors are in `vectors/S2/` and reports in `vectors/S2/report/`. README has an "S2" section.

- **AIRs, from AIR-SPEC in emission order.**
  - M1: 53 constraints, degree 4, 8 chunks.
  - T_hash: 40 AIR + 4 LogUp constraints, 8 chunks.
  - T_ctl: 31 AIR + 4 LogUp constraints, 4 chunks.
  - Bus `P2` has width 13. The fold schedule is [3] for M1 and [3, 3] for M2.
  - Next-row columns are declared exactly as the spec gives them. Preprocessed columns are opened at ζ only.
- **Acceptance: all met, with one size caveat.**
  - Poseidon2 differential test against p3-goldilocks: 10,002 inputs plus the test vector.
  - `check_all_constraints` on honest traces: 0 violations, at leaf 0, leaf 2^30 − 1 and a random leaf.
  - The Rust traces are identical to air8_ref.py's.
  - Single-cell mutations: all caught. M1 17,408/17,408, T_hash 24,576/24,576, T_ctl 1,664/1,664. Of the T_ctl cells, 128 are caught only by the bus: nk, r and the siblings.
  - Forced unsatisfying traces: 16 of 16 rejected by `verify_batch`. The bus-only cases fail with `TerminalSumNonZero`.
  - Wrong public values: 36 of 36 rejected. Other verifying keys: 9 of 9 rejected.
  - Tamper sweeps: 516 cases, 0 unexpected.
  - A second ZK seed gives different bytes.
- **Sizes against S0.** The means are within 0.2%: M1 cap 0 +0.11%, cap 5 +0.13%, M2 −0.19%. That is over 27, 27 and 11 proofs.
  - **One single proof is outside ±3%:** M2 at leaf 2^30 − 1 is 118,950 B, −3.29%. It is smaller than expected; the cause is sibling-sharing luck.
- **Prover time (4 threads, median):** M1 about 0.9–1.0 s, M2 about 1.3 s. At 1 thread: M1 3–4 s, M2 about 6.7 s.
- **Peak RSS:** M1 1.06 GB, M2 1.45 GB.
- **M2 VK setup seed.** The preprocessed commitment is salted by the hiding MMCS. Statement VKs therefore use a published setup seed, `SETUP_SEED` = "t8SETUP1", so anyone can recompute the root. The prover's salts come from a separate RNG.
  - A VK built with another setup seed rejects an honest proof.
  - The S1 vectors still check: 1,538 cases, 0 unexpected.
- **For S3/S4/S5:**
  - Vectors carry `dag`, `transcript_hash_inputs`, `tampered` and `setup_seed`.
  - `s2 witness --case m1@L@W` exports the witness, NF, ROOT and the periodic columns.
  - `s2 batch` produces more than 20 statements on demand (they are cached, not committed).
  - Other parameter VKs reject the same proof, including PoW-bit changes, because batch-stark's domain separator and FRI bind the parameters. The generator must still pin them.

## S3 - JS reference verifier verify-batch.mjs (done, 2026-10-30)

Folder `research/pq-stark-batch/verifier/`; README has the full results and gaps. Regenerate with `gen-s3.sh` (about 3 min; nice, 4 threads for Rust, one node process).

- **Verifier.** `verify-batch.mjs` is independent BigInt JS. It covers N tables, mixed-height injection, per-height alpha' ladders, roll-ins, LogUp (bus layout, lookup PoW, terminal sum), caps, ZK (salts, random codewords, randomized quotient), preprocessed and periodic columns, and the constraint DAG.
  - The VK comes from VK data only. The round layout, cap lengths and FRI schedule are re-derived and must equal `shape`.
- **Acceptance met.**
  - 128 valid vectors are accepted by JS and Rust: 37 committed, 35 extra-seed, and 56 S2 batch statements (M1 cap 0 ×24, cap 5 ×24, M2 ×8).
  - Transcripts: 128/128 identical to Rust's SHA-256 inputs, byte for byte.
  - 14,027 cases, 0 JS/Rust disagreements, 0 unexpected. Families: cap, terminal, ood, random, pow, final, row (injected short tables included), salt, sibling, count, fri_value, truncate, extend, noncanon, statement (PV + 1, NF ± 1, NF + p, foreign ROOT/NF/CTX, permutations), other_vk (cap, set, zk, setup seed, M1 ↔ M2, plus 64 second-seed proofs that both accept), vk_variant (PoW bits, cap + 1), and forced (S2 unsatisfying-trace proofs; the bus-only ones fail on the terminal sum in both verifiers).
  - ZK re-seed: 21 groups, all proofs distinct.
  - JS takes 4–78 ms per proof.
- **Suite sensitivity.** Each of eight checks was removed from a copy of the JS verifier. Six are caught: cap compare, constraint fold, periodic columns, injection, roll-in, terminal sum. **Two are not:** the lookup PoW check and the FRI final-polynomial check. A byte edit before the query indices re-draws them, so Merkle rejects first. Testing these two needs a modified prover; that is not done.
- **Rust changes** (`prover/src/main.rs`, `s2.rs`):
  - `check --verdicts OUT`;
  - per-case `public_values` (non-canonical values rejected), `replace` and `expect`;
  - `s3_valid_expect`;
  - `s2 forced --with-proofs`.
  - The S1/S2 vectors still check: 2,054 cases, 0 unexpected.
- **For S4/S5:**
  - `verify-batch.mjs` is the spec to follow. Its exports are `vkFromVector`, `parse` (with an offset recorder), `verify`, `runCase` and `applyTamper`.
  - The generator must assert the VK-time properties that JS does not check per proof: the multiplicity height bound and the hiding budget.
  - Cases: `gen-cases.mjs` writes one file per vector, in the format Rust `check` and `agree.mjs` read. The on-chain suite can reuse it.

## S4 - Generator and layout (b) for M1 (done with one miss, 2026-10-30)

Folder `research/pq-stark-batch/onchain/` (README there). Regenerate with `gen-s4.sh` (about 20 min; nice, 4 threads for Rust, one node process). The S4 vectors are in `prover/vectors/S4/` (3 committed; 24 statements plus other-VK proofs in cache/s4).

- **Generator.** The VK comes from VK data only (S3 `vkFromVector` plus strict-height and hiding-budget asserts). It supports one table, one height, cap 0, ood PoW 0. Track 5's gen.mjs was copied and adapted, and Track 5 is unchanged.
  - Transcript: batch-stark prefix (seed and degree_bits as one constant), then the trace cap and the public values.
  - AIR: the exported DAG (551 nodes, 53 constraints) runs as a 2.1 KB byte-code program in an OP_INVOKE interpreter. It uses registers for multi-use nodes and selectors multiplied through by (ζ−1)(ζ−g⁻¹).
  - Periodic columns: a 32-step loop with packed coefficients. Quotient: prefix/suffix products. α′, A_z and the row keys: one loop. Extension multiply: a packed schoolbook product.
- **Statement layer.** ROOT is a script constant. NF is a witness item with each lane < p. CTX is computed by introspection of the spending transaction's outputs; the serialization is in prover/FORMAT.md. The prover takes `m1@LEAF@WSEED@<ctx hash>` (`airs.rs`).
- **Regimes, 24 transaction-bound statements:**
  - Raised limits (r100: one 100 KB input) and bch-spec: all accepted, standard and consensus, including libauth whole-transaction verify.
  - Today's rules: rejected (unlocking above 10,000 B), as designed.
  - Unlocking 91,388–94,968 B; transaction 91,477–95,057 B (≤ 100,000); redeem 19,024 B; proof 71,344–74,928 B.
- **Op-cost (BCHN-adjusted) 35.53–36.04M**, 47.4–48.6% of the r100 budget and 42.9–43.8% under bch-spec.
  - **Against the S0 model (28.26M) it is +26–28%, outside ±15%.** Against DESIGN §5's 30–32M it is +11–20%.
  - Queries are 16.09M (model 16.79M) and Merkle 7.05M (model 7.23M), both on model.
  - The miss is the fixed part: 12.8M against a modelled 4.23M. Of that, the AIR is 8.0M (the model assumed 0.6M): DAG interpreter 5.79M, periodic 1.19M, quotient 0.44M. DEEP constants are 3.16M.
- **Sweeps: 0 unexpected.**
  - model-agree: 3,762 cases, model vs verify-batch, 0 disagreements, transcripts identical.
  - Production test-b: 26 files, 2,929 cases. It covers the S3 families plus tx (182), root (52) and witness manipulations (1,014).
  - Harness test-b (CTX as a witness item) on S3's M1 cap-0 case files: 3,309 cases, including forced (9), vk_variant (3) and other_vk.
  - test-ctx: 4 transactions, 0 mismatches.
  - Caveats: 59 NF + p cases are n/a (no 8-byte lane encoding); encodable non-canonical lanes are tested in the witness family. Malformed-by-length proofs are refused by the encoder. In one such case the lenient witness of a 1-byte truncation equals the valid proof's witness, and the script accepts it, correctly.
- **For S5–S7:** extend `vkxFromVector` and `dagProgram` (ext constraints, challenges, perm values; several heights); cap > 0 is not built.

# pq-stark-batch prover (Track 8, stages S1 and S2)

This crate is the batch-STARK prover for the Track 8 CashVM verifier. It builds Plonky3 `p3-batch-stark`
at the pinned commit `0d803737b681774186cd283b1fd2d8e493655c82`, configured with:
- **Field:** Goldilocks, with the cubic trinomial extension (x^3 = x + 1).
- **Hashing:** SHA-256 for Merkle leaves, nodes, Fiat-Shamir and grinding.

For every proof it writes:
- **p3b-v1 bytes** (the wire format, [FORMAT.md](FORMAT.md));
- **the shape** that the verifying key fixes;
- **the constraint DAG** of every table;
- **the transcript log** of every SHA-256 input the Fiat-Shamir challenger hashed.

The design is `research/pq-stark/DESIGN-T8.md` (bench repo, branch `wip/stark-usable-design`), §7 S1. This
crate copies from Track 5's `research/pq-stark/prover` (`cfg.rs`, the encoder pattern) and does not modify it.

```
CARGO_TARGET_DIR=/path/outside/repo ./gen-vectors.sh      # build, all vectors, acceptance, re-check
pq-stark-batch-prover accept --set P3|Z128[+k=v...] [--shift N|auto] --outdir DIR [--sweep]
pq-stark-batch-prover prove --case NAME --set SET [--shift N|auto] [--seed K] [--sweep] --out F.json
pq-stark-batch-prover check F.json...
```

Resources: run under `nice` with `RAYON_NUM_THREADS=4` and `cargo -j4`. Each proof here takes at most 2 s.
The complete `gen-vectors.sh` takes about 1 minute.

## What `accept` checks per case

1. **Prove and self-verify.** `prove_batch`, then Plonky3's `verify_batch` on the in-memory proof.
2. **Encode against the derived shape.** Encode to p3b-v1 against the shape derived from the verifying key
   alone (`src/shape.rs`). Every length and presence flag is asserted against the proof.
3. **Decode and verify the bytes.** Decode the bytes back into `BatchProof`, then run `verify_batch` on the
   decoded proof while recording the transcript. This is the **S1 acceptance check**.
4. **Exact round trip.** `decode(encode(proof))` must be identical to Plonky3's serde tree.
5. **DAG row check.** Every exported base constraint is 0 on every row of the valid trace. One changed
   cell makes some base constraint nonzero.
6. **Tamper sweep** (`--sweep`). These are plain rejections of altered proofs:
   - flip the first and the last byte of every section (each root or cap, terminal, OOD block, PoW witness,
     random-codeword block, FRI root, final polynomial, row block, salt block and sibling list);
   - a non-canonical element (= p);
   - truncate by 1 byte, and extend by 1 byte;
   - public value + 1.

   Every case must be rejected.
7. **Fresh randomness under ZK.** A second seed must give different proof bytes for the same witness.

`check` covers the same ground from the file alone:
- it rebuilds the verifying key from the vector (case, shift, seed, set);
- it requires the same shape and the same preprocessed commitment;
- it then re-runs the valid proof and every stored tampered case through `verify_batch`.

## S1 acceptance results

These are Plonky3's batch tests, reconfigured to SHA-256 / Goldilocks / cubic trinomial. `verify_batch`
accepts the decoded p3b-v1 bytes in every case.

The parameter sets (`src/cfg.rs`):

| set | meaning |
|---|---|
| **P3** | Plonky3's own FRI shapes and ZK settings: `FriParameters::new_testing(_, 2)`. ZK tests use 4 random codewords, salt 4 and cap 2, as in `make_config_zk`. Plonky3's heights are used. **Not secure.** |
| **Z128** | DESIGN-T8 §0.5: lb 9, arity ≤ 8, final length 256, Q 24, PoW query 24 / commit 2 / batch 20, rc 3, salt 2, cap 0, ZK. Heights are Plonky3's × 2^shift, with the smallest shift that meets the strict FRI height rule. |
| **Z128+zk=0**, **Z128+cap=5**, **Z128g** | non-ZK; Merkle cap 5 (the today's-rules layout); final length 32 (M2's set) |

`n1024` rows use M1's trace height n = 2^10 (LDE 2^20, one arity-8 fold), or a mixed batch on the arity
grid.

| set | case | log n | FRI log-arities | proof B | siblings B | prove ms | rejection cases | transcript hashes |
|---|---|---|---|--:|--:|--:|--:|--:|
| PT | single_instance | [5] | [1,1,1] | 2,484 | 1,728 | 0 | 42 | 11 |
| PT | three_instances_mixed_sizes | [4,3,3] | [1,1] | 2,410 | 864 | 0 | 42 | 9 |
| PT | mixed_preprocessed | [4,4] | [1,1] | 2,642 | 1,408 | 0 | 40 | 9 |
| PTZ | both_lookups_zk | [5,5] | [1,1,1,1] | 12,442 | 2,816 | 1 | 84 | 15 |
| PTZ | periodic_air_zk | [6] | [1,1,1,1,1] | 5,848 | 2,624 | 0 | 69 | 15 |
| Z128 | single_instance | [8] | [1] | 64,146 | 46,272 | 777 | 54 | 14 |
| Z128 | three_instances_mixed_sizes | [9,8,8] | [1,1] | 98,652 | 57,984 | 614 | 64 | 16 |
| Z128 | mixed_preprocessed | [8,8] | [1] | 76,290 | 47,232 | 902 | 56 | 14 |
| Z128 | both_lookups_zk | [8,8] | [1] | 98,644 | 56,256 | 289 | 68 | 16 |
| Z128 | periodic_air_zk | [8] | [1] | 52,288 | 38,400 | 371 | 47 | 14 |
| Z128 | single_instance n1024 | [10] | [3] | 75,346 | 54,016 | 1,432 | 54 | 14 |
| Z128 | both_lookups_zk n1024 | [10,10] | [3] | 110,932 | 65,088 | 1,947 | 68 | 16 |
| Z128+zk=0 | single / mixed sizes / mixed pre / lookups / periodic | [9] … [10,9,9] | [1] or [1,1] | 35,238 – 61,546 | | ≤ 602 | 31 – 48 | |
| Z128+cap=5 | the same five | as Z128 | as Z128 | 53,952 – 103,804 | | ≤ 1,121 | 47 – 68 | |
| Z128g | the same five | [6] … [7,6,6] | [2] or [1,2] | 37,952 – 87,324 | | ≤ 894 | 47 – 64 | |
| Z128g | three_instances_mixed_sizes n1024 | [10,9,9] | [1,3,2] | 108,838 | 67,936 | 954 | 70 | 18 |

**Totals:** 28 vectors, 1,538 `check` cases, 0 unexpected verdicts (`vectors/rust-check.txt`). Every ZK
case gives different bytes under a second seed.

**What the sizes mean:**
- They are for Plonky3's toy AIRs, 2 to 7 columns wide. They are **not** M1 sizes; M1 and M2 come in S2.
- The Merkle siblings (cap 0) are 57–82 % of the proof.
- Moving from cap 0 to cap 5 changes the total by +1 to +5 KB at these small heights. The cap costs
  32 × 32 B per tree, and each query saves only a few sibling digests at these tree depths.

## Findings for the next stages (checked at the pin)

1. **The preprocessed commitment is salted under ZK.**
   - What happens: `HidingFriPcs` commits the preprocessed matrices with the same hiding MMCS. Each
     preprocessed row gets s random salt elements, and the preprocessed round's openings carry salts. The
     round has no random codewords, though.
   - Why it matters: under Z128 the verifying-key commitment is therefore **not** recomputable from the
     AIR alone. It is the commitment produced at setup, from the setup RNG.
   - Design to correct: DESIGN-T8 §4 ("the commitment is transparent and can be recomputed from the AIR")
     needs this correction for M2. Either the VK pins the setup commitment, or the setup salts are fixed and
     published.
   - Binding is unaffected: it is SHA-256.
2. **batch-stark's transcript does not bind periodic columns.** Only `multi-stark` absorbs
   `periodic_statement`. The batch transcript binds instance count, widths, public-value counts and
   degree bits, but not commitment widths or periodic values. Our generator compiles both into the script
   as constants, so this is safe for us. It must stay that way: a verifier that reads periodic values from
   data would be unbound.
3. **Height floor under Z128.** The strict rule log n + zk > log_final_poly_len gives:
   - n ≥ 2^8 with ZK;
   - **n ≥ 2^9 without ZK**. DESIGN-T8 §2.3 states 2^8, which holds only under ZK.

   Under Z128g (final length 32): n ≥ 2^5 with ZK, so T_ctl at 2^7 is fine.
4. **Plonky3's mixed-size test is non-ZK.** At its tiny heights (8 rows) it cannot run under ZK: the
   preprocessed matrix exceeds the hiding budget (`HidingBudgetExceeded { mask_height: 8 }`). The faithful
   P3 run therefore uses each test's own ZK setting. Under Z128 every case runs with ZK.
5. **Lookup PoW is unset.** The lookup grinding site is 0 bits in Z128, because DESIGN-T8 does not fix it.
   With 0 bits the witness is pinned to 0 and is not in the bytes. A nonzero value is supported (`+lpow=b`)
   and adds one element. S0/S8 should set it from the LogUp term.
6. **Zero-bit PoW sites are omitted from the bytes and decode as 0.** This covers Plonky3's OOD and lookup
   sites, which Plonky3 itself pins to 0, and the FRI batch, commit and query sites, as in Track 5's p3s-v1.
   The format therefore cannot carry a nonzero witness at 0 bits.
7. **Reproducibility.** With the same seed, single-instance proofs are byte-identical across runs.
   Multi-instance ZK proofs are not: 4 of the 23 Z128 vectors differed between two runs, first at the
   quotient root. Their trace roots match. The quotient-round randomization is drawn in a different order
   between runs. Every such proof verifies; the stored vector file is the reference. The test seeds are for
   reproducible single-instance vectors only, and production must use OS randomness.
8. **Effective caps** follow 2^min(cap_height, log2 of the smallest matrix in the tree). This is checked
   against Plonky3 for caps 0, 2 and 5. FRI commit-phase trees use the height after the fold.

## S2: statement AIRs M1 and M2

`src/stmt.rs` implements M1 and M2 from AIR-SPEC.md (bench `research/pq-stark/design-t8/`, branch
`wip/stark-usable-design`), in its emission order:
- **M1:** 17 columns, 11 periodic columns, 53 constraints, degree 4, 8 ZK chunks.
- **M2:** batch order T_hash, then T_ctl.
  - T_hash: 24 main columns plus 1 preprocessed; 40 AIR constraints plus 4 LogUp; 8 chunks.
  - T_ctl: 13 main columns plus 5 preprocessed; 31 AIR constraints plus 4 LogUp; 4 chunks.
  - Both tables share one global bus `P2` of width 13.

They are `TestAir` variants, so shape, wire, DAG export, `prove` and `check` handle them unchanged. Case names
are `m1@<leaf>@<witness seed>` and `m2@<leaf>@<witness seed>`. Parameter sets:
- M1: `Z128` (cap 0) and `Z128+cap=5`;
- M2: `Z128g+cpow=3+lpow=8` (AIR-SPEC §5).

```
CARGO_TARGET_DIR=... S2_CACHE=... AIR8_REF_DIR=<bench>/research/pq-stark/design-t8 ./gen-s2.sh
pq-stark-batch-prover s2 selftest|mutate|forced|pvs|batch|witness ...   (src/s2.rs)
```

The full run took about 4 minutes. Its outputs are the vectors in `vectors/S2/` (leaf indices 0, 2^30 − 1 and
0x2b1c9e37) and the reports in `vectors/S2/report/`.

**Verifying-key setup seed (M2).** Under ZK, the hiding MMCS salts the preprocessed commitment.
- Statement cases build the verifying key from a published seed: `SETUP_SEED` = 0x7438534554555031 ("t8SETUP1"),
  drawn as `StdRng::seed_from_u64(SETUP_SEED ^ 0x5a5a_0001)`.
- Anyone can recompute the commitment from the AIR and that seed. `check` does exactly this for every vector.
- The prover's salts come from a separate RNG: its `seed`, which must be OS randomness in production. They are
  never drawn from the setup RNG.
- The S1 test cases keep their old behaviour, so their stored vectors still check: 1,538 cases, 0 unexpected,
  re-run after S2.

**S2 acceptance** (`report/summary.json`):

| check | result |
|---|---|
| Poseidon2-Gl-8 differential test against `p3_goldilocks::default_goldilocks_poseidon2_8()` | AIR-SPEC test vector and 10,002 inputs agree |
| honest traces through Plonky3's `check_all_constraints` (leaf 0, 2^30 − 1, random) | 0 violations, for M1 and both M2 tables |
| bus check (exact multiset, and Plonky3's `check_lookups`) | balanced; the negative control is rejected |
| traces against air8_ref.py | Rust traces identical cell for cell (`report/crosscheck-air8_ref.txt`) |
| single-cell mutations (Plonky3 `DebugConstraintBuilder`, plus the bus for M2) | M1 17,408/17,408; T_hash 24,576/24,576; T_ctl 1,664/1,664 |
| forced unsatisfying traces through `prove_batch` then `verify_batch` | 16 of 16 rejected; the honest controls are accepted |
| wrong public values; other verifying keys | 36 of 36 and 9 of 9 rejected |
| p3b-v1 tamper sweeps of the 9 vectors | 516 cases, 0 unexpected |
| ZK: a second prover seed | different bytes for all 9 vectors, all verify |

In `report/forced.json`, a mutation that only the bus can catch fails verification with `TerminalSumNonZero`.
Examples are nk or r in T_ctl, which no AIR constraint covers. Every other forced case fails with
`OodEvaluationMismatch`.

**Sizes against S0's expected values** (bytes8.py). This covers the 9 vectors plus 24 + 24 + 8 random
statements:

| set | proofs | mean | range |
|---|--:|--:|---|
| M1 Z128 cap 0 (expected 73,434 B) | 27 | +0.11% | −2.24% … +1.69% |
| M1 Z128 cap 5 (expected 75,967 B) | 27 | +0.13% | −1.20% … +1.83% |
| M2 Z128-g (expected 122,993 B) | 11 | −0.19% | **−3.29%** … +1.94% |

One proof falls outside ±3%: `m2-1073741823`, at 118,950 B. It is *smaller* than expected. The spread comes from
how many Merkle siblings the random query set shares (AIR-SPEC §6 item 5). Every mean is within 0.2%.

**Prover time and peak RSS.** These are fresh processes on this machine (24 cores) under nice; the spread over 3
runs is large.

| statement | 4 threads: prove ms (median) | 1 thread: prove ms (median) | peak RSS |
|---|--:|--:|--:|
| M1 Z128 cap 0 | 1,034 (743–1,971) | 3,842 (2,653–7,839) | 1.06 GB |
| M1 Z128 cap 5 | 809 (767–1,051) | 3,004 (2,480–3,932) | 1.06 GB |
| M2 Z128-g | 1,274 (875–1,277) | 6,715 (3,434–8,458) | 1.45 GB |

Rust verification takes 2–5 ms. The batch medians at 4 threads are 912 ms (M1 cap 0), 1,000 ms (M1 cap 5) and
1,346 ms (M2).

## Files

| file | role |
|---|---|
| `src/cfg.rs` | configurations and parameter sets (Track 5 cfg.rs + cap_height, OOD/lookup PoW) |
| `src/airs.rs` | Plonky3's batch test AIRs, ported, and the five S1 cases |
| `src/shape.rs` | p3b-v1 shape from the verifying key (quotient chunks, rounds, caps, fold schedule) |
| `src/wire.rs` | p3b-v1 encoder/decoder, with a section map |
| `src/dag.rs` | constraint-DAG export and the row self-check |
| `src/main.rs` | prove / accept / check |
| `vectors/P3`, `vectors/Z128` | the vectors; `accept-*.json` summaries; `rust-check.txt` |

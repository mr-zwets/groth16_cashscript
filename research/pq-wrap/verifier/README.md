# Track 8 S3: JS reference verifier for p3-batch-stark (p3b-v1)

`verify-batch.mjs` is an independent JavaScript (BigInt) verifier for Plonky3 `p3-batch-stark` proofs in the
p3b-v1 byte format (`../prover/FORMAT.md`). Plonky3 pin 0d80373; SHA-256, Goldilocks, cubic trinomial extension.
It is the specification the CashVM generator (S4/S5) follows. It shares no code with Plonky3 or with the Rust
prover. The field, Keccak and challenger primitives are copied, not imported, from Track 5's
`research/pq-stark/prover/verify.mjs`. Track 5's files are unchanged.

## What it covers (DESIGN-T8 §7 S3)

| feature | where |
|---|---|
| N tables, one transcript | `batchSeparator`, `verify` (degree_bits, main cap, public values, preprocessed cap, lookup phase, alpha, quotient and random caps, ood PoW, zeta) |
| mixed heights: injection | `merkleVerify`: node = SHA256(SHA256(l‖r) ‖ H(rows of the matrices of that height)), group-consistency check |
| per-height DEEP ladders | reduced openings: one alpha' power ladder per LDE height, walking (round, matrix, point, column) |
| roll-ins | FRI fold: `folded += beta^(2^log_arity) * ro[h]` when the folded height has inputs |
| LogUp | bus ids in first-use order (global buses shared), `bus_prefix[k] = alpha + (k+1)·beta^maxW`, per-lookup `[prefix, beta]` challenges, lookup PoW, the terminal sum over the batch is 0 |
| Merkle caps | proof levels = max(total − min(cap, total), last injection level); final digests must equal `cap[index]` |
| ZK | salts on every input and FRI leaf (preprocessed too), random-codeword values appended to the claims (none for the preprocessed round), randomized quotient (2^(log_chunks+1) chunks on the disjoint coset) |
| preprocessed columns | the VK's commitment is observed before any challenge and verified as round 4 |
| periodic columns | VK constants from the DAG; evaluated at zeta^(n/period) on the period subgroup |
| constraints | the exported DAG (`dag[i]`) evaluated at zeta, Horner fold with alpha, checked against the recomposed quotient |

The verifying key comes only from VK data in the vector: the parameter set, per-instance AIR metadata (widths,
next-row use, public-value count, quotient chunk count), the DAG (with lookups and periodic columns) and the
preprocessed commitment. `vkFromVector` re-derives the PCS round layout, every Merkle cap length, the FRI fold
schedule and the PoW flags, and refuses a vector whose `shape` differs.

## Results (`gen-s3.sh`, about 3 minutes)

| check | result |
|---|---|
| valid vectors | 128 accepted by JS and Rust: the 37 committed S1/S2 vectors, 35 extra-seed proofs, 56 S2 batch statements (M1 cap 0 ×24, cap 5 ×24, M2 ×8) |
| transcript | 128 / 128 identical to Rust's recording, byte for byte (every SHA-256 challenger input) |
| verdict agreement | 14,027 cases, 0 JS/Rust disagreements, 0 verdicts against expectation |
| ZK re-seed | 21 groups (same statement, same VK, 2–3 seeds): all proofs distinct, all accepted |
| JS speed | 4–78 ms per valid proof (node 24, one core, unoptimised BigInt) |

Cases per family (all expected to reject except the 64 alternative valid proofs in `other_vk`):

| family | cases | what |
|---|--:|---|
| cap | 1,531 | every Merkle cap digest of every input and FRI tree, byte 0; byte 31 of each cap's first digest |
| terminal | 72 | every LogUp terminal, coefficients 0 and 2 |
| ood | 2,258 | every opened value at zeta and zeta·g (trace, preprocessed, quotient chunks, random, permutation) |
| random | 1,366 | every opened random-codeword value |
| pow | 438 | every PoW witness present (lookup, batch, commit, query) |
| final | 996 | final-polynomial coefficients 0, 8, 16, … and the last |
| row | 1,158 | per round and matrix (short injected tables included): first and last query |
| salt | 1,074 | per round and matrix, first and last query |
| sibling / count | 1,018 / 823 | first, middle, last sibling of every multiproof; sibling count ± 1 |
| fri_value | 388 | FRI sibling values and salts |
| truncate / extend | 387 / 239 | − 1, − 8, − 24, − 32, half, empty, section ends; + 1, + 8 bytes, a duplicated digest, 24 bytes after the ood region |
| noncanon | 343 | one element of each kind set to p, v + p or 2^64 − 1 |
| statement | 1,358 | each public value + 1; NF − 1; NF + p; a foreign/stale ROOT; a foreign NF; a foreign CTX; CTX changed; ROOT/NF swapped; rotated; all zero; values moved to another instance |
| other_vk | 411 | another vector's proof under this VK: cap 0 ↔ cap 5, Z128 ↔ Z128g ↔ zk off ↔ P3, other setup seed (other preprocessed commitment), M1 ↔ M2; plus 64 second-seed proofs of the same statement and VK (accepted by both) |
| vk_variant | 23 | the stored proof under a VK with batch, commit, query, lookup or ood PoW bits changed, or cap + 1 |
| forced | 16 | S2's proofs of unsatisfying traces and wrong public values, made by the release prover; the 2 bus-only M2 cases fail on the terminal sum in both verifiers |

## Sensitivity of the suite

The suite was run (37 committed vectors, 9,878 cases) against eight copies of the JS verifier, each with one check
removed or broken:

| removed or broken | disagreements found |
|---|--:|
| cap comparison in the Merkle walk | 1,385 |
| one constraint dropped from the fold | 58 |
| periodic columns evaluated as 0 | 36 |
| injection hash skipped | 15 |
| roll-in skipped | 15 |
| LogUp terminal-sum check | 2 (the bus-only forced proofs) |
| lookup PoW check | **0** |
| FRI final-polynomial check | **0** |

The last two are not exercised by any plain tampering of an honest proof. Any edit made before the query
indices are drawn changes them, so a Merkle check rejects first. Testing these two checks in isolation needs a
prover that emits internally consistent wrong proofs (a modified prover), which is outside S3. Both checks are
written to the pinned Plonky3 code (`check_witness`, `verify_fri`). The same holds for the duplicate-query and
injected-group consistency checks in `merkleVerify`: they are implemented, but no case contains two equal query
indices with different rows.

## Not covered, or covered elsewhere

- **Header bytes.** p3b-v1 has no header: `degree_bits` are VK data and are bound into the transcript from the VK.
- **Depth-29 VK.** No depth-29 statement AIR exists. Other-VK cases use other parameter sets, cap heights, ZK
  on/off, setup seeds, PoW bits and the other statement AIR.
- **VK-time checks.** Plonky3's `check_multiplicity_height_bound`, the hiding budget and the strict FRI height
  rule are properties of the VK, not of a proof. JS checks the strict height rule and lookup tuple/bus widths when
  it builds the VK. The generator (S4/S5) must assert the multiplicity bound and the hiding budget at generation
  time.
- **Quotient chunk count and DAG.** Both are taken from the VK export (Plonky3's symbolic evaluation); JS does not
  re-derive constraint degrees.
- **Sampling.** Final-polynomial coefficients every 8th; rows and salts two per matrix; siblings three per list.
  The 35 extra-seed and 56 batch vectors get one or two cases per family; the committed vectors get all.

## Files and commands

- `verify-batch.mjs`: the verifier. `node verify-batch.mjs [--trace] VECTOR.json...` runs the valid proof
  (`--trace` compares the transcript) and the vector's own `tampered` list.
- `gen-cases.mjs`: builds the case set above from the parser's offset map. Each output file is a copy of a vector
  whose `tampered` list holds the extended cases (`family`, `expect`, optional `public_values` and `replace`).
- `agree.mjs`: JS verdicts against Rust's `check --verdicts` output, per case.
- `gen-s3.sh`: the whole run. Env: `CARGO_TARGET_DIR`, `S3_CACHE`, `S2_BATCH`.
- `report/`: `summary.json` (counts per family, per vector, VK variants, re-seed groups), `agree.txt`,
  `rust-check.txt`, `gen-cases.txt`. The 90 MB case files and both verdict files stay in the cache.

The Rust prover gained what this needs (`../prover/src/main.rs`, `../prover/src/s2.rs`):
- `check --verdicts OUT` writes every verdict;
- a case may carry `public_values` (non-canonical values are rejected, as the wire format does), `replace` (a whole
  other proof) and `expect`;
- a vector may set `s3_valid_expect: false`;
- `s2 forced --with-proofs` stores each forced proof as p3b-v1 hex with its public values.

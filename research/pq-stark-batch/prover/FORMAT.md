# p3b-v1: byte format for Plonky3 batch-stark proofs (SHA-256, Goldilocks, D = 3)

This is the canonical serialization the Track 8 CashVM verifier reads. It covers N tables, mixed heights,
preprocessed columns, periodic columns, LogUp lookups, Merkle caps and ZK.

- **Encoder and decoder:** `src/wire.rs`. They work on Plonky3's serde tree of `BatchProof<SC>` at commit
  `0d803737b681774186cd283b1fd2d8e493655c82`.
- **Shape:** `src/shape.rs` derives it from the verifying key alone.
- **Round-trip check:** every vector's bytes are decoded back into `BatchProof` and passed to Plonky3's
  own `verify_batch`. `decode(encode(proof))` is also checked to equal Plonky3's serde tree exactly.

It extends Track 5's p3s-v1 (`research/pq-stark/prover/FORMAT.md`) and keeps its primitives.

## Primitives

| item | encoding |
|---|---|
| base element (Goldilocks, p = 2^64 − 2^32 + 1) | 8 bytes little-endian. **Must be canonical (< p)**, else reject. |
| extension element | 3 base elements, coefficient of u^0 first. The field is `CubicTrinomialExtensionField<Goldilocks>`, u^3 = u + 1. |
| digest | 32 bytes (SHA-256) |
| cap of length c | c digests. c comes from the shape, with no count field. |
| digest list | u16 LE count, then `count` digests. This is the only self-describing length. |
| PoW witness | one base element. It is present only when that site's bits > 0. An absent witness means 0. |

## The shape (verifying-key data, never read from a proof)

Each vector carries the shape as `shape`, and `check` re-derives it from the AIRs and the parameter set. It
holds the following.

**Per instance i** (in batch order):
- `degree_bits` = log n_i + zk;
- `log_lde` = degree_bits + log_blowup;
- `width` W_i, and `opens_next` (trace opened at ζ·g_i);
- `preprocessed_width` PW_i, and `preprocessed_next`;
- `num_chunks` C_i, quotient chunks with ZK included: 2^(log_chunks + zk);
- `num_lookups` L_i, and `perm_width` PE_i = (L_i + 1)·3 when L_i > 0, else 0.

Several things are not in the bytes:
- `degree_bits` are VK data. Plonky3's proof carries them, the decoder fills them in from the shape, and
  the transcript observes them.
- The preprocessed commitment is in the VK (`preprocessed_commitment` in a vector).
- Public values are not in the proof.

**PCS rounds**, in opening order (= `coms_to_verify` in `batch-stark/src/verifier/mod.rs`):

| round | matrices | columns | opening points | random codewords rc |
|---|---|---|---|---|
| `random` (ZK only) | one per instance | 3 + rc | ζ | rc |
| `trace` | one per instance | W_i + rc | ζ, plus ζ·g_i if `opens_next` | rc |
| `quotient` | C_i per instance, instances in order | 3 + rc | ζ | rc |
| `preprocessed` (if any instance has one) | one per instance with PW_i > 0, in `matrix_to_instance` order | PW_i (no rc) | ζ, plus ζ·g_i if `preprocessed_next` | 0 |
| `permutation` (if any lookup) | one per instance with L_i > 0 | PE_i + rc | ζ, ζ·g_i | rc |

Every matrix of instance i has LDE height 2^log_lde_i.

`rc` = `num_random_codewords` under ZK, else 0. Note:
- The preprocessed commitment is built by the same hiding MMCS, so its rows are salted.
- It carries no random codewords.

**Cap length of a round** = 2^min(cap_height, log2(smallest matrix height in that tree)).

Plonky3 keeps the proof down to the layer where the shortest matrix is injected (`arity_schedule_and_proof_levels`
in `merkle-tree/src/mmcs/mod.rs`).

**FRI:**
- `log_arities` = `p3_fri::fold_schedule(distinct log_lde tallest first, log_final_poly_len + log_blowup, max_log_arity)`.
- Every log_lde must be > log_final_poly_len + log_blowup (strict, `validate_input_height`).
- The commit-phase tree of round r holds one matrix of height H_r / 2^a_r. H_r is the codeword height
  entering round r.
- Its cap length is 2^min(cap_height, log2(H_r) − a_r).

## Layout

Notation: N instances; R FRI rounds; Q queries; L final-polynomial length; s salt elements (ZK only).

```
roots       trace cap                                        cap_len(trace) digests
            [any lookup] permutation cap                     cap_len(permutation)
            quotient cap                                     cap_len(quotient)
            [ZK] random cap                                  cap_len(random)
terminals   for each instance with L_i > 0: lookup terminal  1 ext
ood         for each instance i:
              trace_local[W_i]                               ext each   (at zeta)
              [opens_next] trace_next[W_i]                   ext each   (at zeta * g_i)
              [PW_i > 0] preprocessed_local[PW_i]            ext each
              [preprocessed_next] preprocessed_next[PW_i]    ext each
              quotient_chunks[C_i][3]                        ext each   (chunk k, base column j)
              [ZK] random[3]                                 ext each
              permutation_local[PE_i]                        ext each   (empty when L_i = 0)
              permutation_next[PE_i]                         ext each
pow         [any lookup and lookup_pow_bits > 0] lookup_pow_witness
            [ood_pow_bits > 0] ood_pow_witness
random      [ZK] for each PCS round, each matrix, each opening point: rc ext
            (opened values of the random codewords; the preprocessed round contributes 0 values)
pow         [batch_pow_bits > 0] batch_pow_witness
fri roots   for r < R: commit-phase cap                       fri_cap_lens[r] digests
pow         [commit_pow_bits > 0] commit_pow_witness[R]
final       final_poly[L]                                     ext each (coefficients, constant first)
pow         [query_pow_bits > 0] query_pow_witness
inputs      for each PCS round (order above):
              for q < Q: for each matrix m of the round: row[columns_m]      base each
              [ZK] for q < Q: for each matrix m: salt[s]                      base each
              siblings: digest list (pruned multiproof)
fri         for r < R (arity a_r = 2^log_arities[r]):
              for q < Q: sibling_values[a_r - 1]                              ext each
              [ZK] for q < Q: salt[s]                                         base each
              siblings: digest list
```

There must be no trailing bytes.

The encoder writes a `sections` list into every vector, with name, offset and length per section. The tamper
sweep and future tooling use it.

## Merkle trees (Plonky3 `MerkleTreeMmcs` / `MerkleTreeHidingMmcs`, binary, SHA-256)

**Leaf.** Leaf i = SHA-256 of the canonical u64-LE bytes of row i of every tallest matrix of the round, in
round order. Under ZK each matrix's row is followed by its own s salt elements: `row_m ‖ salt_m`. The
hiding MMCS commits `HorizontalPair(matrix, salts)`.

**Node.** Node = SHA-256(left ‖ right), via `CompressionFunctionFromHasher<Sha256, 2, 32>`.

**Injection (mixed heights).** At the digest layer whose width equals a shorter matrix group's height h,
node_i = SHA-256(SHA-256(left ‖ right) ‖ H(rows_i of that group)). H is the leaf hash above, including
salts.
- Within one height, matrices keep round order (stable sort, tallest first).
- A query at index idx in the tallest tree reads row `idx >> (log_max − log_h)` of a matrix of height 2^log_h.

**Leaf positions** are bit-reversed LDE positions (Plonky3's convention).

**FRI round-r leaf.** The a_r extension values of the coset, base-flattened. The folded value from the
previous round sits at slot `index mod a_r`; the other a_r − 1 come from `sibling_values`. ZK appends the
salt.

**Caps.** The paths stop at the cap layer. The final digest must equal `cap[index >> (layer height)]`.

**Pruned multiproof** (`PrunedMerklePaths`, same rules as p3s-v1):
1. Take the queried indices.
2. Drop duplicates. A duplicate must carry an identical leaf, else reject.
3. Walk level by level, by ascending index. Take each missing sibling from the list, in order.
4. The list must be consumed exactly.

## Transcript

The challenger is `SerializingChallenger64<Goldilocks, HashChallenger<u8, SHA-256, 32>>`, seeded by
batch-stark's domain separator (`batch-stark/src/transcript.rs`), so the first hash input starts with the
protocol seed.

Order:
1. degree_bits;
2. main commitment;
3. public values per instance;
4. preprocessed commitment;
5. if any lookup: lookup PoW, then lookup α, lookup β, the permutation commitment and the terminals;
6. constraint challenge α;
7. quotient commitment;
8. random commitment;
9. ood PoW, then ζ;
10. the PCS/FRI opening argument, inside its own bracket.

Every SHA-256 input the Rust verifier hashed for the challenger is in `transcript_hash_inputs`, as hex in
call order. S3 compares the JS transcript against it byte for byte.

**Not bound by batch-stark's transcript:**
- the periodic columns (only multi-stark binds `periodic_statement`);
- commitment widths.

Both are verifying-key constants in our generator.

## Constraint DAG (`dag[i]` in each vector)

The DAG covers each instance's AIR constraints plus its LogUp constraints. It is built exactly as the
verifier builds them (`p3_batch_stark::symbolic::get_symbolic_constraints` and `get_constraint_layout`, with
`LogUpGadget`). It is hash-consed into one node table, where each node refers only to earlier nodes.

| op | meaning |
|---|---|
| `main` {row, col} | trace value: row 0 is at ζ, row 1 at ζ·g |
| `pre` {row, col} | preprocessed value |
| `periodic` {col} | periodic column col evaluated at ζ. The values over one period are in `periodic_columns`. |
| `public` {col} | public value |
| `is_first_row`, `is_last_row`, `is_transition` | Plonky3 selectors at ζ (`selectors_at_point`) |
| `const` {v} | base constant, decimal string |
| `perm` {row, col} | extension permutation column col (the ext element recomposed from 3 opened base-flattened values) |
| `challenge` {col} | per-instance permutation challenge |
| `perm_value` {col} | the instance's lookup terminal |
| `ext_const` {v[3]} | extension constant |
| `add`, `sub`, `mul` {a, b}; `neg` {a} | arithmetic; `node_is_ext[k]` says whether node k is extension-valued |

`constraints` lists the constraints in Plonky3's global emission order. Each entry is {node, field: base|ext}.

**Fold:** acc = Σ_{i<K} α^(K−1−i)·C_i (Horner: acc ← acc·α + C_i). The check is
acc · inv_vanishing(ζ) = quotient(ζ), where quotient(ζ) is recomposed from the chunks
(`recompose_quotient_from_chunks`).

`lookups` is Plonky3's serde of the instance's `Lookups`: kind, bus, element tuples and multiplicities as
symbolic trees.

`dag_row_check` records a self-check of the export:
- every base constraint of the exported DAG evaluates to 0 on every row of the valid trace;
- after one trace cell is changed (row 1, column 0), the same rows give a nonzero value.

The LogUp (extension) constraints are not covered by this check. Their correctness is established only by
`verify_batch` accepting, and the DAG's LogUp part is first evaluated independently in S3.

## Vector JSON (`vectors/<set>/<case>-<set>.json`)

| field | meaning |
|---|---|
| `format`, `plonky3_rev` | `"p3b-v1"`, the pin |
| `case`, `plonky3_test` | the Plonky3 batch test this reconfigures |
| `airs`, `log_heights`, `shift` | the tables. Heights are Plonky3's heights × 2^shift. |
| `seed` | seed of the hiding RNGs: salts and random codewords. **Test vectors only**; production uses OS randomness. |
| `set` | parameter set: FRI, PoW (batch, commit, query, ood, lookup), zk, rc, salt, cap_height |
| `shape` | as above |
| `public_values` | per instance, decimal strings |
| `preprocessed_commitment` | VK cap (Plonky3 serde), or null |
| `proof_hex`, `sizes`, `sections` | proof bytes, byte count per kind, section map |
| `prove_ms`, `rust_verify_ms` | measured with RAYON_NUM_THREADS=4, under nice |
| `rust_verify`, `decode_encode_identity` | Plonky3's verdict on the decoded bytes, and whether the serde tree is identical |
| `dag`, `dag_row_check` | see above |
| `tamper_sweep`, `tampered` | rejection cases, each `{name, patch?: [{at, hex}], insert?: {at, hex}, truncate?: n}`; see README |
| `transcript_hash_inputs` | hex of every challenger SHA-256 input, in order |

## CTX serialization (M1/M2 public values CTX[0..4]; fixed by the S4 generator)

AIR-SPEC §3.1 leaves the exact output serialization to the generator. The layout (b) script
(`../onchain/ctx.mjs`) recomputes CTX by introspection of the spending transaction, so a proof is bound to the
transaction's outputs:

```
ser   = u32 LE output count
        ‖ for each output, in order:
            value          u64 LE                 OP_OUTPUTVALUE
            category       u8 length ‖ bytes      OP_OUTPUTTOKENCATEGORY (0, 32 or 33 bytes, capability byte included)
            commitment     u16 LE length ‖ bytes  OP_OUTPUTTOKENCOMMITMENT
            token amount   u64 LE                 OP_OUTPUTTOKENAMOUNT (0 without fungible tokens)
            locking        u32 LE length ‖ bytes  OP_OUTPUTBYTECODE
h     = SHA-256(ser)
CTX_k = little-endian integer of h[7k .. 7k+7), k = 0..3   (each < 2^56)
```

Every field is fixed-length or length-prefixed, so `ser` is injective in the introspectable content of the
outputs. The transcript observes CTX_k as u64 LE, i.e. the bytes h[7k .. 7k+7) ‖ 0x00, which the script builds
directly. The prover takes the hash as a fourth case component: `m1@LEAF@WSEED@<h as 64 hex chars>` (and `m2@...`).
`../onchain/test-ctx.mjs` checks the script block against this definition on plain, token (FT, NFT with and without
capability, 128-byte commitment) and long-bytecode outputs.

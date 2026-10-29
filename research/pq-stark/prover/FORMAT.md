# p3s-v1: byte format for Plonky3 uni-stark proofs (SHA-256, Goldilocks)

This is the canonical serialization the CashVM verifier reads. The encoder is `src/wire.rs`, which works
from Plonky3's serde tree of `Proof<SC>` at the pinned commit `0d803737b681774186cd283b1fd2d8e493655c82`.
The independent parser is `parse()` in `verify.mjs`. `pq-stark-prover check` decodes these bytes back
into Plonky3's proof type and runs Plonky3's own verifier on them, so the format round-trips.

The format has no self-describing lengths except Merkle sibling counts. Every other length comes from
the **shape**. The shape is fixed by the verifying key: AIR, log n, and parameter set. Each vector
carries it as `shape`, and the verifier rebuilds it with `makeVk()`.

## Primitives

| item | encoding |
|---|---|
| base element (Goldilocks, p = 2^64 - 2^32 + 1) | 8 bytes little-endian; **must be canonical (< p)**, else reject |
| extension element (degree D = 2 or 3) | D base elements, coefficient of u^0 first |
| digest | `h` bytes (h = 32, or 25 for the truncated `C100h`/`P100` sets) |
| digest list | u16 LE count, then `count` digests |

The extension fields are those Plonky3 ships:
- D = 2: `BinomialExtensionField<Goldilocks, 2>`, u^2 = 7.
- D = 3: `CubicTrinomialExtensionField<Goldilocks>`, u^3 = u + 1.

## Layout

Notation:
- W: trace width (Fib 2, MiMC 3).
- C: quotient chunks.
- R: number of FRI commit rounds, `= len(log_arities)`.
- Q: queries.
- L: final-polynomial length.
- rc: random codewords (ZK only).
- s: salt elements (ZK only).

In order:

```
header        degree_bits                      1 byte   (= log n, or log n + 1 in ZK mode)
roots         trace_root                       h
              quotient_root                    h
              [ZK] random_root                 h
ood           trace_local[W]                   W   ext   (at zeta)
              trace_next[W]                    W   ext   (at zeta * g)
              quotient_chunks[C][D]            C*D ext   (chunk i, base column k, at zeta)
              [ZK] random[D]                   D   ext   (random polynomial, at zeta)
              [ZK] random-codeword values      per input batch b, per matrix, per opening point: rc ext
                                               (batches in order random, trace, quotient; trace has 2 points)
pow           [batch_pow_bits > 0] batch_pow_witness           base
fri commits   commit_root[R]                   R*h
pow           [commit_pow_bits > 0] commit_pow_witness[R]       R base
final         final_poly[L]                    L ext    (coefficients, constant term first)
pow           [query_pow_bits > 0] query_pow_witness           base
inputs        for each input batch b (non-ZK: trace, quotient; ZK: random, trace, quotient):
                for q < Q: for each matrix m of b: row[width_m]      base each
                [ZK] for q < Q: for each matrix m of b: salt[s]       base each
                siblings: digest list (pruned multiproof, see below)
fri openings  for each round r < R (arity a_r = 2^log_arities[r]):
                for q < Q: sibling_values[a_r - 1]                   ext each
                [ZK] for q < Q: salt[s]                               base each
                siblings: digest list
```

There must be no trailing bytes. Matrix widths per input batch are in `shape.batch_widths`:
- non-ZK: `[[W], [D, D, ...C times]]`.
- ZK: `[[D+rc], [W+rc], [D+rc, ...C times]]`.

The quotient chunks are EF-valued, so they are committed as D base columns each. Under ZK every committed
matrix also carries rc random columns.

## Merkle trees (as Plonky3 `MerkleTreeMmcs`, binary, cap height 0)

- **Leaf** = SHA-256 of the concatenated canonical u64-LE bytes of the rows of every matrix in the batch
  at that index (`SerializingHasher<Sha256>`), with the salt appended in ZK mode. It is truncated to h bytes.
  - FRI round r leaf = the a_r extension values of the coset (the folded value from the previous round
    sits at slot `index mod a_r`; the other a_r - 1 come from `sibling_values`).
- **Node** = SHA-256(left || right), truncated to h bytes (`CompressionFunctionFromHasher<Sha256, 2, h>`). It
  is *not* `p3_sha256::Sha256Compress`, which is the raw unpadded compression function that `OP_SHA256`
  cannot compute.
  - h = 25 is not a stock Plonky3 hasher. It is a 30-line wrapper (`TruncSha256<H>` in `src/cfg.rs`) that
    plugs into the same generic `MerkleTreeMmcs`.
- Leaves are at LDE positions in bit-reversed order (Plonky3's convention).
  - The input trees have height logH = degree_bits + log_blowup.
  - The FRI round-r tree has height logH - sum_{j<=r} log_arities[j].
- No per-tree tags. The depth and leaf length are fixed by the shape.

**Pruned multiproof (Plonky3 `MalformedPrunedProof` semantics).**
1. Take the queried indices.
2. Drop duplicates. A duplicate must carry an identical leaf, else reject.
3. Walk level by level, ascending index. For each parent, take each child either from the known
   frontier or, if absent, from the sibling list, in order.
4. The list must be consumed exactly. Too few or too many siblings is a rejection.

## Vector JSON (`vectors/<air>-<set>[-zk|-zkmin]-<k>.json`)

| field | meaning |
|---|---|
| `format` | `"p3s-v1"` |
| `plonky3_rev` | pinned commit |
| `air`, `log_n`, `k` | statement: AIR (`fib` / `mimc`), trace height 2^log_n, statement variant k |
| `public_values` | decimal strings (Fib: a, b, out; MiMC: x_in, y_out) |
| `set` | FRI parameters: `ext`, `log_blowup`, `num_queries`, `query_pow_bits`, `commit_pow_bits`, `batch_pow_bits`, `max_log_arity`, `log_final_poly_len`, `digest`, `zk`, `num_random_codewords`, `salt` |
| `shape` | the derived layout above (the verifier recomputes it and must match) |
| `proof_hex` | the proof bytes |
| `sizes` | byte count per section |
| `plonky3_security_estimates` | Plonky3's own estimators (`p3-uni-stark security.rs`): conjectured, legacy, proven list-decoding (`proven_ldr_bits`), proven unique-decoding |
| `prove_ms`, `rust_verify`, `rust_verify_ms` | prover time (24-thread laptop) and Plonky3's verdict |
| `transcript_hash_inputs` | hex of every SHA-256 input of the Fiat-Shamir challenger, recorded inside the Rust verifier (`verify.mjs --trace` compares them byte for byte) |
| `debug_separators` | the three domain-separator patterns and seeds (stark, pcs, fri) |
| `tampered` | (`-0` vectors only) rejection cases: `{name, patch?: [{at, hex}], insert?: {at, hex}, truncate?: n, public_values?}`, applied in that order to the valid proof (`applyTamper` in verify.mjs); all must be rejected |

`vectors/summary.json` is one row per vector. `vectors/stats.json` has the hash calls, bytes and SHA-256
iterations by role (transcript, Merkle leaf, Merkle node) for the main vectors. `vectors/js-verify.txt` and
`vectors/rust-check.txt` hold the per-case verdicts of the two verifiers.

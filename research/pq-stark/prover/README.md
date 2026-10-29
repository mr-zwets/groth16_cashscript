# pq-stark prover: Plonky3 uni-stark with SHA-256 over Goldilocks

Track 5, Prover phase. This is research, not a leaderboard entry.

This crate produces proofs from a real, configurable STARK prover in a form a CashVM verifier can check.
- Prover: Plonky3 `p3-uni-stark`, pinned to commit `0d803737b681774186cd283b1fd2d8e493655c82` (2026-10-26).
- Hash: SHA-256 for every hash.
- Field: Goldilocks, with a degree-2 or degree-3 extension.
- AIRs: two (Fibonacci and a MiMC round chain).
- Modes: plain and zero-knowledge.

The byte format is in [FORMAT.md](FORMAT.md). The independent JS reference verifier is [verify.mjs](verify.mjs),
which is the spec the on-chain verifier follows.

## Result in one paragraph

Plonky3 can be configured with SHA-256 everywhere using only stock components:
- Merkle leaves: `SerializingHasher<Sha256>`.
- Merkle nodes: `CompressionFunctionFromHasher<Sha256,2,32>`.
- Fiat-Shamir and grinding: `SerializingChallenger64<Goldilocks, HashChallenger<u8, Sha256, 32>>`.
- Field: Goldilocks with `BinomialExtensionField<_,2>` or `CubicTrinomialExtensionField` (degree 3).

Every SHA-256 call is an ordinary padded SHA-256 of a byte string, so `OP_SHA256` computes all of them.
Plonky3's `HidingFriPcs` gives a working ZK mode for uni-stark at this commit.

For 45 valid proofs plus 1,114 tampered variants (1,159 cases), the independent JS verifier and Plonky3's
own verifier agree on every verdict. Every SHA-256 transcript input of the JS verifier matches, byte for
byte, the one recorded inside Plonky3's verifier.

The protocol is suitable, at a size cost against Track 4's hand-rolled DEEP-ALI:
- With Track 4's own parameters, a Plonky3 proof is 16-21% larger.
- With Plonky3's larger arity, larger blowup and PoW knobs, a 128-bit (Plonky3 proven-LDR estimator)
  MiMC proof is **78.4 KB**, smaller than Track 4's 91.5 KB P128.

ZK costs +44% to +70%.

## Build and regenerate

```
cargo build --release                 # Rust 2024 edition, pinned Plonky3 git deps
./gen-vectors.sh                      # prove all sets, add tampered cases, check with JS and Plonky3
node verify.mjs vectors/*.json        # -> js verify: 1159 cases, 0 unexpected
./target/release/pq-stark-prover check vectors/*.json   # -> rust check: 1159 cases, 0 unexpected
./target/release/pq-stark-prover sets  # Plonky3's security estimators per set
```

Sources:
- `src/cfg.rs`: configurations.
- `src/airs.rs`: AIRs.
- `src/sets.rs`: parameter sets and estimators.
- `src/wire.rs`: p3s-v1 encoder and decoder.
- `src/main.rs`: the `prove`, `check` and `sets` CLI.
- `gen-tampered.mjs`: rejection cases.
- `summary.mjs`: summary table.

## AIRs

- **fib** (W = 2, 3 publics a, b, out): first-row a, b; transition (x', y') = (y, x + y); last-row y = out.
  Its constraints have degree 2, so it has 1 quotient chunk.
- **mimc** (W = 3, publics x_in, y_out): the Track 4 statement, MiMC-7 with 8 periodic round constants.
  - The constants are the same as Track 4 (`SHA256("verifier.cash/pq-hash/rc" || j) mod p`).
  - Columns (x, a = s^3, b = a^2) with s = x + c(i), next x = b * s.
  - Its constraints have degree 3, so it has 2 quotient chunks.
  - The periodic column uses Plonky3's periodic-column support. The verifier interpolates it over the
    size-8 subgroup at zeta^(n/8).
- Trace height n = 2^16 for all vectors, like Track 4.

## Parameter sets and measured proof sizes (n = 2^16, bytes)

`bits` is Plonky3's own estimator at this commit (`p3-uni-stark/src/security.rs`):
- conj: conjectured (ethSTARK-style).
- LDR: proven, list-decoding regime (Johnson bound, per-round).
- UDR: proven, unique decoding.

The Soundness phase's own per-round bound is in its handoff. The S-sets below are its picks. All sets
use SHA-256 digests of 32 bytes unless `h` says otherwise.

| set | D | blowup | queries | PoW (query/commit/batch) | arity | final len | h | conj / LDR bits | fib | mimc |
|---|---|---|---|---|---|---|---|---|--:|--:|
| C100 | 2 | 2^3 | 27 | 21/0/0 | 8 | 32 | 32 | 100 / 61 | 56,693 | 56,893 |
| C100h | 2 | 2^3 | 27 | 21/0/0 | 8 | 32 | 25 | 100 / 61 | 46,686 | 47,498 |
| C128 | 3 | 2^3 | 36 | 22/0/0 | 8 | 32 | 32 | 128 / 75 | 79,677 | 81,717 |
| P100 (Track 4 shape) | 3 | 2^7 | 22 | 28/0/0 | 8 | 32 | 25 | 100 / 100 | 58,259 | 58,183 |
| P128 (Track 4 shape) | 3 | 2^5 | 43 | 28/0/0 | 8 | 32 | 32 | 128 / 128 | 108,213 | 110,765 |
| S100 | 3 | 2^5 | 30 | 27/0/0 | 8 | 128 | 32 | 128 / 101 | 74,779 | 76,019 |
| S100b | 3 | 2^8 | 19 | 25/0/0 | 16 | 256 | 32 | 128 / 100 | 59,809 | 60,793 |
| **S128** | 3 | 2^8 | 26 | 26/15/23 | 16 | 256 | 32 | 128 / 128 | 78,337 | **78,393** |
| S128b | 3 | 2^5 | 41 | 28/7/14 | 8 | 128 | 32 | 128 / 128 | 97,659 | 99,795 |

Notes on the table:
- `C*` are "conjectured" sets, for comparison only.
- `P*` reuse Track 4's blowup, queries and PoW in Plonky3's protocol.
- The P100 vectors use h = 25 like Track 4.
- A second MiMC statement per set (`mimc-<set>-1.json`) differs by at most a few hundred bytes. The
  multiproof size depends on index collisions.

**Comparison with Track 4** (same statement, n = 2^16):
- Track 4 P100: 50,022 B. Plonky3-P100: 58,183 B (+16%).
- Track 4 P128: 91,468 B. Plonky3-P128: 110,765 B (+21%).
- Plonky3-S128: 78,393 B (-14%), from:
  - arity 16 and blowup 2^8, so fewer queries;
  - query PoW 26 bits, plus commit-round PoW 15 bits and batch PoW 23 bits.

  The PoW grinding is a prover cost only (S128 proves in about 1.9 s).

### Zero-knowledge (HidingFriPcs)

Plonky3 at this commit has `HidingFriPcs` + `MerkleTreeHidingMmcs`, and uni-stark supports it (`config.is_zk()`).
In ZK mode:
- the trace is randomized and committed over 2n rows (degree_bits = log n + 1);
- a random polynomial is committed and opened at zeta;
- every committed matrix gets `rc` random codewords (extra columns), opened at the same points;
- every Merkle leaf, including FRI leaves, gets an `s`-element random salt;
- the quotient has 4x as many chunks (Fib 4, MiMC 8).

Two variants were measured:
- `-zk`: Plonky3's test defaults, rc = 4 and s = 4.
- `-zkmin`: the smallest that keeps the hiding argument, rc = D and s = 2 (a 128-bit salt).

| set | fib plain -> zkmin (zk) | mimc plain -> zkmin (zk) |
|---|---|---|
| C100 | 56,693 -> 81,111 (89,943) +43% | 56,893 -> 89,423 (100,303) +57% |
| C128 | 79,677 -> 121,431 (127,839) +52% | 81,717 -> 128,135 (143,567) +57% |
| P100 | 58,259 -> 98,055 (102,127) +68%* | 58,183 -> 102,695 (110,767) +77%* |
| P128 | 108,213 -> 158,751 (165,943) +47% | 110,765 -> 175,047 (188,607) +58% |
| S100z (Soundness ZK pick) | 85,853 | (not generated) |
| S128z (Soundness ZK pick) | 112,501 | (not generated) |

\* In the P100 rows, the plain proof uses 25-byte digests and the hiding MMCS uses 32-byte digests.

Where the bytes go (mimc P128 -> zkmin):
- input leaves +17.5 KB (rc columns and 8 chunks);
- salts +9.6 KB;
- input siblings +25.7 KB (one tree deeper, plus a third input tree);
- FRI +10 KB (one extra fold, plus salts);
- OOD +1.3 KB.

The only extra verifier logic for ZK:
- one more root and one more input batch;
- the random-codeword values appended to each claim;
- salts appended to leaf preimages;
- a quotient domain of 2x the size.

## The protocol, as verify.mjs implements it

1. **Domain separators.** Plonky3's `fs` module defines three seeds: `p3-uni-stark`, `p3-fri-pcs` and
   `p3-fri`.
   - Each seed is a 64-byte id, then Keccak-256 of a rendered interaction pattern, then a length-prefixed
     label of the shape parameters, then `0x80`.
   - Each seed is observed as a length followed by 7-byte little-endian chunks, one field element each.
   - All three depend only on the verifying key, so the CashVM verifier can bake them as constants (no
     Keccak on chain). The seeds are 149-197 bytes, which become about 180-235 transcript bytes each.
2. **Challenger.** It is one running SHA-256 `HashChallenger`.
   - `observe` appends bytes to an input buffer and clears the output buffer.
   - Sampling flushes when the output is empty: digest = SHA256(input buffer), and the digest becomes
     both the new input buffer and the output buffer.
   - Bytes are popped from the end of the digest.
   - A base sample is 8 popped bytes read little-endian, rejected and resampled if it is >= p.
   - An extension sample is D base samples.
   - Query indices are the low logH bits of a u64 sample.
3. **uni-stark.** The order is:
   1. seed(stark);
   2. observe the trace root, then the public values (u64 LE each);
   3. sample alpha (EF);
   4. observe the quotient root, then the random root (ZK);
   5. sample zeta (EF).

   The verifier rejects if zeta^n = 1 (and in ZK if zeta^(2n) = 1).
4. **PCS.** The order is:
   1. seed(pcs);
   2. observe every claimed evaluation, in the claim order: [random], trace at zeta, trace at zeta*g,
      then the quotient chunks at zeta (with the rc random-codeword values appended under ZK);
   3. batch PoW;
   4. sample alpha'.

   Then the reduced opening at query point x is the sum over claims of alpha'-power-weighted
   (sum(z) - sum(x)) / (z - x). The powers of alpha' run continuously across all opened values.
5. **FRI.** The order is:
   1. seed(fri);
   2. per round: observe the commit root, commit PoW, sample beta_r;
   3. observe the final polynomial;
   4. query PoW;
   5. sample Q indices of logH bits.

   For each query:
   - Check the Merkle multiproofs of the input batches.
   - Compute the reduced opening at x = 7 * g_H^rev(index).
   - Fold through the rounds. Each round:
     - the leaf is the coset of a_r values (the previous value at slot `index mod a_r`);
     - the fold is the value at beta_r of the degree < a_r interpolant through the coset points
       g^rev(...) (the coset shift 7 is absorbed into the polynomial);
     - then `index >>= log a_r`.
   - Compare the result with the final polynomial at g_final^rev(index).
   - Check the FRI multiproofs, one per round, over the grouped indices.
6. **AIR check at zeta.**
   - Constraints are folded by Horner in alpha, in `eval()` order.
   - Selectors are unnormalized, as in Plonky3:
     - first = Z_H(zeta)/(zeta - 1);
     - last = Z_H(zeta)/(zeta - g^-1);
     - transition = zeta - g^-1.
   - The verifier requires folded / Z_H(zeta) = quotient(zeta). The quotient is rebuilt from the C chunk
     openings with Plonky3's vanishing-ratio recombination over C disjoint cosets 7 * g_Q^i, and each
     chunk is the sum of e_k * u^k over its D base columns.

## Where Plonky3 differs from Track 4's DEEP-ALI

| aspect | Track 4 (pq-hash) | Plonky3 uni-stark at 0d80373 | CashVM impact |
|---|---|---|---|
| constraint batching | 4 independent alpha_j | powers of one alpha (Horner) | fewer squeezes; soundness loses (#constraints)/|EF|, negligible |
| quotient | H = H0 + X^n H1 on one domain, recombined with z^n | C chunks on disjoint cosets, recombined with vanishing-polynomial ratios (C^2 small ops) | a few more EF ops at zeta, one-off |
| zeta restriction | z not in F_p | only zeta^n != 1; z != x is checked per query | per-query check, or bake z not in F_p as a stricter rule (honest proofs fail it with prob 2^-128) |
| DEEP batching | 5 independent gamma_j | powers of one alpha' across all opened values (and across batches) | one squeeze; batching error grows to (#values)/|EF| |
| opening points | z, omega*z | zeta, zeta*g (same) | same |
| committed leaves | trace and composition leaves hold k0 = 4-point cosets, so the first fold is done straight from them | one LDE row per leaf; the DEEP codeword f0 gets its **own** FRI tree (round 0) | one extra full-height tree per proof; 7 extra EF values + about 1 path per query: the main reason for +16-21% |
| leaf hash | SHA256(tag \|\| bytes) | SHA256(u64-LE bytes), no tag; ZK appends a salt | about 100 op per leaf saved |
| node hash | SHA256(l \|\| r)[0:h] | same (h = 32 stock; h = 25 via a small wrapper) | same |
| fold arity | 4, 8, 8 | max_log_arity, then the remainder (8,8,8,4 or 16,16) | same kernel family; the fold is Lagrange at beta (equivalent to IDFT + Horner) |
| folding domain | shifted cosets 7*<w> | unshifted subgroup per round (shift absorbed) | slightly simpler x0 per round |
| final polynomial | 256 coefficients | 2^lf coefficients (32 for C/P sets, 128-256 for S sets) | smaller final poly means less Horner and fewer transcript bytes |
| Fiat-Shamir | chained t_i = SHA256(t_{i-1} \|\| msg), challenge = 256-bit digest mod p^3 | running buffer challenger with seeds, 8-byte rejection-sampled limbs popped from the digest end | about 2-8 KB transcript input (S sets: final poly 6 KB); 0.5 of 32 bytes per EF limb; 4 query indices per SHA call |
| query sampling | coset index in L1, mod N/k0 | low logH bits per index, position in the full LDE | equivalent |
| PoW | top g bits of SHA256(t6 \|\| nonce) zero | squeeze 1 byte, observe the 8-byte witness, low g bits of the next u64 zero; optional per-commit-round and batch PoW | 1-3 extra SHA calls per PoW |
| encodings | no range checks | canonical (< p) enforced on every element | one compare per element (or drop it on chain; Plonky3's own decoder enforces it, so keep it for exact agreement) |
| extension | u^3 = 7, u^2 = 7 | u^3 = u + 1 (trinomial), u^2 = 7 | the trinomial reduction is additions only, a little cheaper |
| ZK | none | HidingFriPcs (see above) | +44-77% bytes |

## Hash cost profile (vectors/stats.json, SHA-256 iterations)

| vector | transcript (calls / bytes / iters) | Merkle leaf iters | Merkle node iters |
|---|---|--:|--:|
| mimc-P100 (h = 25) | 14 / 2,302 / 46 | 352 | 1,834 |
| mimc-P128 | 19 / 2,504 / 51 | 688 | 5,606 |
| mimc-S128 | 16 / 7,720 / 130 | 416 | 3,400 |
| mimc-S100b | 11 / 7,536 / 125 | 304 | 2,592 |
| fib-S128z-zkmin | 18 / 8,600 / 144 | 546 | 5,364 |

The extension-multiplication counts in stats.json come from the unoptimized reference verifier. They are
upper bounds, not a CashVM cost model.

## What did not work or is limited

- `p3_sha256::Sha256Compress` (the obvious "SHA-256 compression" choice) is the raw compression function
  without padding. CashVM cannot compute it, so it must not be used. `CompressionFunctionFromHasher` is
  the right choice.
- Plonky3 has no `BinomialExtensionField<Goldilocks, 3>`: Goldilocks implements `BinomiallyExtendable` for degrees 2 and 5 only. The stock cubic is the trinomial u^3 - u - 1.
  - The Soundness phase's analysis assumed a binomial u^3 - 7. The bound depends only on |EF| = p^3, so
    the numbers carry over.
  - The verifier must still use the trinomial.
- 25-byte digests need a small custom hasher type, which is not stock. The hiding MMCS here is used only
  with 32-byte digests.
- `verify.mjs` covers what these AIRs use:
  - one trace, no preprocessed columns, no lookups;
  - all committed matrices of the same height (one FRI ladder, so no reduced-opening roll-ins);
  - uni-stark only (no multi-STARK batch).

  A different AIR with mixed heights would need the roll-in step.
- The batched-opening and constraint batching use powers of one challenge. Any soundness bound must
  include the (#values)/|EF| batching term, which is about 2^-185 at D = 3 and negligible. A per-round
  bound from Track 4's independent-challenge analysis does not apply verbatim.

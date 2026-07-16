# Grouped verifier (multi-tx, multi-input, standard-relayable)

A THIRD chunking method for the BN254 Groth16 verifier, a hybrid of the other two:

- **Covenant** (`chunked/pairing`, `bch-groth16-chunked`): one sequential transaction per
  chunk; larger layouts can approach or exceed BCH's default 50-transaction mempool-chain edge.
- **Intra-tx** (`chunked/intratx`, `bch-groth16-intratx`): the whole verifier in one
  transaction; large layouts exceed the 100,000-byte standard size, while the optimized BN254
  quotient construction fits.
- **Grouped** (this dir, `bch-groth16-grouped`): packs one chunk graph into a handful of standard
  transactions, remaining under both the transaction-size and chain-depth limits.

## Mechanism

- **Within a group tx:** chunks forward-check each other via `tx.inputs[idx+1].unlockingBytecode`
  (OP_INPUTBYTECODE), identical to the intra-tx method.
- **Across groups:** the running state rides a CashToken NFT commitment (covenant method). A
  group's last chunk commits `hash256(outBlob)` to `output[0]` (covout); the next group's first
  chunk binds its `inBlob` via `require(tx.inputs[0].nftCommitment == hash256(inBlob))`
  (covInHash). The token thread chains all groups in order (group k+1 spends group k's token);
  the terminal group burns it.
- **Boundaries** sit only at within-stage links that carry the full state unchanged
  (`outLimbs[i] == inLimbs[i+1]`), so the stage-internal cross/terminal binding stays inside one
  group and is preserved bit-for-bit from the intra-tx build.

## Files

- `build_vectors_bls.mjs` — the BLS12-381 counterpart (W=48). Same grouping/assembly logic;
  swaps in the BLS spec builders (five-chunk shared-table GLV vk_x + input-validated prepared Miller +
  final exponentiation with uncommitted easy-part-inverse witnesses) and emits
  `groth16-bls12381-grouped-vectors.json`.
- `build_vectors.mjs` — packs the chunks into groups (target 90 KB, cut only between within
  chunks), assigns the grouped role per chunk (covInHash / covout / forward / terminal), compiles
  + tunes each group's per-input pad, and emits `verifier/src/bch/groth16-grouped-vectors.json`
  (valid + extraValidProofs + worstCaseProof + invalid, each carrying per-group token config).
- The chunk MATH is reused verbatim from `chunked/pairing/generated/*.cash`; the grouped
  prologue/epilogue swap lives in `chunked/intratx/transform.mjs` (`covInHash` / `epilogueMode`
  options). The BN254 build requires the STAGE-BOUND layouts (regenerate `gen_g2check.mjs` and
  `gen_miller.mjs` with `STAGE_BOUND_LAYOUT=1` first) and keeps the G2-final -> Miller-genesis
  proof binding inside one group. Run: `node chunked/grouped/build_vectors.mjs`.

## Result (benchmark `bch-groth16-grouped`)

42 inputs / **5 transactions**, 328,458 script B / 330,628 score B, and 261,496,203 op-cost.
Every step fits the current BCH per-input limits and every group passes standard policy. One fixed
locking graph accepts multiple runtime proofs.

The plain BLS12-381 entry (`bch-groth16-bls12381-grouped`) is 56 inputs / **6 transactions**,
475,292 script B / 478,150 score B, and 377,556,467 op-cost. Every group passes standard policy.
Its five GLV inputs remain together in group 0 so four siblings can read the one hash-bound VK
table carried by the fifth.

The quotient-residue BLS entry (`bch-groth16-bls12381-grouped-residue`) is 26 inputs in **3 standard
transactions**, 204,424 script B / 205,734 score B / 204,894 wire B, and 160,953,436 op-cost. Its
cross-transaction state thread requires a mutable NFT, excludes same-category sibling inputs, and
requires the terminal transaction to burn the thread token.

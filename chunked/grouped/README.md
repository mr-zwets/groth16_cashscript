# Grouped verifier (multi-tx, multi-input, standard-relayable)

A THIRD chunking method for the BN254 Groth16 verifier, a hybrid of the other two:

- **Covenant** (`chunked/pairing`, `bch-groth16-chunked`): 54 sequential transactions, one
  chunk each → a 54-deep unconfirmed chain that exceeds BCH's default mempool ancestor/
  descendant limit (50).
- **Intra-tx** (`chunked/intratx`, `bch-groth16-intratx`): the whole verifier in ONE
  transaction → ~0.5 MB, over the 100,000-byte standard size, so it is non-standard
  (mine-direct).
- **Grouped** (this dir, `bch-groth16-grouped`): the SAME 54 chunks packed into **~6 standard
  (<100,000 B) transactions** → under the chain limit AND relayable under standard policy.

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
  swaps in the BLS spec builders (g2check + vk_x + batched 4-R Miller + final exponentiation with
  uncommitted easy-part-inverse witnesses) and emits `groth16-bls12381-grouped-vectors.json`.
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

54 inputs / **6 transactions**, ~446 KB total, op-cost 348 M (worst-case 391 M, accepted),
every step ≤ 8,032,800 op / ≤ 10 KB, every group < 100,000 B. PASS, **standard-relayable**,
runtime-general (2/2 proofs), invalid runs rejected. The only full Groth16 verifier that is both
standard-relayable and within the mempool chain limit.

The BLS12-381 entry (`bch-groth16-bls12381-grouped`) is 87 inputs / **9 transactions**, ~711 KB
total, op-cost 552 M, every group < 100,000 B — likewise standard-relayable and ~9 deep.

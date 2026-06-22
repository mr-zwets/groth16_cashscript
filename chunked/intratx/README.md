# Intra-transaction linked chunks (the single-transaction verifier)

A second way to chunk the Groth16 verifier, alternative to the sequential
NFT-commitment covenant in [`../pairing`](../pairing) and [`../bls12-381`](../bls12-381).

## The idea

The covenant method spreads the computation over a **chain of transactions** and hands
state forward through a token NFT commitment: each step stores `hash256(state)` in the
commitment (32 bytes), re-provides the full state in the next transaction's witness,
re-hashes it, runs one chunk, and commits `hash256(newState)` to its output. State is
capped at 128 bytes (hence the hash), and the steps are strictly sequential
(one block-or-mempool hop each).

This method instead lays the **whole computation out as the inputs of ONE transaction**.
Inputs of a transaction are validated independently and in parallel, but a script can
*read its siblings' witnesses* by introspection (`OP_INPUTBYTECODE` =
`tx.inputs[i].unlockingBytecode`). So a chunk can pass its result to the next chunk by
having the next chunk **read it** — no state token, no hashing, and intermediate values
can be any size:

```
chunk i:   take inBlob (incoming state) in the witness
           recompute outgoing state
           require( outgoing == tx.inputs[i+1].unlockingBytecode[front slice] )   // forward-check
chunk i+1: take inBlob (== chunk i's outgoing) in the witness, ...
```

That `require` is exactly the "verify `arg01 == arg10`" from the design discussion: a
chunk binds the chain by checking that its successor's argument equals its own output,
as a raw byte comparison. The first chunk of a stage is genesis (no predecessor binds
it); the last chunk asserts the verdict (`finalExp == 1`). Cross-stage soundness links
are bound where the byte layouts line up: the **vk_x** point is bound into the Miller
genesis input, and the **Miller boundary** into the final-exponentiation genesis input.

Each input still has to fit one BCH input's budget (op-cost ≤ 8,032,800, script
≤ 10,000 B), so the *chunking* is identical to the covenant version — these scripts
reuse the exact same validated chunk math. What changes is the packaging: ~60–84 inputs
in a single **non-standard (< 1 MB) transaction** instead of ~60–84 sequential standard
transactions, with no per-step hashing and no 128-byte state limit.

## Files

- `transform.mjs` — rewrites a covenant chunk (`../{pairing,bls12-381}/generated/*.cash`)
  into a linked chunk: the `covIn` hash check becomes `split` the `inBlob` into int
  limbs; the `covOut` commitment becomes rebuild the outgoing blob + the forward-check.
  The arithmetic body in between is reused verbatim. Curve-agnostic (`W` = limb width).
- `build_vectors.mjs` — BN254: assembles the Miller boundary (`bch-pairing-intratx`) and
  the full verifier (`bch-groth16-intratx`) into one-transaction vectors, evaluates every
  input on the real BCH 2026 VM, and writes `verifier/src/bch/{pairing,groth16}-intratx-vectors.json`.
- `build_vectors_bls.mjs` — BLS12-381 counterpart (`bch-pairing-bls12381-intratx`,
  `bch-groth16-bls12381-intratx`); 48-byte limbs, the easy-part inverse rides as an
  uncommitted witness.

Run (after the corresponding `../{pairing,bls12-381}` generators have populated
`generated/`):

```
node build_vectors.mjs       # BN254  -> pairing-intratx + groth16-intratx vectors
node build_vectors_bls.mjs   # BLS    -> pairing-bls12381-intratx + groth16-bls12381-intratx
```

## Harness support

The benchmark harness (`verifier`) gained a `Step.intraTx { index, inputs }` context: a
step is one input of a shared multi-input transaction, evaluated against a tx built from
every input's `(locking, unlocking)` so its `tx.inputs[idx±1]` introspection resolves to
the real siblings (see `verifier/src/harness/vm.ts`). The four entries are classified
`structure: 'single-tx'` (they are one transaction) and run runtime-general (one fixed
set of input scripts verifies multiple proofs) with invalid runs that corrupt one input's
blob (the predecessor's forward-check then fails).

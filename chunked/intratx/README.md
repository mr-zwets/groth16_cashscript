# Intra-transaction linked chunks (the single-transaction verifier)

A second way to chunk the Groth16 verifier, alternative to the sequential
NFT-commitment covenant in [`../pairing`](../pairing) and [`../bls12-381`](../bls12-381).

## The idea

Where the covenant method (`../pairing`, `../bls12-381`) hands state forward through a
token NFT commitment across a chain of transactions, this lays the **whole computation
out as the inputs of ONE transaction**. A script can read its siblings' witnesses by
introspection (`OP_INPUTBYTECODE` = `tx.inputs[i].unlockingBytecode`), so a chunk passes
its result to the next by having the next chunk read it — no state token, no hashing,
intermediate values any size:

```
chunk i:   take inBlob (incoming state) in the witness
           recompute outgoing state
           require( outgoing == tx.inputs[i+1].unlockingBytecode[front slice] )   // forward-check
chunk i+1: take inBlob (== chunk i's outgoing) in the witness, ...
```

That `require` is the "verify `arg01 == arg10`" from the design discussion. The first
chunk of a stage is genesis (nothing binds its input); the last asserts the verdict
(`finalExp == 1`). Cross-stage links are bound where byte layouts line up: **vk_x** into
the Miller genesis input, the **Miller boundary** into the final-exp genesis input.

Each input still fits one BCH budget (op-cost ≤ 8,032,800, script ≤ 10,000 B), so the
chunking — and the chunk math, reused verbatim — is identical to the covenant version.
What changes is packaging: ~60–84 inputs in one **non-standard (< 1 MB) transaction**
instead of that many sequential transactions, with no per-step hashing and no 128-byte
state cap.

### P2SH deployment

The op-cost budget counts only the unlocking: `(41 + scriptSig length) × 800`. Deploying
each chunk as **P2SH** (the default; `INTRATX_BARE=1` for bare) puts the ~4–5 KB redeem in
the scriptSig, where it counts toward that budget instead of needing an equal-sized pad on
top — ~27–30% fewer on-chain bytes, and the forward-check is unaffected (`inBlob` is still
the first scriptSig push). This is a general lever, so the covenant chunks would shrink the
same amount.

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

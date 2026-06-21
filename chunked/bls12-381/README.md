# chunked/bls12-381/ — BCH-native multi-transaction BLS12-381 vk_x

The **public-input aggregation** stage of a Groth16 verifier on **BLS12-381** (the
same curve as nchain), split across transactions so **every step fits one BCH input**
(op-cost ≤ 8,032,800, locking+unlocking ≤ 10,000 B):

```
vk_x = IC0 + in0·IC1 + in1·IC2        (multi-scalar-mult on G1)
```

This is the BLS12-381 counterpart of the BN254 `../pairing/gen_vkx.mjs` (the
`bch-vkx-chunked-covenant` entry) and the chunked form of the monolithic
`singleton/bls12-381/vkx.cash` baseline. It produces the benchmark entry
**`bch-vkx-bls12381-chunked-covenant`** in the verifier repo.

## Full-width and magnitude-independent (not a small-input shortcut)

The MSM is a single MSB-first Shamir/Straus double-and-add over one Jacobian
accumulator that tiles **all 255 scalar-field bit positions**. The chunk windows are
sized against a **worst-case all-bits-set planning input** (so every position is
costed as a doubling **and** an add), which means the deployed lockings aggregate
**any** public input `< r` — exactly like Ethereum's `ecMul` precompile (flat cost,
no small-input optimization), and matching the full-width property of nchain /
scrypt-bn256 and the BN254 chunked work. The small real test instances are only test
data; they exercise the same lockings at lower runtime op-cost (the un-set high bits
skip their adds at runtime), but the contract is bound to process every position.

Cost: ~13 chunks, ~92M worst-case op-cost total (≈ the singleton's ~101M / ~13
inputs), each step < 7.7M op-cost.

## Proof-agnostic covenant

Each chunk carries **no baked instance**: the running Jacobian accumulator `(rX,rY,rZ)`
plus the public inputs `(in0,in1)` are committed as `hash256` of their 48-byte
little-endian limbs (BLS12-381 field elements are 381-bit → 48 bytes, vs 40 for
BN254) in the spent/created token's **NFT commitment**. Each chunk verifies the
incoming commitment on entry (`tx.inputs[this.activeInputIndex].nftCommitment`),
recomputes its window, and re-commits the outgoing state to `tx.outputs[0]` under the
same token category. The final chunk folds `IC0`, verifies a supplied modular inverse
on stack (`rZ·zInv == 1`), converts to affine, and **commits the computed `vk_x`** to
`output[0]` (it does **not** assert against a baked point), so one fixed set of
lockings aggregates any public inputs. Runtime-generality is confirmed by replaying a
second, distinct public-input pair through identical lockings (`extraValidProofs`).

## Regenerating (everything in `generated/` is git-ignored)

```
node gen_vkx.mjs          # plan + emit generated/vkx_NN.cash + manifest_vkx.json
node build_vectors.mjs    # assemble -> verifier/src/bch/vkx-bls12381-chunked-covenant-vectors.json
```

`gen_vkx.mjs` sizes each window empirically: it grows the window and, for every
candidate, compiles the contract with the custom `cashc` and evaluates it on the real
BCH 2026 VM (through a synthetic token tx) to measure exact op-cost, stopping before
the per-input budget. `build_vectors.mjs` then re-compiles, pads, and evaluates every
chunk for **two** distinct public-input instances (valid + tampered) on the real VM,
and refuses to write the vectors unless every step fits, accepts, and rejects its
tampered witness. Fast probe (no planner): `node gen_vkx.mjs probe <lo> <hi>`.

## Files

| file | role | committed |
|------|------|:--------:|
| `_vkxmath.mjs` | shared Fp/Jacobian math, 48-byte serialization, covenant emitters, real-VM measurer, planner | ✅ |
| `gen_vkx.mjs` | plan + emit the worst-case-sized vk_x chunks | ✅ |
| `build_vectors.mjs` | assemble all chunks → the `bch-vkx-bls12381-chunked-covenant` vectors | ✅ |
| `generated/` | the ~13 `.cash` chunks + manifest (derived) | ❌ git-ignored |

The committed instance + IC points come from `../../singleton/bls12-381/bls_instance.mjs`;
the singleton baseline is `../../singleton/bls12-381/vkx.cash`.

# chunked/bls12-381/ — BCH-native multi-transaction BLS12-381 Groth16

The Groth16 verifier on **BLS12-381** (the same curve as nchain) split across
transactions so **every step fits one BCH input** (op-cost ≤ 8,032,800,
locking+unlocking ≤ 10,000 B). The BLS12-381 counterpart of the BN254
`../pairing/` work, and the chunked form of the monolithic `../../singleton/bls12-381/`
oracle. Three benchmark entries (in the verifier repo) are produced from here:

- **`bch-vkx-bls12381-chunked-covenant`** — the public-input aggregation
  `vk_x = IC0 + in0·IC1 + in1·IC2` (G1 multi-scalar-mult), 11 chunks / 23,036 B / 6.86M op-cost.
- **`bch-pairing-bls12381-chunked`** — the **Miller loops + final exponentiation**:
  `e(-A,B)·e(α,β)·e(vk_x,γ)·e(C,δ)` as ONE batched 4-pair Miller loop →
  the BLS/Hayashida-Scott final exponentiation → verdict (== Fp12 ONE). 72 chunks / 639,846 B / 506.38M op-cost.
- **`bch-groth16-bls12381-chunked`** — the **complete verifier**: the vk_x chunks
  prepended to the pairing. 86 chunks / 682,962 B / 535.40M op-cost; ranked in the main
  Groth16 leaderboard against nchain (its BLS12-381 reference) — the only BCH-compatible
  full Groth16 verifier on that curve.

## Optimizations (batched Miller + lazy reduction)

The first two passes cut the full verifier from 196 chunks / 2.28 MB / 1.137 B op to
116 / 1.47 MB / 754 M op; later optimizations produced the current figures above:

- **Batched 4-pair Miller** — instead of four independent single-pair chains (each
  squaring `f` every step), ONE loop squares `f` once per NAF step and folds all four
  pairs' lines into the shared `f` (each pair's `R` evolves independently). Eliminates 3
  of every 4 `fp12Sqr`, and the conjugated `f` after the loop IS the boundary, so there
  is **no separate combine step**. One batched step is ~8 `mul014` (too coarse for one
  input), so the loop is chunked as a FLAT op list (sqr / double-line / add-line) at any
  op boundary, carrying `f + 4 R + points`.
- **Lazy reduction** — `addFp` drops its `% p` (values only grow inside a chunk; `mulFp`,
  `subFp`, and the covOut commitment reduce them back); `subFp` keeps the mod with a big
  `K·p` bias. Applied to the emitted miller + final-exp functions. The dead inverse
  functions (`fp12Inv`/…, replaced by the witness trick) are dropped from the prologue.

Since per-step bytes are dominated (~64%) by op-cost-proportional unlocking padding,
op-cost cuts translate ~1:1 into size.

Every chunk is validated on the real BCH 2026 VM, against `@noble/curves` bls12-381,
for **two** distinct instances under the same VK (runtime-general).

## How it works

A GENERIC (proof-agnostic) covenant: each chunk carries **no baked proof**. The
running state — vk_x's Jacobian accumulator, the Miller `f` (Fp12, 12 limbs) + running
G2 point `R` (6 limbs), or the live final-exp Fp12 values — plus the proof-derived
points ride in the spent/created token's **NFT commitment** as `hash256` of their
**48-byte** little-endian limbs (a 381-bit BLS field element needs 48 bytes, vs 40 for
BN254's 254-bit field). Each chunk verifies the incoming commitment, recomputes its
window, and re-commits the outgoing state under the same token category, so one fixed
set of lockings verifies any proof. Within a chunk the work is **unrolled straight-line
with fresh SSA variables** (the NAF digit baked per Miller step), so the body compiles
once and **op-cost binds, not size**. Windows are sized by measuring real-VM op-cost.

### BLS-specific notes (vs BN254)

- **Miller loop** (`miller_ref.mjs` blueprint): multiplicative twist → the line uses
  `mul014` (not `mul034`); the ate loop is the NAF of `|x|` (x = −0xd201000000010000),
  64 digits, with **no 6x+2 and no Q1/Q2 postPrecompute**; because x is negative the
  batched `f` is **conjugated** once at the end of the loop (that conjugated `f` is the
  boundary — no combine).
- **Final exponentiation** is the BLS/Hayashida-Scott hard part over `|x|`, traced as
  the same Fp12 op-DAG primitives as BN254 (cycSqr/mul/conj/frob1-3/inv) with liveness
  carrying only the live Fp12 values. The easy-part **381-iteration Fermat inverse**
  would alone exceed one input's op-cost budget, so `f⁻¹` is supplied as an **unlocking
  witness** and verified by `fp12Mul(f, f⁻¹) == ONE` (the same trick as vk_x's `zInv`).
- vk_x is **full-width / magnitude-independent** (worst-case-sized windows over all 255
  scalar positions) — see the dedicated note below.

## Regenerating (everything in `generated/` is git-ignored)

```
node generate.mjs            # vk_x + 4 Miller chains + combine + final exp + all vectors
```

Individual pieces (all reproducible artifacts; only the generators are committed):

```
node gen_vkx.mjs                    # vk_x covenant chunks (worst-case / full-width)
node gen_miller.mjs                 # batched 4-pair Miller loop (flat-op, lazy)
node gen_finalexp.mjs               # final exponentiation -> verdict
node build_vectors.mjs             # -> verifier vkx-bls12381-chunked-covenant-vectors.json
node build_vectors_pairing.mjs     # -> verifier pairing- + groth16-bls12381-chunked-vectors.json
```

### Residue-plan ownership

The residue verifier has two deployment-owned chunk plans. They intentionally do not share a
manifest:

- `generated/manifest_{millerres,finalexpres}.json` is the covenant plan. Its chunks retain the
  incoming/outgoing NFT commitment hashes and are measured as independent token transactions.
- `generated/linked-residue/manifest_{millerres,finalexpres}.json` is the hash-free linked plan,
  consumed only by `chunked/intratx/build_vectors_residue_bls.mjs` and
  `chunked/grouped/build_vectors_residue_bls.mjs`. Those builders remove the boundary hashes and
  validate the wider windows in their real sibling-input contexts on both consensus and standard
  BCH 2026 VMs.

Regenerate the linked namespace before either linked vector:

```
node gen_miller_residue.mjs linked
node gen_finalexp_residue.mjs linked
```

Do not point the covenant or proposed-large builders at `generated/linked-residue/`. Several linked
windows exceed the covenant density limit before the boundary hashes are removed; the proposed-large
track has a separate 100 kB/bch-spec plan.

Fast probes (no planner): `node gen_miller.mjs 0 probe`, `node gen_finalexp.mjs probe`,
`node gen_vkx.mjs probe <lo> <hi>`.

### Why it takes a few minutes

The runtime is the chunk *planner*, not the cryptography: there is no formula for "how
many steps fit one BCH input", so each chunk is sized empirically — the generator grows
a window and, for every candidate, compiles the contract with the custom `cashc` and
evaluates it on the real BCH 2026 VM (through a synthetic token tx) to measure exact
op-cost. `build_vectors*` then re-compiles, pads, and evaluates every chunk twice (valid
+ tampered) for **two** distinct instances. Fully deterministic.

## vk_x is full-width / magnitude-independent

The vk_x MSM tiles **all 255 scalar-field bit positions** and the windows are sized
against a **worst-case all-bits-set input**, so one fixed locking aggregates **any**
public input < r (EVM ecMul-equivalent), not just small inputs. (The 255-bit scalar is
far below the 381-bit field, so the worst-case value reduces cleanly — no off-by-one,
unlike BN254 where 2²⁵⁴−1 exceeds the prime.)

## Files

| file | role | committed |
|------|------|:--------:|
| `_vkxmath.mjs` | shared Fp/Jacobian math, 48-byte serialization, covenant emitters, real-VM measurer, planner | ✅ |
| `_pairingmath.mjs` | shared noble Miller/finalExp math, op-DAG trace, instance pairs, fnExtractor | ✅ |
| `_residue_linked_plan.mjs` | audited hash-free Miller/tail boundaries and stress fixture, shared by grouped + intra-tx | ✅ |
| `gen_vkx.mjs` | plan + emit the worst-case-sized vk_x chunks | ✅ |
| `gen_miller.mjs` | plan + emit the batched 4-pair Miller chunks (flat-op, lazy) | ✅ |
| `gen_finalexp.mjs` | trace + chunk the final exponentiation (op-DAG + liveness, lazy) | ✅ |
| `build_vectors.mjs` | assemble the vk_x covenant vectors | ✅ |
| `build_vectors_pairing.mjs` | assemble the pairing + full-groth16 vectors | ✅ |
| `generate.mjs` | one-command orchestrator | ✅ |
| `generated/` | the ~116 `.cash` chunks + manifests (derived) | ❌ git-ignored |
| `generated/linked-residue/` | hash-free residue chunks + manifests for grouped/intra-tx only (derived) | ❌ git-ignored |

The instance + IC/VK points come from `../../singleton/bls12-381/bls_instance.mjs`; the
singleton oracles are `../../singleton/bls12-381/{vkx,miller,finalexp}.cash`.

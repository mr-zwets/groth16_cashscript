# chunked/bls12-381/ — BCH-native multi-transaction BLS12-381 Groth16

The Groth16 verifier on **BLS12-381** (the same curve as nchain) split across
transactions so **every step fits one BCH input** (op-cost ≤ 8,032,800,
locking+unlocking ≤ 10,000 B). The BLS12-381 counterpart of the BN254
`../pairing/` work, and the chunked form of the monolithic `../../singleton/bls12-381/`
oracle. Four benchmark entries (in the verifier repo) are produced from here:

- **`bch-vkx-bls12381-chunked-covenant`** — the public-input aggregation
  `vk_x = IC0 + in0·IC1 + in1·IC2` (G1 multi-scalar-mult), 11 chunks / 22,277 B / 6,808,579 op-cost.
- **`bch-pairing-bls12381-chunked`** — the **Miller loops + final exponentiation**:
  `e(-A,B)·e(α,β)·e(vk_x,γ)·e(C,δ)` as one prepared-VK 4-pair Miller product →
  the BLS/Hayashida-Scott final exponentiation → verdict (== Fp12 ONE). 51 chunks / 470,061 B / 372,314,128 op-cost.
- **`bch-groth16-bls12381-chunked`** — the **complete verifier**: five stage-bound GLV vk_x
  chunks prepended to an input-validated Miller namespace. 56 chunks / 484,519 B /
  377,785,509 op-cost; ranked in the main
  Groth16 leaderboard against nchain (its BLS12-381 reference) — the only BCH-compatible
  full Groth16 verifier on that curve.
- **`bch-groth16-bls12381-chunked-covenant-residue`** — the source-owned standard-VM
  covenant graph: five full-stage GLV chunks -> input-validation-fused residue Miller -> the
  one-input Fp6 residue verdict. It enforces a minting-baton genesis, one mutable state
  thread, fixed P2SH32 successor pins, and an immutable terminal verdict. 27 steps /
  208,340 B / 157,706,001 op-cost.

The separate 29-chunk input-unvalidated pairing and input-validated full Miller namespaces
also feed the linked layouts assembled by the sibling `intratx/` and `grouped/` builders:

- `bch-pairing-bls12381-intratx`: 51 inputs / 465,462 B / 372,116,160 op-cost.
- `bch-groth16-bls12381-intratx`: 56 inputs / 475,310 B / 377,658,775 op-cost.
- `bch-groth16-bls12381-grouped`: 56 inputs / 6 standard transactions / 475,292 B /
  377,556,467 op-cost.
- `bch-groth16-bls12381-intratx-residue`: fixed-VK quotient-torus frontier, 11 inputs /
  96,236 B / 76,886,155 op-cost in one 96,344-byte standard-policy transaction.
- `bch-groth16-bls12381-grouped-residue`: 35 inputs / 4 standard transactions / 209,937 B /
  158,744,466 op-cost.
- `bch-groth16-bls12381-intratx-residue-large`: 3 inputs / 164,426 B / 149,814,405 op-cost
  on the proposed 100 kB-script VM.

## Optimizations (prepared batched Miller + lazy reduction)

The first two passes cut the full verifier from 196 chunks / 2.28 MB / 1.137 B op to
116 / 1.47 MB / 754 M op; later optimizations produced the current figures above:

- **Batched 4-pair Miller** — instead of four independent single-pair chains (each
  squaring `f` every step), ONE loop squares `f` once per NAF step and folds all four
  pairs' lines into the shared `f`. Eliminates 3
  of every 4 `fp12Sqr`, and the conjugated `f` after the loop IS the boundary, so there
  is **no separate combine step**.
- **Default prepared VK pairs** — in the four-pair tracks, only `B` is a proof-derived G2 point,
  so only its `R_B` walk is
  performed on-chain. The fixed `γ`/`δ` trajectories contribute baked line coefficients;
  the fully fixed `e(α,β)` contributes one baked dense Miller value rather than 69 line
  folds. The flat trace falls from 340 to 272 ops and each interior hand-off carries
  `f + R_B + runtime points` (28 limbs rather than 46).
- **Default-path fused input validation for full Groth16** — the first full-Miller chunk checks A/C
  and B on-curve after requiring canonical `[0,p)` encodings for all ten stage coordinates.
  The last reuses its existing homogeneous `R_B=[|x|]B` walk for the
  guarded `psi(B)==[-x]B` subgroup relation. This removes the separate three-input G2
  pass while keeping pairing-only in a distinct, explicitly input-unvalidated namespace.
- **Lazy reduction** — `addFp` drops its `% p` (values only grow inside a chunk; `mulFp`,
  `subFp`, and the covOut commitment reduce them back); `subFp` keeps the mod with a big
  `K·p` bias. Applied to the emitted miller + final-exp functions. The dead inverse
  functions (`fp12Inv`/…, replaced by the witness trick) are dropped from the prologue.
- **Forward final-exp packing** — the planner targets 100,000 op-cost below the per-input
  budget by default, fitting the final-exponentiation trace into 22 chunks while preserving
  the existing forward execution order.
- **Default full-verifier GLV aggregation** — the prepared four-pair verifier decomposes each canonical Fr input
  into two non-negative 128-bit scalars and uses a four-scalar Straus walk over the fixed
  endomorphism table. The covenant form embeds the exact VK table; the intra/grouped forms
  carry it once in the fifth GLV input, hash-pin it there, and let the four siblings read it
  by input introspection. The first contract derives infinity from only six scalar limbs,
  and the last emits the exact `(-A,B,C,vk_x)` stage. The standalone vk_x benchmark remains
  the existing 11-chunk full-width Shamir implementation for a like-for-like track.
- **Exact canonical handoffs** — stage-bound vk_x and validated G2 producers serialize values
  exactly once their bounds or field operations prove canonicality. The full-stage proof tuple is
  preserved byte-for-byte until the first Miller range gate, so a coordinate encoded as `x+p` is
  rejected rather than silently normalized.
- **Fp6 residue membership** — the residue construction always produces `w` in the embedded
  `Fp6*`: its A-part lies in Fp because `A | p-1`, and its root-of-unity corrector lies in Fp6.
  Since `p^6-1 | (p^12-1)/r`, the terminal witnesses only the six Fp6 limbs and fixes the upper
  Fp12 half to zero, replacing the 63-step `w^(27A)` walk. The inverse and terminal equations
  exclude zero.
- **Fixed-key collapse and comb** — bilinearity rewrites the four-pair equation to
  `e(-A,B)·e(D,G2.BASE)=1`, where `D=5α+7vk_x+11C`. One width-six fixed-comb input
  assembles `D`; two proof-dependent slope slices are carried by Miller inputs and read with
  input introspection, while the 6,048-byte fixed table is hash-pinned across three Miller
  witnesses. Positive field biases let each affine row canonicalize its outputs once. Affine G2
  walks and half-normalized G1 lines then evaluate the two-pair trace in ten inputs.
- **Quotient-torus residue frontier** — the fixed-key intra-transaction build works in
  `Fp12*/Fp6*`, a cyclic group of order `p^6+1`. For `lambda=p+|x|`,
  `gcd(lambda,p^6+1)=r`, so the lambda-power image is exactly the final-exponent kernel in the
  quotient. A canonical six-limb `u` carries the finite class `[c]=[1+u*W]`; the Fp6 correction
  disappears, constant folds use two Fp6 products instead of three, and the final Miller input
  checks `[fF]=[frob(c,1)]` by a nonzero projective cross-product. This removes the separate tail.
  A fixed r-torsion shift makes a finite root available for every accepting class.

Since per-step bytes are dominated (~64%) by op-cost-proportional unlocking padding,
op-cost cuts translate ~1:1 into size.

Every chunk is validated on the real BCH 2026 VM against `@noble/curves` bls12-381. The fixed-key
one-transaction path covers 16 valid instances, 24 rejection runs, all A/B/C identity combinations,
the `vk_x` identity, a satisfying fixed-comb final-equal/doubling case, and three isolated
point-validation cases under the same locking graph.

## How it works

A GENERIC (proof-agnostic) covenant: each chunk carries **no baked proof**; only VK
constants are prepared. The
running state — vk_x's Jacobian accumulator, the Miller `f` (Fp12, 12 limbs) + running
G2 point `R` (6 limbs), or the live final-exp Fp12 values — plus the proof-derived
points ride in the spent/created token's **NFT commitment** as `hash256` of their
**48-byte** little-endian limbs (a 381-bit BLS field element needs 48 bytes, vs 40 for
BN254's 254-bit field). Each chunk verifies the incoming commitment, recomputes its
window, and re-commits the outgoing state under the same token category, so one fixed
set of lockings verifies any proof. The full chain is sequential: public inputs → vk_x →
`(-A,B,C,vk_x)` → input-validated Miller → final exponentiation. vk_x range-checks
canonical Fr inputs; Miller derives `f=1` and `R=B`. Every stage emits
the exact next-stage state, and every nonterminal covenant pins the actual successor
locking bytecode. Within a chunk the work is **unrolled straight-line
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
VERIFIER_DIR=/path/to/zk-verifier-bench node generate.mjs
```

The covenant-residue track has its own one-command source-to-vector path:

```
VERIFIER_DIR=/path/to/zk-verifier-bench node generate_covenant_residue.mjs
```

Individual pieces (all reproducible artifacts; only the generators are committed):

```
node gen_vkx.mjs                    # standalone vk_x covenant chunks
node gen_vkx.mjs full               # legacy full-stage Shamir generator
node gen_vkx_glv.mjs                # GLV planner; full builders emit the audited stage-bound layout
node gen_miller.mjs                 # pairing-only prepared Miller (input-unvalidated)
node gen_miller.mjs full            # full prepared Miller with fused input validation
node gen_finalexp.mjs               # final exponentiation -> verdict
node build_vectors.mjs             # -> verifier vkx-bls12381-chunked-covenant-vectors.json
node build_vectors_pairing.mjs     # -> verifier pairing- + groth16-bls12381-chunked-vectors.json
```

### Residue-plan ownership

The residue verifier has two deployment-owned chunk plans. They intentionally do not share a
manifest:

- `generated/manifest_{millerres,finalexpres}.json` is the covenant plan. Its chunks retain the
  incoming/outgoing NFT commitment hashes and are measured as independent token transactions.
  `generate_covenant_residue.mjs` regenerates this namespace in its exact full-stage layout before
  assembling the lifecycle-bound P2SH32 graph.
- `generated/linked-residue/manifest_{millerres,finalexpres}.json` is the hash-free linked plan,
  consumed only by `chunked/intratx/build_vectors_residue_bls.mjs` and
  `chunked/grouped/build_vectors_residue_bls.mjs`. Those builders remove the boundary hashes and
  validate the wider windows in their real sibling-input contexts on both consensus and standard
  BCH 2026 VMs.

Regenerate the grouped/default linked namespace with:

```
node gen_miller_residue.mjs linked
node gen_finalexp_residue.mjs linked
```

The fixed-VK one-transaction verifier uses the specialized one-command path below instead. It
regenerates the collapsed quotient-torus Miller stage with the required flags, proves the quotient
and half-normalized line identities, checks the lazy-integer bounds, executes the full dual-VM
vector builder, and then certifies the all-canonical-input resource envelope:

```
VERIFIER_DIR=/path/to/zk-verifier-bench pnpm vectors:intratx:torus:bls
```

The orchestrator resolves the linked `cashc` package, requires a clean compiler checkout at commit
`1c707c1dbf87396b30ba5e0704b1db44475ce893`, and rebuilds `@cashscript/utils` plus `cashc` from that
source before generating bytecode.

The final certificate recompiles the exact transformed contracts, pins every source and redeem
hash plus the control and numeric program counters, covers every finite conditional mode, and
propagates integer intervals through the BCH 2026 VM. Its proof-independent envelope is a
97,447-byte transaction (2,553 bytes below the standard limit), with every unlocking at most
9,753 bytes and every standard-policy input op-cost at most 7,835,111. The primary concrete
benchmark fixture is the 96,344-byte transaction reported above.

Benchmark fixture scope: this fixed-VK track uses deterministic, known-log synthetic fixtures. The
verification-key and proof points are constructed as known scalar multiples of the standard G1/G2
bases so accepting branch, identity, graph-binding, and resource cases can be reproduced exactly.
The proof-point construction logs are test-generation data rather than witness values; the fixed-key
scalar relations are intentionally part of this benchmark specialization. These vectors demonstrate
verifier execution and resource behavior for this specialized key; an interoperability claim
additionally requires proofs and a verification key produced independently by an external Groth16
circuit/toolchain.

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
against two **canonical complementary Fr scalars** whose bitwise union sets every
position, so every planning iteration executes its add path. One fixed locking therefore
aggregates **any** public input in `[0,r)` (EVM ecMul-equivalent), not just small inputs;
the first chunk rejects negative or out-of-range scalars rather than silently truncating them.

## Files

| file | role | committed |
|------|------|:--------:|
| `_vkxmath.mjs` | shared Fp/Jacobian math, 48-byte serialization, covenant emitters, real-VM measurer, planner | ✅ |
| `_pairingmath.mjs` | shared noble Miller/finalExp math, op-DAG trace, instance pairs, fnExtractor | ✅ |
| `_residue_linked_plan.mjs` | audited hash-free Miller/tail boundaries and stress fixture, shared by grouped + intra-tx | ✅ |
| `gen_vkx.mjs` | plan + emit the standalone worst-case-sized Shamir vk_x chunks | ✅ |
| `gen_vkx_glv.mjs` | emit the hardened five-window GLV layout used by full-verifier builders | ✅ |
| `gen_miller.mjs` | plan + emit separate pairing-only and input-validated full prepared-Miller namespaces | ✅ |
| `gen_finalexp.mjs` | trace + chunk the final exponentiation (op-DAG + liveness, lazy) | ✅ |
| `build_vectors.mjs` | assemble the vk_x covenant vectors | ✅ |
| `build_vectors_pairing.mjs` | assemble the pairing + full-groth16 vectors | ✅ |
| `build_vectors_covenant_residue.mjs` | assemble and gate the BLS covenant-residue lifecycle | ✅ |
| `generate_covenant_residue.mjs` | one-command BLS covenant-residue vector reproduction | ✅ |
| `prove_resource_bounds.mjs` | source-pinned BCH 2026 resource certificate for the one-transaction verifier | ✅ |
| `generate.mjs` | one-command orchestrator | ✅ |
| `generated/` | generated `.cash` chunks + manifests (derived) | ❌ git-ignored |
| `generated/linked-residue/` | hash-free residue chunks + manifests for grouped/intra-tx only (derived) | ❌ git-ignored |

The instance + IC/VK points come from `../../singleton/bls12-381/bls_instance.mjs`; the
singleton oracles are `../../singleton/bls12-381/{vkx,miller,finalexp}.cash`.

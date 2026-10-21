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
  377,785,509 op-cost; ranked in the main Groth16 leaderboard against nchain (its
  BLS12-381 reference).
- **`bch-groth16-bls12381-chunked-covenant-residue`** — the source-owned standard-VM
  covenant graph: five full-stage GLV chunks -> input-validation-fused residue Miller -> the
  one-input Fp6 residue verdict. It enforces a minting-baton genesis, one mutable state
  thread, fixed P2SH32 successor pins, and an immutable terminal verdict. 27 steps /
  208,340 B / 157,706,001 op-cost.

The separate 29-chunk input-unvalidated pairing and input-validated full Miller namespaces
also feed the linked layouts assembled by the sibling `intratx/` and `grouped/` builders:

- `bch-pairing-bls12381-intratx`: 51 inputs / 465,462 B / 372,116,160 op-cost.
- `bch-groth16-bls12381-intratx`: 56 inputs / 475,310 B / 377,658,775 op-cost.
- `bch-groth16-bls12381-intratx-fs-compact`: compact Fiat-Shamir PIT candidate, 22 inputs / **69,947 B score / 69,177 B wire / 42,969,175 committed native-standard op-cost**; maximum supplied native-standard 57,059,203 (Libauth standard 56,959,761); dense observed 90,107 B score / 89,337 B wire. This is finite source/native corpus evidence, not a universal resource or live-admission claim.
- `bch-groth16-bls12381-grouped`: 56 inputs / 6 standard transactions / 475,292 B /
  377,556,467 op-cost.
- `bch-groth16-bls12381-intratx-residue`: quotient-torus frontier, 24 inputs / 192,317 script B /
  193,369 score B / 192,529 wire B / 151,427,800 op-cost. The unchanged default Fp6-tail path remains reproducible at 35 inputs /
  209,216 B / 157,700,169 op-cost.
- `bch-groth16-bls12381-grouped-residue`: 26 inputs / 3 standard transactions / 204,424 script B /
  205,734 score B / 204,894 wire B / 160,953,436 op-cost.
- `bch-groth16-bls12381-intratx-residue-large`: 3 inputs / 164,426 script B / 164,579 score B /
  164,474 wire B / 149,814,405 op-cost on the proposed 100 kB-script VM; non-standard by total size.

## Nine-input Fiat-Shamir candidate

`RPA_FUSE_COORDINATOR_HEAD=1 RPA_CACHE_COORDINATOR_PREFIX=1` adds a default-off
nine-input layout. With the pinned scheduled compiler
`efc6ab80d9cbbea06c3c364b8fd5e915b9da84b4`, its primary challenge score is
**60,626 bytes** (60,219 script + 407 overhead; 60,311-byte spend transaction).
Actual native primary opcost is **37,855,684 consensus / 38,025,924 standard**.
Relative to the existing ten-input point, this saves **1,626 bytes**, one input,
and **92,464 / 95,536** primary cost units. The ten- and eleven-input profiles
remain reproducible with their existing flags.

The quotient head joins the coordinator in root input 0. The root checks the
ordered eight-worker locking commitment inline before loading the complete
coordinator arithmetic from four existing funding payloads and a literal data
push in the First/Tail worker. That imported program excludes the expected
worker hash, avoiding a cryptographic hash fixed point. The root reuses the
existing arithmetic library after a guarded ABI remapping. All 21 logical stages
and all 46 archived proof argument pushes retain their values and encodings.

Each input caches only the first 870 bytes of encoded root header/statement under
raw function key `0x67`. The installed body is one literal PUSHDATA2 data push;
witness bytes are never executed. Rewriting is restricted to exact bounded
header/statement reads. Full-root and quotient readers keep their original
inputs. The inline ACTIVEBYTECODE framing check and final sibling commitment
protect the imported program and its offsets.

Qualification covers ten archived fixtures, 3,520 source owning/whole rejection
checks, and 1,072 actual native contexts: 20 accepted and 1,052 rejected, with all
180 positive input prices reconciled. All 164 previous invalid cases and 336 direct
origin records remain represented, including explicit relocation of four old
carrier attacks. Ten new bad-code/rebound-producer controls cover all five code
carriers. Maximum sampled native cost is 49,501,698 / 49,850,498; minimum sampled
per-input headroom is 54,639 / 48,751. Maximum sampled score is 80,786 bytes.
The cache-disabled normal export is byte-identical to the published ten-input
profile. These are finite corpus results, not arbitrary-proof resource bounds,
a universal soundness theorem, or a live-relay result. Existing FS-PIT, G2/G1
validation grades and campaign limitations remain unchanged.

Run from this directory with the compiler above (the JSON padding is encoded
funding data reused by the coordinator, not newly added padding):

```sh
RPA_COORDINATOR_DENSITY_PADDING='0' \
RPA_EXPORT_RESOURCE_BYTECODES='1' \
RPA_INVERSES='off' \
RPA_PIC32='1' \
RPA_PIC_BLOCK2_DENSITY_PADDING='0' \
RPA_PIC_BLOCK4_DENSITY_PADDING='0' \
RPA_PIC_LAYOUT='regular' \
RPA_Q_TAIL_COEFFICIENTS='22' \
RPA_REGULAR_DENSITY_PADDING='{}' \
RPA_SKIP_GAMMA='1' \
RPA_TEMPLATE_FACTOR_DENSITY_PADDING='0' \
RPA_TEMPLATE_RUN='1' \
RPA_TEMPLATE_TAIL_DENSITY_PADDING='0' \
RPA_TEMPLATE_TERMINAL_DENSITY_PADDING='0' \
RPA_COMPACT_ARITHMETIC_PRIME_KEY='-1' \
RESCHEDULE='on' \
RPA_COMPACT_REGULAR_DENSITY_PADDING='{"3": 288, "5": 281, "6": 229, "7": 0, "8": 0, "9": 225, "10": 226, "11": 234, "12": 229, "13": 236, "14": 252, "16": 262, "17": 232, "18": 236, "19": 0}' \
RPA_TEMPLATE_COMMON_PRIME_POOL='on' \
RPA_PROOF_FIXTURE='committed' \
RPA_TEMPLATE_TERMINAL_PRIME_POOL='on' \
RPA_FUSE_FINAL_PAIR='1' \
RPA_SCHEDULE_COORDINATOR='1' \
RPA_GROUP_DENSITY_PADDING='0' \
RPA_FUSE_REGULAR_PAIR='1' \
RPA_SCHEDULE_PIC_AUTH='1' \
RPA_FUSE_REGULAR_PAIRS='1' \
RPA_FUSE_REGULAR_TRIPLES='1' \
RPA_FUSE_CARRIER_PAIR='1' \
RPA_FUSE_MIDDLE_PAIR='1' \
RPA_ARITHMETIC_REGULAR_CARRIER='1' \
RPA_FUSE_FIRST_TAIL_PAIR='1' \
RPA_BUNDLE_REGULAR_MAIN='1' \
RPA_LAZY_PAIR_PRODUCT='1' \
RPA_FUSE_RELATIONS='1' \
RPA_FINAL_RELATION_TOTAL='1' \
RPA_EVAL6_PAIRED='1' \
RPA_COORDINATOR_TAIL_BYTES='0' \
RPA_FUSE_COORDINATOR_HEAD='1' \
RPA_CACHE_COORDINATOR_PREFIX='1' \
RPA_TEMPLATE_CASHC='/path/to/zk-language/packages/cashc/dist/compiler.js' \
node measure_d3_two_chart_binary.mjs
```

## Optimizations (prepared batched Miller + lazy reduction)

The first two passes cut the full verifier from 196 chunks / 2.28 MB / 1.137 B op to
116 / 1.47 MB / 754 M op; later optimizations produced the current figures above:

- **Batched 4-pair Miller** — instead of four independent single-pair chains (each
  squaring `f` every step), ONE loop squares `f` once per NAF step and folds all four
  pairs' lines into the shared `f`. Eliminates 3
  of every 4 `fp12Sqr`, and the conjugated `f` after the loop IS the boundary, so there
  is **no separate combine step**.
- **Prepared VK pairs** — only `B` is a proof-derived G2 point, so only its `R_B` walk is
  performed on-chain. The fixed `γ`/`δ` trajectories contribute baked line coefficients;
  the fully fixed `e(α,β)` contributes one baked dense Miller value rather than 69 line
  folds. The flat trace falls from 340 to 272 ops and each interior hand-off carries
  `f + R_B + runtime points` (28 limbs rather than 46).
- **Fused input validation for full Groth16** — the first full-Miller chunk checks A/C
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
- **GLV full-verifier aggregation** — the full verifier decomposes each canonical Fr input
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
- **Quotient-torus residue frontier** — the opt-in intra-transaction build works in
  `Fp12*/Fp6*`, a cyclic group of order `p^6+1`. For `lambda=p+|x|`,
  `gcd(lambda,p^6+1)=r`, so the lambda-power image is exactly the final-exponent kernel in the
  quotient. A canonical six-limb `u` carries the finite class `[c]=[1+u*W]`; the Fp6 correction
  disappears, constant folds use two Fp6 products instead of three, and the final Miller input
  checks `[fF]=[frob(c,1)]` by a nonzero projective cross-product. This removes the separate tail.
  A fixed r-torsion shift makes a finite root available for every accepting class.

Since per-step bytes are dominated (~64%) by op-cost-proportional unlocking padding,
op-cost cuts translate ~1:1 into size.

Every chunk is validated on the real BCH 2026 VM, against `@noble/curves` bls12-381,
for **two** distinct instances under the same VK (runtime-general).

The prescribed verifier.cash BLS12-381 key is synthetic and publishes its setup and IC scalars.
The bytecode evaluates the complete four-pair equation without collapsing it through those scalar
relations, but these fixtures do not establish circuit knowledge, secure application public-input
binding, arbitrary-key verification, or interoperability with an independently generated setup.

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

The current-BCH intra-transaction quotient frontier has a deterministic one-command path. It
also runs the quotient-group proof and full valid/invalid dual-VM gates before writing the vector:

```
VERIFIER_DIR=/path/to/zk-verifier-bench pnpm vectors:intratx:torus:bls
```

The quotient path is opt-in. Running the original four unflagged GLV, Miller, final-residue, and
builder commands still reproduces the 35-input artifact byte-for-byte.

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
| `generate.mjs` | one-command orchestrator | ✅ |
| `generated/` | generated `.cash` chunks + manifests (derived) | ❌ git-ignored |
| `generated/linked-residue/` | hash-free residue chunks + manifests for grouped/intra-tx only (derived) | ❌ git-ignored |

The instance + IC/VK points come from `../../singleton/bls12-381/bls_instance.mjs`; the
singleton oracles are `../../singleton/bls12-381/{vkx,miller,finalexp}.cash`.

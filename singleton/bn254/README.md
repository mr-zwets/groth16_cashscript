# singleton/bn254/ — BN254 Groth16 verifier (singleton oracle)

The complete BN254 verifier: on-chain `vk_x` (`vkx.cash`), the field tower
(Fp2→Fp6→Fp12), the Miller loop, and final exponentiation. Built singleton-first (the
correctness oracle), bottom-up, grading each layer **directly against `@noble/curves`
bn254** on the loosened BCH 2026 VM — and `vkx.cash` is the oracle for `../../chunked/`.

Basis is locked to noble's tower so checkpoint #2 (`millerHex`) grades byte-for-byte:
`u²=−1`, `v³=9+u`, `w²=v`; an Fp12 is 12 ints in toBytes order
`c0.c0.c0 … c1.c2.c1`. See `../../../verifier/docs/pairing-checker.md`.

Every tower op is a reusable multi-return function (shared via `OP_DEFINE`/`OP_INVOKE`
unless the compiler decides inlining is byte-cheaper). Top-level functions, `import`
and multi-return are upstream in CashScript v0.14; the committed artifacts are compiled with
the local cashc fork branch `compiler-optimizations-8` (see
[cashscript-compiler-fork.md](../../cashscript-compiler-fork.md)).

## Files / status

| layer | contract | grader | ops graded vs noble | status |
|-------|----------|--------|---------------------|--------|
| Fp2  | `fp2.cash`  | `fp2.mjs`  | mul, sqr, inv, mulXi, conj | ✅ PASS |
| Fp6  | `fp6.cash`  | `fp6.mjs`  | mul, sqr, mulByV           | ✅ PASS |
| Fp12 | `fp12.cash` | `fp12.mjs` | mul, sqr, conjugate        | ✅ PASS |
| Fp12 | `fp12_frob.cash` | `fp12_frob.mjs` | Frobenius p, p², p³ | ✅ PASS |
| Fp12 | `fp12_inv.cash` | `fp12_inv.mjs` | inverse (fp2Inv→fp6Inv→fp12Inv) | ✅ PASS |
| Miller | `miller_ref.mjs` (JS spec) | self-validating | full 6x+2 loop, 4-pair batch → cp#2 | ✅ spec matches noble byte-for-byte |
| Miller | `mul034.cash` | `mul034.mjs` | sparse line multiply (mul034 + fp6Mul01) | ✅ PASS |
| Miller | `g2lines.cash` | `g2lines.mjs` | pointDouble / pointAdd line steps | ✅ PASS |
| Miller | `miller.cash` | `miller.mjs` | single-pair loop == noble pairing(g1,g2,false) | ✅ PASS (~238M) |
| **Miller** | **`miller4.cash`** | **`miller4.mjs`** | **4-pair boundary == golden millerHex** | ✅ **cp#2** (~957M) |
| FinalExp | `finalexp_ref.mjs` (JS spec) | self-validating | (p¹²−1)/r == noble finalExp | ✅ spec matches noble |
| **FinalExp** | **`finalexp.cash`** | **`finalexp.mjs`** | **== noble; valid→1, invalid→≠1** | ✅ **cp#3** (~255M, 9.3 KB) |

| **Verdict** | **`verify.cash`** | **`verify.mjs`** | **4 pairs → boundary → finalExp → require==1; valid accepts, invalid rejects** | ✅ **full pairing** (~1.21B, 19.9 KB) |
| **Verifier** | **`groth16.cash`** | **`groth16.mjs`** | **proof+inputs → vk_x on-chain → pairing → ==1; valid accepts, tampered rejects** | ✅ **COMPLETE & SOUND** (~1.26B, 21.7 KB) |

**The full BN254 Groth16 pairing is implemented + verified in CashScript** (singleton
oracle): Fp12 tower → Miller boundary (cp#2, byte-for-byte vs golden) → final
exponentiation (cp#3, verdict matches golden valid/invalid). `verify.cash` ties it into
the single intrinsic verdict `e(-A,B)·e(α,β)·e(vk_x,γ)·e(C,δ)==1`. `groth16.cash` folds
in the on-chain `vk_x` (also standalone in `vkx.cash`) for the complete Groth16 verifier.

**In the verifier benchmark:**
- `bch-groth16-singleton` — the COMPLETE verifier (byte reference), in the main **Groth16**
  leaderboard head-to-head with nchain/scrypt. Build:
  `node singleton/bn254/build_vectors_groth16.mjs` → `verifier/src/bch/groth16-singleton-vectors.json`.
  `pnpm benchmark`: `PASS`, 15,867 B scored, 888,690,550 op-cost, ~111 inputs.
  Same BN254 curve as scrypt-bn256 → **~734× smaller bytecode** (15.9 KB vs 11.7 MB).
- `bch-groth16-singleton-minop` — the **op-optimized** variant: an unrolled batched
  c^-(6x+2)-fused Miller evaluated in the quotient torus Fp12*/Fp6* (6-limb canonical root,
  lazy tower, fixed-VK line coeffs baked so only `(-A,B)` runs on-chain G2 arithmetic),
  affine runtime B with witnessed slopes, the exact G2 subgroup check fused into the psi
  endpoint, and affine witnessed-slope GLV `vk_x` — all gated witnesses.
  Build: `node singleton/bn254/gen_singletons.mjs`,
  then `build_vectors_groth16_minop.mjs` + `VARIANT=minop node gen_multiproof_opt.mjs`.
  `pnpm benchmark`: `PASS`, **64,840,336 op-cost** (worst case 72,761,016; −92% vs the baseline's 771,300,238 on the
  current harness), 9 inputs,
  50,539 B locking / 58,073 B scored — below the
  13-input chunked verifier's total op-cost; beats scrypt on both bytes and op. The unroll
  (needed to bake coeffs as literals; runtime blob indexing is ~100 op/byte for OP_SPLIT) makes
  the script large and needs the cashc fork's large-contract compile fix (`COMPILER_FIX_NOTE.md` Fix 2).
- `bch-pairing-singleton` — the pairing-only milestone (leaderboard "Groth16 pairing
  (BCH-native)"). Build: `node singleton/bn254/build_vectors.mjs`. 20,735 B, ~1.21B, ~151 inputs.
  The standalone `vk_x` baseline (`bch-vkx-singleton`) builds with `node singleton/bn254/build_vectors_vkx.mjs`.

## Soundness of `groth16_minop.cash` (`bch-groth16-singleton-minop`)

Status: **reviewed** (two independent constructive reviews, 2026-10-27; no owner gap). The
shipped locking bytecode (50,539 B) is regenerated by `node gen_singletons.mjs` (with
`VERIFIER_DIR` pointing at the zk-verifier-bench checkout) and recompiled with the cashc fork
(`rescheduleStacks: true`) byte for byte. Line numbers below refer to `groth16_minop.cash`;
kernels live in `lib/lazy/Bn254Lazy.cash`.

The verifier is one input with no introspection, state hand-off or sibling inputs, so there is
no multi-input binding to argue. The argument has five parts.

### Owner table

Every value the accept decision depends on, and what fixes it.

| value | owner | where |
|-------|-------|-------|
| `Ax, Ay, Cx, Cy` | canonical (`within(.,0,p)`) and on `y² = x³ + 3`. BN254 G1 has cofactor 1, so on-curve means in G1. Affine coordinates cannot encode O. | L18-23 |
| `Bxa, Bxb, Bya, Byb` | canonical and on the twist `y² = x³ + 3/(9+u)`. Subgroup membership comes from the endpoint relation (part 3). | L20-28, L593-606 |
| `in0, in1` | exact equation `in = (k1 + k2·λ_GLV) mod r` with `k >= 0`, so `in ∈ [0, r)` (part 4) | L32-36 |
| `k10, k20, k11, k21, nb` | `nb ∈ [0,128)`; `k >> (nb+1) == 0` (OP_RSHIFTNUM, floor) forces `0 <= k < 2^(nb+1)` | L32-34 |
| `glvSlopes` (32-byte chunks) | each slope is canonical and fixed by the exact chord/tangent equation in `g1AddAffine` / `g1DoubleAffine`, which also require `dx ≠ 0` / `y ≠ 0`. Unused trailing bytes have no effect on the verdict. | L37-61 |
| GLV table, `IC0`, `λ_GLV`, `r` | VK constants: the 15 entries are the subset sums of `{IC1, φ(IC1), IC2, φ(IC2)}`, `φ(x,y) = (βx, y) = [λ_GLV]`, and `λ_GLV² + λ_GLV + 1 ≡ 0 (mod r)` | L35-57 |
| `vk_x` | computed on-chain from the above: `IC0 + in0·IC1 + in1·IC2` exactly (every affine step is exact; an exceptional step is rejected, which costs completeness only) | L37-61 |
| `iAy, iVy, iCy` | canonical and `y·i ≡ 1`; this also forces `A.y, vk_x.y, C.y ≠ 0` | L64-69 |
| `u0..u5` (residue root) | canonical. Otherwise free: the terminal argument (part 2) holds for **every** `u` | L30 |
| `s0a/b .. s87a/b` (G2 slopes) | each is canonical and fixed by the exact tangent (`m·2Y = 3X²`) or chord (`m·dx = dy`) equation. `pointDoubleAffine` requires `Y ≠ 0`; `pointAddAffine` requires `dx ≠ 0`. | `Bn254Lazy.cash:596-642` |
| runtime line coefficients | computed on-chain by those kernels from the slope and the current `R` | same |
| baked `(vk_x, γ)` and `(C, δ)` lines | VK constants: the 88 + 88 unit lines of the affine Miller walk of γ and δ on the same `6x+2` NAF, plus the two Frobenius lines. Both reviewers recomputed them independently. | L70-611 |
| baked `K` (torus constant) | VK constant: `[1 + tW]` with `FE(K) = e(α, β)` (recomputed by review 1; an accepted honest proof also pins `K^FE`) | L612 |
| `psi`, `torusFrob1/2`, `ζ` constants | curve constants: `ξ^((p-1)/3)`, `ξ^((p-1)/2)`, `ξ^((p-1)/6)` and their `p²` composites, recomputed against noble | `Bn254Lazy.cash:743, 892-911`, L604 |
| `F0..F11` | computed on-chain: one linear chain from the genesis `[1 − uW]` through every square, line and `c^±1` fold | L70-617 |

### 1. Miller schedule

The runtime walk starts at `R = B` and runs 86 affine doubles and adds. Those steps compute
exactly `R = [6x+2]B`. Each slope is used once and each runtime line is evaluated once at
`−A` through the unit coordinates `(u, v) = (A.x/A.y, 1/A.y)`. The `c` exponent is exactly
`−(6x+2)`: the genesis value is `F = [c⁻¹] = [1 − uW]`, each square doubles the exponent,
a `+B` digit folds `c⁻¹` and a `−B` digit folds `c`. The unit-line normalisation divides each
line by a `P.y ∈ Fp*`. That factor lies in `Fp6*` and disappears in the quotient below.

### 2. Residue verdict (no final exponentiation)

The accumulator lives in `Fp12* / Fp6*`, where `[c] = [1 + uW]`. Since
`(1 + uW)(1 − uW) = 1 − u²v ∈ Fp6`, `[1 − uW]` is the inverse class. The terminal check
(L613-626) is

    [F · c^(p²)] = [c^p · c^(p³)]

by projective cross-multiplication:
`F_a·(t1 + t3) ≡ F_b·(1 + v·t1·t3)` limb by limb mod p, where `t1 = frob1(u)`,
`t3 = frob2(t1)`, and `F_a, F_b` are the two Fp6 halves after folding `c^(p²)`.

The `[0:0]` representative would make the cross-multiplication vacuous, so it is rejected
(L622). `fp12MulTorus` returns signedFp limbs in `(−p, p)`. A limb in that range that is
`0 mod p` is exactly 0, so `F ≡ 0` forces an integer sum of 0 and the `!= 0` gate rejects it.
(A nonzero `F` whose signed limbs sum to 0 is also rejected. That is a negligible
completeness loss, not a soundness issue.) The right-hand side `(1 + t1W)(1 + t3W)` is never 0.

Let `f` be the Miller value of the three runtime-dependent pairs `(−A, B), (vk_x, γ), (C, δ)`.
An accepted spend then gives

    f · K = c^λ · s,   s ∈ Fp6*,   λ = 6x + 2 + p − p² + p³.

`r | λ` holds (checked numerically). `p⁶ − 1` divides `(p¹² − 1)/r`, so raising both sides to
`(p¹² − 1)/r` kills `s` and `c^λ` for **any** witness `u`. That leaves

    e(−A, B) · e(α, β) · e(vk_x, γ) · e(C, δ) = 1,

the Groth16 equation, with `e` the optimal-ate pairing. The bracketed class equality is
exact: integer equality mod p of reduced limbs, with `F ≠ 0` and the target nonzero.
Reference model: `../../chunked/pairing/_residuemath.mjs` and `prove_miller_torus.mjs`.

### 3. G2 membership of B (endpoint relation)

After the `[6x+2]B` walk the two Frobenius additions compute `R + ψ(B) − ψ²(B)`, also
affine and with exact slopes. L604-606 then require the result to equal `−ψ³(B)`, which is
`(ζ·ψ(B).x, ψ(B).y)` with `ζ` the baked cube root of unity (L604). So `α(B) = O` for the endomorphism

    α = (6x + 2) + ψ − ψ² + ψ³.

With `ψ² − tψ + p = 0` on `E'(Fp2)` (t = 6x² + 1), α reduces to `a + bψ` with norm
`N(α) = a² + tab + pb²`. Then:

- `#E'(Fp2) = r·h2`, where `h2 = 2p − r`. `r ∤ h2` and `gcd(N(α), h2) = 1`, both checked numerically.
- `B ∈ ker α` gives `[N(α)]B = O`, so the order of B divides `gcd(N(α), r·h2) = r`. That means B ∈ G2.
- Conversely, ψ acts as `[p]` on G2 and `r | λ`, so every G2 point satisfies the relation.

The walk cannot pass through O. Affine points cannot encode it, a double requires `Y ≠ 0`
and an add requires `dx ≠ 0`. `h2` is odd, so `E'(Fp2)` has no 2-torsion. Every accepted
step is therefore the true group operation. Reference: `../../chunked/pairing/prove_miller_endpoint_subgroup.mjs`.

### 4. Public inputs below r

There is no explicit `within(in, 0, r)` check. Instead `in = (k1 + k2·λ_GLV) % r` (L35-36)
with `k1, k2 >= 0`. cashc compiles `>>` to OP_RSHIFTNUM, which floors, so a negative `k`
gives `k >> n = −1 ≠ 0` and is rejected. With a nonnegative dividend, BCH `%` returns a value
in `[0, r)`, so `in0, in1 ∈ [0, r)` and `in ± r` is rejected (tested). The Straus loop runs
over bits `nb..0`, which covers every bit of `k`, so the scalar applied to `IC1` is exactly
`k1 + k2·λ_GLV ≡ in0 (mod r)` (same for `IC2`). So `vk_x` is the true linear combination.

### 5. Rejection tests and evidence

On the shipped bytes, `in0 ± r`, `in1 + r`, `Ax + p`, `Ay − p`, `Bxa + p`, `Byb + p`, `Cy + p`
and `Ay → p − Ay` are all rejected, and the valid proof is accepted. Review notes:
`work/review-minop-1/NOTES.md` and `work/review-minop-2/NOTES.md`, with scripts for the
schedule parse, the constants, the G2 norm and the kernel differentials. These live in the
maintainer workspace and are not part of this repo.

No separate byte-optimized singleton: for a sound verifier the field tower is a ~15.8 KB floor and
every optimization either moves bytes into witness unlocking or adds locking, so the baseline is
already byte-optimal. The win is op-cost (`-minop`). All are honest single-tx baselines
(BCH-incompatible on script-size + op-cost) that motivate chunking.

Remaining: split across transactions for BCH limits (the chunked/ work) — the singleton
Miller is ~957M and finalExp ~255M op-cost, vs ~8.03M per input.

`miller_ref.mjs` is the proven blueprint for the in-script Miller loop: it
reproduces noble's `millerBoundary` (single-pair on the generators AND the 4-pair
Groth16 instance), matches golden `millerHex` exactly, and `finalExp==1`. It uses our
exact orchestration (pointDouble/pointAdd/mul034/NAF/postPrecompute) on noble's field
primitives — which our CashScript fp2/fp6/fp12 functions already match — so the
transcription composes. Constants captured there: `Fp2B` (twist b), `PSI_X/PSI_Y`
(Q1/Q2 map), `INV2`, the `6x+2` NAF (~65 steps).

Op-cost heads-up for chunking: the singleton Miller is ~65 steps × (1 Fp12 sqr +
~6 sparse line mults across 4 pairs); at ~1.2M op-cost per Fp12 mul that is on the
order of ~500M op-cost — far past one input's 8.03M budget, so the Miller loop is the
main thing task #8 must split across transactions.

Run a layer: `node singleton/bn254/fp2.mjs` (or fp6/fp12). Each prints
accept count, tamper-reject, and op-cost. `_harness.mjs` is the shared compile+eval loop.

Op-cost notes (loose VM, one spend invocation): Fermat Fp inverse ~2.7M (keep
inversions rare — only normalization/final-exp); one Fp12 mul ~1.2M.

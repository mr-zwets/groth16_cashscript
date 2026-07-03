# singleton/bn254/ — BN254 Groth16 verifier (singleton oracle)

The complete BN254 verifier: on-chain `vk_x` (`vkx.cash`), the field tower
(Fp2→Fp6→Fp12), the Miller loop, and final exponentiation. Built singleton-first (the
correctness oracle), bottom-up, grading each layer **directly against `@noble/curves`
bn254** on the loosened BCH 2026 VM — and `vkx.cash` is the oracle for `../../chunked/`.

Basis is locked to noble's tower so checkpoint #2 (`millerHex`) grades byte-for-byte:
`u²=−1`, `v³=9+u`, `w²=v`; an Fp12 is 12 ints in toBytes order
`c0.c0.c0 … c1.c2.c1`. See `../../../verifier/docs/pairing-checker.md`.

Every tower op is a reusable multi-return function (shared via `OP_DEFINE`/`OP_INVOKE`
unless the compiler decides inlining is byte-cheaper). This needs the local cashc
`feat/multi-returns` build (top-level functions + `import` + multi-return).

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
  c^-(6x+2)-fused Miller (lazy tower, fixed-VK line coeffs baked so only `(-A,B)` runs on-chain
  G2 arithmetic), witnessed-residue final-exp (2024/640), fast-endo 63-bit G2 check (2022/348),
  GLV `vk_x` — all extra inputs gated witnesses. Build: `node singleton/bn254/gen_singletons.mjs`,
  then `build_vectors_groth16_minop.mjs` + `VARIANT=minop node gen_multiproof_opt.mjs`.
  `pnpm benchmark`: `PASS`, **191,574,525 op-cost (−78%)**, ~24 inputs, 67,632 B — matches the
  chunked verifier's op-cost in ONE tx; beats scrypt on both bytes and op. The unroll (needed to
  bake coeffs as literals; runtime blob indexing is ~100 op/byte for OP_SPLIT) makes the script
  large and needs the cashc fork's large-contract compile fix (`COMPILER_FIX_NOTE.md` Fix 2).
- `bch-pairing-singleton` — the pairing-only milestone (leaderboard "Groth16 pairing
  (BCH-native)"). Build: `node singleton/bn254/build_vectors.mjs`. 20,735 B, ~1.21B, ~151 inputs.
  The standalone `vk_x` baseline (`bch-vkx-singleton`) builds with `node singleton/bn254/build_vectors_vkx.mjs`.

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

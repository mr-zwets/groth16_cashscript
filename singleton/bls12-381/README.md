# singleton/bls12-381/ — BLS12-381 Groth16 verifier (singleton oracle)

The complete Groth16 verifier on **BLS12-381** — the same curve as the nChain
reference, so the benchmark can compare on the same curve. On-chain `vk_x`
(`vkx.cash`), the field tower (Fp2→Fp6→Fp12), the Miller loop, and the final
exponentiation, all graded **directly against `@noble/curves` bls12-381** on the
loosened BCH 2026 VM. This is a file-for-file mirror of `../bn254/`; only the curve
constants and the Miller / final-exp orchestration differ.

## What differs from BN254 (`../bn254/`)

| concern | BN254 | BLS12-381 |
|---|---|---|
| base prime p | 254-bit / 32 B | **381-bit / 48 B** |
| sextic non-residue ξ | `9 + u` | **`1 + u`** → `fp2MulXi(a)=(a0−a1, a0+a1)` |
| G1 curve b | 3 | 4 (Jacobian formulas are b-independent) |
| G2 twist b′ | D-twist `Fp2B` | **M-twist `4·(1+u)`** → `mulByB(a)=(4a0−4a1, 4a0+4a1)` |
| line / sparse mul | `mul034` (divisive) | **`mul014` (multiplicative)** |
| ate loop | NAF of `6x+2` + Q1/Q2 ψ post-step | **NAF of `|x|`** (`x=−0xd201000000010000`), no post-step |
| x sign | positive | **negative → conjugate `f` at the end** |
| final exp hard part | BN scheme | **BLS / Hayashida–Scott** chain |

The Fp2 basis (u²=−1), pointDouble/pointAdd, Fp12 tower shape, and cyclotomic
squaring are identical; the tower/G1 layers are near-mechanical re-parameterizations.

## Files / status (all green vs noble on the loose VM)

| layer | contract | grader | graded vs noble | status |
|-------|----------|--------|-----------------|--------|
| Fp2  | `fp2.cash`  | `fp2.mjs`  | mul, sqr, inv, mulXi, conj | ✅ PASS (~6.8M) |
| Fp6  | `fp6.cash`  | `fp6.mjs`  | mul, sqr, mulByV           | ✅ PASS |
| Fp12 | `fp12.cash` | `fp12.mjs` | mul, sqr, conjugate        | ✅ PASS |
| Fp12 | `fp12_frob.cash` | `fp12_frob.mjs` | Frobenius p, p², p³ | ✅ PASS |
| Fp12 | `fp12_inv.cash` | `fp12_inv.mjs` | inverse (fp2Inv→fp6Inv→fp12Inv) | ✅ PASS |
| Miller | `miller_ref.mjs` (JS spec) | self-validating | single-pair + 4-pair batch + finalExp == noble | ✅ blueprint |
| Miller | `g2lines.cash` | `g2lines.mjs` | pointDouble / pointAdd (M-twist b) | ✅ PASS |
| Miller | `mul014.cash` | `mul014.mjs` | sparse multiplicative-twist line multiply | ✅ PASS |
| Miller | `miller.cash` | `miller.mjs` | single-pair loop == noble pairing(g1,g2,false) | ✅ PASS (~252M) |
| **Miller** | **`miller4.cash`** | **`miller4.mjs`** | **4-pair boundary == noble millerLoopBatch** | ✅ **cp#2** (~1.01B) |
| **FinalExp** | **`finalexp.cash`** | **`finalexp.mjs`** | **== noble; valid→1, invalid→≠1** | ✅ **cp#3** (~365M, 9.4 KB) |
| G1 (vk_x) | `vkx.cash` | `vkx.mjs` | IC0 + in0·IC1 + in1·IC2 (Jacobian, 255-bit loop) | ✅ PASS (3.9 KB) |
| **Verdict** | **`verify.cash`** | **`verify.mjs`** | **4 pairs → product → conj → finalExp → require==1** | ✅ **full pairing** (~1.38B, 19.8 KB) |
| **Verifier** | **`groth16.cash`** | **`groth16.mjs`** | **proof+inputs → vk_x on-chain → pairing → ==1** | ✅ **COMPLETE & SOUND** (~1.48B, 24.2 KB) |

`verify.cash` ties the pairing into the single intrinsic verdict
`e(−A,B)·e(α,β)·e(vk_x,γ)·e(C,δ)==1`; `groth16.cash` folds in the on-chain `vk_x`
(also standalone in `vkx.cash`) for the complete verifier.

## How it's built

`bls_instance.mjs` constructs a deterministic **valid** Groth16 instance (with
`B = 1·G2` and `A = a·b + vx·g + c·d` so the product is exactly Fp12 ONE; tampering
a public input changes `vk_x` and the verdict ≠ 1). `verify.cash`, `vkx.cash`, and
`groth16.cash` are thin consumers that `import` the shared field/pairing tower from
[`lib/`](lib/README.md) rather than re-declaring it, so they reuse the already-graded
function bodies. (Earlier these capstones were brace-assembled by an `assemble.mjs`
script; the shared import system replaced it.)

## Run

```
node singleton/bls12-381/fp2.mjs          # (or fp6 / fp12 / fp12_frob / fp12_inv)
node singleton/bls12-381/g2lines.mjs      # pointDouble / pointAdd
node singleton/bls12-381/mul014.mjs       # sparse line multiply
node singleton/bls12-381/miller_ref.mjs   # JS blueprint vs noble (fast)
node singleton/bls12-381/miller.mjs       # single-pair Miller (slow)
node singleton/bls12-381/miller4.mjs      # cp#2 4-pair boundary (very slow)
node singleton/bls12-381/finalexp.mjs     # cp#3 final exponentiation (slow)
node singleton/bls12-381/vkx.mjs          # vk_x G1 checkpoint
node singleton/bls12-381/verify.mjs       # pairing verdict (very slow)
node singleton/bls12-381/groth16.mjs      # full verifier (very slow)

node singleton/bls12-381/build_vectors.mjs          # -> pairing-bls12381-singleton-vectors.json
node singleton/bls12-381/build_vectors_groth16.mjs  # -> groth16-bls12381-singleton-vectors.json
node singleton/bls12-381/build_vectors_optimized.mjs# -> groth16-bls12381-singleton-opcode-optimized{,-multiproof}-vectors.json
```

## Op-optimized variant (`groth16_minop.cash`, generated)

`gen_singleton_minop.mjs` emits the BLS analog of `../bn254/groth16_minop.cash`
(`bch-groth16-bls12381-singleton-minop`): lazy tower + ONE batched c^-|x|-fused Miller
(only `(-A,B)` runs on-chain G2; `e(alpha,beta)` and the `(vk_x,gamma)`/`(C,delta)` line
coefficients baked) + witnessed-residue final exp + GLV vk_x. 65,474-byte locking,
**~256.6M op-cost (~32 inputs) vs the baseline's ~966M (~121) as currently measured
by the harness** — ~73% less (~83% vs the 1.48B the baseline measured pre-rescheduler).

BLS-specific differences vs the BN254 min-op (see `../../chunked/bls12-381/_residuemath.mjs`):

- residue relation `c^lambda == g*w` with `lambda = p + |x|`; the tail is a single
  Frobenius: `gF*w == frob(c,1)`, on the **unconjugated** boundary (x<0's final
  conjugation is absorbed into the witness — conj is an automorphism);
- the witness scaling group is `mu_27A`, `A = (|x|+1)/3 = gcd(m'', p^12-1)` (real valid
  boundaries DO carry an A-part in their order, removed by a one-exponentiation
  projection); the on-chain membership check is `((w^|x|) * w)^9 == 1` (27A = 9(|x|+1),
  |x| sparse: 6 bits);
- the G2 subgroup check `psi(B) == [-x]B` is fused into the Miller tail and reuses
  `[|x|]B`;
- G1 subgroup checks for A and C are omitted as redundant: both points remain checked
  on-curve and are paired only with order-`r` G2 points, so their cofactor components
  pair trivially. This matches the grouped/intra-tx residue verifiers.

```
node singleton/bls12-381/gen_singleton_minop.mjs         # regenerate groth16_minop.cash
node singleton/bls12-381/build_vectors_groth16_minop.mjs # -> groth16-bls12381-singleton-minop-vectors.json
node singleton/bls12-381/gen_multiproof_minop.mjs        # -> ...-minop-multiproof-vectors.json
```

## In the verifier benchmark

Entries on the **same curve as nChain** (so a true apples-to-apples size
comparison, unlike the BN254 entries):

- `bch-groth16-bls12381-singleton` — the COMPLETE verifier, plain compiler output
  (size objective + rescheduleStacks, no post-passes); 7,698-byte locking, ~966M
  op-cost (~121 BCH inputs). **Far smaller bytecode than the nChain reference.**
- `bch-groth16-bls12381-singleton-opcode-optimized` — the byte-optimized COMPLETE
  verifier (`build_vectors_optimized.mjs`: golf recompile A/B'd vs the rescheduled
  compile, then auto-outlining); **5,789-byte locking**, ~1.004B op-cost. The pair shows the
  bytesize-vs-opcost tradeoff, mirroring the BN254 plain/optimized split.
- `bch-groth16-bls12381-singleton-minop` — the op-optimized COMPLETE verifier
  (`groth16_minop.cash`); 67,163 total bytes, **~256.6M op-cost (~32 inputs)** vs the baseline's
  ~966M (~121) on the current harness.
- `bch-pairing-bls12381-singleton` — the pairing-only milestone (`verify.cash`);
  ~19.8 KB, ~1.38B op-cost.

All are honest single-tx baselines (BCH-incompatible: op-cost, plus script-size for
the minop variant) that
motivate a future `chunked/bls12-381/` multi-tx verifier, exactly as the BN254 work
sequenced singleton → chunked.

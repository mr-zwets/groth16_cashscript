# singleton/bls12-381/ — BLS12-381 Groth16 verifier (singleton oracle)

> **Domain checks added (2026-10-26).** The bench entries built from `groth16.cash`,
> `bch-groth16-bls12381-singleton` and `bch-groth16-bls12381-singleton-opcode-optimized`, were
> held as withdrawn on maintainer review because `groth16.cash` range-checked only the public
> inputs. It now validates the proof points before any pairing work (see
> [Proof-point validation](#proof-point-validation)): every coordinate is range-checked
> (`0 <= v < p`), A and C must satisfy `y^2 = x^3 + 4`, B must satisfy the twist equation
> `y^2 = x^3 + 4(1+u)`, and B must pass the G2 subgroup check `psi(B) == [x]B` (x < 0, so `[x]B = -[|x|]B`), fused into B's
> Miller walk with a `Z != 0` guard. Both entries are rebuilt with their original pipelines.
> An independent review (2026-10-26) found no soundness gaps; its minor follow-ups (more
> non-canonical-encoding tests, the cofactor-malleability note below) are done, and both entries
> are marked reviewed. `bch-groth16-bls12381-singleton-minop`
> (`groth16_minop.cash`) is a separate source and is not affected.

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
| **Verifier** | **`groth16.cash`** | **`groth16.mjs`** | **proof+inputs → vk_x on-chain → pairing → ==1** | ✅ **COMPLETE** (~1.48B, 24.2 KB; pre-rescheduler numbers) |

`verify.cash` ties the pairing into the single intrinsic verdict
`e(−A,B)·e(α,β)·e(vk_x,γ)·e(C,δ)==1`; `groth16.cash` folds in the on-chain `vk_x`
(also standalone in `vkx.cash`) for the complete verifier.

## Proof-point validation

`spend()` checks the proof points before vk_x and the Miller loops:

| check | how |
|---|---|
| public inputs `0 <= in < r` | `within` (unchanged) |
| coordinates `0 <= v < p` | `within(v, 0, P)` on Ax, Ay, Bxa, Bxb, Bya, Byb, Cx, Cy |
| A, C on `E(Fp)`: `y^2 = x^3 + 4` | `g1Check(x, y)` (range + curve), one body called twice |
| B on `E'(Fp2)`: `y^2 = x^3 + 4(1+u)` | two `fp2Sqr` and one `fp2Mul` |
| B in G2: `psi(B) == [x]B` (x < 0) | fused into B's Miller walk (below), no separate `[\|x\|]B` walk |

**Points at infinity.** The affine encoding has no point at infinity, and `(0,0)` is off both
curves, so A = O, B = O and C = O are all rejected by the curve checks. The honest fixtures never
use them (`B = 1*G2`, A and C nonzero multiples of the G1 generator).

**G2 subgroup check.** The `(-A, B)` Miller loop now runs through `millerSingleR`
(`lib/Miller.cash`), which also returns its homogeneous accumulator `R = (X:Y:Z)`. The NAF walk
starts at `R = B` and ends at `[|x|]B` whenever every step is a regular double/add. Every
exceptional step (`R = ±B` in `pointAdd`, `R` of order 2 in `pointDouble`) produces `Z = 0`, and
`Z = 0` is absorbing under both formulas, so `require(Rza + Rzb != 0)` leaves only faithful walks;
then `X == psi(B).x * Z` and `Y == -psi(B).y * Z` check `psi(B) == -[|x|]B = [x]B`, which holds
exactly for B in G2. `psi` is `g2psi` from `lib/G2Check.cash`. This is the same fused check (and
guard) as `groth16_minop.cash`; see [psi-subgroup-degeneracy.md](../../psi-subgroup-degeneracy.md)
for the order-13 collapse that the guard closes. The other three pairs also call
`millerSingleR`, so the bytecode keeps one Miller body, and drop the extra outputs (cashc
prints unused-variable warnings for them).

**No G1 subgroup check on A, C.** Both are paired only with order-r G2 points (B is checked,
gamma and delta are fixed), so a G1 cofactor component pairs to 1, as in `groth16_minop.cash`.

**Cofactor malleability (not a soundness issue).** Because of this, `A + T` and `C + T` also verify
for any point `T` of order dividing the G1 cofactor `h1` (`gcd(h1, r) = 1`; for example `(0, 2)`,
of order 3): the pairing values are unchanged. These variants are the same proof up
to a cofactor component. Projecting with `[h1 * (h1^-1 mod r)]` recovers the honest `A` and `C`,
which can be done efficiently, so a verifying `(A, B, C)` still proves knowledge exactly as a
standard Groth16 proof does. This is malleability only. It matters only if an application uses
the proof bytes themselves as an identifier or nullifier. Such an application should bind the
public inputs instead, as it must for Groth16 anyway, since Groth16 proofs are re-randomizable.
(B has no such variants: it must be in G2.)

**Tests.** `domain_checks_test.mjs` runs the honest instance, the bench multiproof set, and 17
out-of-domain cases from `domain_cases.mjs`: off-curve A and C, off-twist B, `(0,0)` for A, B and
C, B on the twist but outside G2 (`B + T13` with `T13` of order 13, `T13` alone, and `B + [r]Q`),
and non-canonical coordinates (`Ax + p`, `Cx + p`, `Cy + p`, `Bxa + p`, `Bxb + p`, `Bya + p`,
`Byb + p`, `Ay - p`). For B the range check is the only guard against a second encoding (the
twist equation is evaluated mod p), so each of its four coordinates has its own case. All are
rejected. The
op-cost at rejection shows where each one fails: about 20k-190k for the range and curve checks,
about 0.1-0.19B for the subgroup check (after vk_x and B's Miller loop), and about 1B for a
pairing mismatch. Before this change the non-canonical encodings tested at the time (`Ax + p`,
`Cy + p`, `Byb + p`, `Ay - p`) were **accepted** (the same point under a second encoding); the off-curve and off-subgroup cases with the honest A/C
happened to fail the pairing equation. The vector builders ship the 17 cases to the bench as
extra invalid runs and fail the build if any is accepted.

| entry | locking before → after | bench score before → after | op-cost before → after |
|---|---|---|---|
| `bch-groth16-bls12381-singleton` | 6,863 → 7,026 B | 7,347 → 7,510 B | 978,824,303 → 994,589,979 |
| `bch-groth16-bls12381-singleton-opcode-optimized` | 5,344 → 5,515 B | 5,828 → 5,999 B | 1,002,455,753 → 1,003,512,299 |

(Bench score = locking + unlocking + transaction overhead; the "before" scores are the committed
`results.json` values.)

The checks themselves cost about 0.1M op-cost on the valid path; most of the plain entry's
+15.8M op-cost comes from the rescheduler laying out the larger program differently (a build
that kept `g2psi`/the curve checks inline in `spend()` measured 7,296 B / 979.2M, so the
committed source trades +15M op-cost for -270 B, the scored quantity).

```
node singleton/bls12-381/domain_checks_test.mjs                 # compile groth16.cash and run all cases
node singleton/bls12-381/domain_checks_test.mjs <vectors.json>  # same, against a built lockingOK
```

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
node singleton/bls12-381/domain_checks_test.mjs  # proof-point validation: 17 out-of-domain cases (slow)

node singleton/bls12-381/build_vectors.mjs          # -> pairing-bls12381-singleton-vectors.json
node singleton/bls12-381/build_vectors_groth16.mjs  # -> groth16-bls12381-singleton-vectors.json
node singleton/bls12-381/build_vectors_optimized.mjs# -> groth16-bls12381-singleton-opcode-optimized{,-multiproof}-vectors.json
```

## Op-optimized variant (`groth16_minop.cash`, generated)

`gen_singleton_minop.mjs` emits the BLS analog of `../bn254/groth16_minop.cash`
(`bch-groth16-bls12381-singleton-minop`, status **reviewed** after two independent constructive
reviews on 2026-10-27). It combines a lazy tower, ONE batched `c^-|x|`-fused Miller loop (only
`(-A,B)` runs on-chain G2 arithmetic; `e(alpha,beta)` and the `(vk_x,gamma)`/`(C,delta)` line
coefficients are baked), a **quotient-torus** residue verdict in place of the final
exponentiation, and GLV `vk_x`. Shipped: **58,007 B locking, 58,841 B scored, 145,596,803 op-cost
(19 inputs; worst case 171,126,234)**, against 994,589,979 (124 inputs) for the
`bch-groth16-bls12381-singleton` baseline on the current harness (about 85% less).
`node gen_singleton_minop.mjs` regenerates the `.cash` byte for byte, and the cashc fork
(`rescheduleStacks: true`) recompiles it to the shipped `lockingOK`.

The spend takes 21 arguments: `Ax, Ay, Bxa, Bxb, Bya, Byb, Cx, Cy, in0, in1, u0..u5, k10, k20,
k11, k21, vkxZinv`. There are no slope witnesses, and the only inverse witness is `vkxZinv` (fixed by an exact
equation, see the table): the G2 walk is homogeneous projective, and the GLV accumulator is Jacobian.

### Soundness (owner table)

Line numbers refer to `groth16_minop.cash`; kernels live in `lib/lazy/`.

| value | owner | where |
|---|---|---|
| `Ax, Ay, Cx, Cy` | canonical and on `y^2 = x^3 + 4`. No G1 subgroup check: see the cofactor note above (malleability only) | L18-35 |
| `Bxa..Byb` | canonical and on `y^2 = x^3 + 4(1+u)`. In G2 by the fused psi check below | L18-40, L413-419 |
| `u0..u5` (residue root) | canonical. Otherwise free: the verdict argument holds for **every** `u` | L28-33 |
| `k10, k20, k11, k21` | `within(k, 0, 2^128)` | L42 |
| `in0, in1` | exact equation `in = (k1 + k2*lambda_GLV) % r` with `k >= 0`, so `in` lies in `[0, r)` | L43-44 |
| GLV table, `IC0`, `lambda_GLV = -x^2 mod r` | VK constants: the 15 entries are the subset sums of `{IC1, phi(IC1), IC2, phi(IC2)}`, `phi(x,y) = (beta*x, y) = [lambda_GLV]` | L43-57 |
| `vk_x` | computed on-chain: a fixed 128-iteration MSB Straus loop over all bits of `k`. `jacAddG1` is complete (`O + Q`, `P == Q` goes to doubling, `P == -Q` gives `Z = 0`), and the final addend is `IC0` | L45-61 |
| `vkxZinv` | exact equation `icz * vkxZinv == 1`. This forces `vk_x != O` and an exact affine conversion | L58-61 |
| runtime G2 lines and `R` | computed on-chain by `pointDouble` / `pointAdd` (`Bls12381Lazy.cash:333, 362`) from `B`; each line is evaluated once at `-A = (Ax, -Ay)` | L62-411 |
| baked `(vk_x,gamma)`, `(C,delta)` lines | VK constants: the 69 + 69 lines of the projective walk of gamma and delta on the `|x|` schedule, recomputed independently by both reviews | L62-411 |
| baked `e(alpha,beta)` torus constant `K` | VK constant: `[1 + tW]` with `FE(K)` matching the model `e(alpha,beta)` (recomputed by review 1; an accepted honest proof also pins `K^FE`) | L412 |
| `psi`, `torusFrob1` constants | curve constants. `torusFrob1` uses `xi^((p-1)/3)`, `xi^(2(p-1)/3)`, `xi^((p-1)/6)`, and `fp2Half = (p+1)/2`. The psi coefficients map E' to E' and satisfy `psi^2 - (x+1) psi + p = 0`. Both reviews recomputed these against noble | `Bls12381LazyG.cash:92`, `Bls12381LazyTorus.cash:27` |
| Fp12 accumulator | computed on-chain as one SSA chain from the genesis `[1 - uW]` (squared by the first op, L67) through every square, line and `c`/`c^-1` fold | L62-412 |

The verifier is one input with no introspection, state or sibling inputs, so there is no
multi-input binding to argue.

**Miller schedule.** The runtime walk starts at `R = B` and runs 64 doubles and 5 adds over
`|x| = 0xd201000000010000` on a signed-digit schedule: one `-B` add (with a `c` fold) and four
`+B` adds, so the double count is 64, not 63. Every Fp12 op consumes the previous Fp12 output, and every G2 op
consumes the previous point. The `c` exponent is exactly `-|x|`. The loop is unconjugated, so
it computes the Miller value of `[|x|]`, whose final exponentiation is the inverse of the ate
pairing for `x`. It is used consistently for all four pairs and for `K`, so the verdict still
expresses the Groth16 equation.

**Residue verdict (quotient torus, no `w`, no `c*cInv` gate).** The accumulator lives in
`Fp12*/Fp6*`, with `[c] = [1 + uW]` and `[c^-1] = [1 - uW]`, because `(1+uW)(1-uW) = 1 - u^2 v`
lies in Fp6. The terminal (L420-424) reduces the final accumulator to `tF = (tF_a, tF_b)` with
limbs `mulFp(., 1)` in `(-p, p)`. It then requires:

1. `sum(tF) != 0`. A limb in `(-p, p)` that is `0 mod p` is exactly 0, so this rejects the
   vacuous `[0:0]`. A nonzero class whose signed limbs sum to 0 is also rejected, which costs
   completeness only, with negligible probability.
2. `tF_a * frob1(u) == tF_b` mod p, limb by limb, i.e. `[tF] = [1 + frob1(u) W] = [c^p]`. With
   `tF != [0:0]`, `tF_a = 0` would force `tF_b = 0`, so this is an exact class equality.

Write `f` for the Miller value of `(-A,B)`, `(vk_x,gamma)` and `(C,delta)`. An accepted spend
gives `f * K = c^(p+|x|) * s` with `s` in `Fp6*`. Here `r | p + |x|` (`p ≡ x mod r`, x < 0), and
`p^6 - 1` divides `(p^12 - 1)/r`. Raising to `(p^12-1)/r` therefore kills both factors for any
`u`, which leaves `e(-A,B) * e(alpha,beta) * e(vk_x,gamma) * e(C,delta) = 1`.

**G2 membership (fused psi check).** L413 requires `Z != 0` on the final `R`. `Z = 0` is
absorbing under both formulas: `pointDouble` gives `nZ = 2Y^3 Z` and `pointAdd` gives
`nZ = Z t1^3`. Every exceptional step (`R = ±B` in an add, `Y = 0` in a double) produces `Z = 0`.
So `Z != 0` means every step was a regular group operation and `R = [|x|]B` exactly. This
closes the vacuous case in [psi-subgroup-degeneracy.md](../../psi-subgroup-degeneracy.md).

L414-419 then require `X == psi(B).x * Z` and `Y == -psi(B).y * Z`, i.e.
`[|x|]B = -psi(B)`, i.e. `psi(B) = [x]B` (x negative). On `E'(Fp2)`,
`psi^2 - (x+1) psi + p = 0`, `N(psi - x) = p - x`, `gcd(p - x, h2) = 1` and `r ∤ h2`. So
`psi(B) = [x]B` holds exactly for B in G2. The compares are integer equalities of reduced
values, which implies congruence.

**What changed from the earlier construction.** Earlier revisions of this section described a
witness `w` in the embedded `Fp6*`, a "six zero upper limbs" membership check and a
`c*cInv == 1` gate. The shipped quotient-torus code has none of these: `w` vanishes in the
quotient, and `[c^-1]` is `[1 - uW]` by construction. The model is
`../../chunked/bls12-381/_residuemath.mjs`.

```
node singleton/bls12-381/gen_singleton_minop.mjs         # regenerate groth16_minop.cash
node singleton/bls12-381/build_vectors_groth16_minop.mjs # -> groth16-bls12381-singleton-minop-vectors.json
node singleton/bls12-381/gen_multiproof_minop.mjs        # -> ...-minop-multiproof-vectors.json
```

## In the verifier benchmark

Entries on the **same curve as nChain** (so a true apples-to-apples size
comparison, unlike the BN254 entries):

- `bch-groth16-bls12381-singleton` — plain compiler output (size objective +
  rescheduleStacks, no post-passes); 7,026-byte locking, ~995M op-cost (~124 BCH inputs),
  with the proof-point validation above (range, curve, G2 subgroup).
- `bch-groth16-bls12381-singleton-opcode-optimized` — the byte-optimized build of the
  same source (`build_vectors_optimized.mjs`: golf recompile A/B'd vs the rescheduled
  compile, then auto-outlining); 5,515-byte locking, ~1.004B op-cost. The pair shows the
  bytesize-vs-opcost tradeoff, mirroring the BN254 plain/optimized split.
- `bch-groth16-bls12381-singleton-minop` — the op-optimized COMPLETE verifier
  (`groth16_minop.cash`); 58,007 B locking / 58,841 B scored, **145,596,803 op-cost (19 inputs)**
  vs the baseline's 994,589,979 (124) on the current harness.
- `bch-pairing-bls12381-singleton` — the pairing-only milestone (`verify.cash`);
  ~19.8 KB, ~1.38B op-cost.

All are honest single-tx baselines (BCH-incompatible: op-cost, plus script-size for
the minop variant) that
motivate a future `chunked/bls12-381/` multi-tx verifier, exactly as the BN254 work
sequenced singleton → chunked.

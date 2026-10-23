# Hybrid-direct (HD-τSZ): exact lines, torus-normalized states, minop verdict

**Status:** design plus an end-to-end hot-section prototype on the VM. Not a full verifier:
the vk_x MSM and the terminal verdict are measured standalone and added.
**Measured score:** 36,603 B (36,503 B; 37.04M worst-case op against a 37.20M budget).
**Review:** sound. 2 major issues (missing G2-subgroup derivation; projective zero-line hazard)
and 5 minor issues, all folded into the spec below. The measured configuration differs from the
reviewed one in format and completeness choices, not in the identities: canonical limbs are
checked with `WITHIN [1, p)` instead of a negative-zero rule, structurally zero top Q
coefficients are dropped from the format (nQ 80/77 instead of 81), the concrete projective
formulas were written after the review (`check-proj.mjs` verifies them), and the affine-prefix
K = 16 / F1-at-64 mix is new. These have not been re-reviewed.

The most conservative of the three designs: it keeps the existing sound pieces (msm-single for
vk_x, groth16_minop's torus residue verdict, minop's fused ψ endpoint) and replaces only the exact
Fp12 Miller accumulator with committed torus checkpoints checked by batched Schwartz–Zippel at
`±z`. It runs three Miller pairs, including the γ pair.

## Notation

- `Fp12 = Fp[X]/M`, `M = X¹² − 18X⁶ + 82`; `w = X`, `v = X²`, `u = X⁶ − 9` (noble tower, as in
  densless). `Fp6` = even powers.
- **Torus chart:** `τ(g) = 1 + X·g(X²)` for `g ∈ Fp6` given as 6 tower limbs
  `(A₀.c₀, A₀.c₁, A₁.c₀, A₁.c₁, A₂.c₀, A₂.c₁)` of `g = A₀ + A₁v + A₂v²`. At z, with `s = z⁶ − 9`:
  `g(z²) = A₀.c₀ + A₀.c₁·s + (A₁.c₀ + A₁.c₁·s)z² + (A₂.c₀ + A₂.c₁·s)z⁴`, and
  `τ(g)(±z) = 1 ± z·g(z²)`, `τ(−g)(z) = τ(g)(−z)`. `τ(g)·τ(−g) = 1 − v·g² ∈ Fp6*` (nonzero:
  v is not a square in Fp6), so `[τ(−g)] = [τ(g)]⁻¹` in `Fp12*/Fp6*`.
- **Residue root** (minop / ePrint 2024/640): `c = [1 + u·w] = [τ(u)]`, u ∈ Fp6 (6 limbs);
  `c⁻¹ = [τ(−u)]`.
- **Lines** `(c_y, c_λ, c_β) ∈ Fp2³` at P: `l(X) = y_P·c_y − x_P·X·c_λ + X³·c_β` (Fp2 coefficients
  mapped by `u ↦ X⁶ − 9`, degree 9). At ±z: `l(±z) = e ± o`, `e = y_P·(c_y,₀ + c_y,₁·s)`,
  `o = a₁·c_λ,₀ + a₂·c_λ,₁ + z³·c_β,₀ + z³s·c_β,₁` with per-pair `a₁ = −x_P·z`, `a₂ = a₁·s`.
  - affine unit line: `(1, λ, β)`, `β = λx_T − y_T`;
  - projective doubling: `(2YZ, 3X², Y² − 3b'Z²)`;
  - projective mixed addition with affine Q: `(λ', θ, θx_Q − λ'y_Q)`, `θ = Y − y_QZ`, `λ' = X − x_QZ`.
- **Pairs:** 0: `P = −A`, `Q = B` (runtime); 1: `P = vk_x`, `Q = γ` (fixed); 2: `P = C`, `Q = δ`
  (fixed). `K = [τ(κ)]`, `κ = c₁/c₀` of `Miller(α, β)` (baked torus coordinate).
- **Events** e = 0..64 with NAF digits `d_e` (21 nonzero):
  `Φ_e = (3 doubling lines) · (3 addition lines and τ(−d_e·u) if d_e ≠ 0)`; event 64 also carries
  the 6 Frobenius lines (`ψ(Q)`, `−ψ²(Q)` per pair) and K. 264 lines in total.
- **Segments:** 36 contiguous event ranges, byte-optimal under a degree cap of 174
  (`schedule.mjs`): `[0,1] [2,3] … [18,19] [20] [21,22] … [27,28] [29] [30,31] [32,33] [34] [35,36]
  [37,38] [39] [40,41] … [48,49] [50] [51,52] … [55,56] [57] [58,59] [60,61] [62,63] [64]`
  (pairs except singletons at 20, 29, 34, 39, 50, 57, 64).
  For segment j over `[a..b]`: `P_j` = (`P ← P²·Φ_e` for e = a..b) started at `τ(G_{j−1})`,
  `G_{−1} = −u`; `R_j(X) = P_j(X)·τ(−G_j)(X)`, `deg R_j ≤ 174`. Relation j: the odd part of
  `R_j mod M` is zero, i.e. `Q_j = (R_j(X) − R_j(−X))/M` exists (odd, degree ≤ 162).

## Protocol

### Witness (measured configuration)

| Item | Encoding | Bytes |
|---|---|---|
| n₀, n₁; A (x, y), B (x₀, x₁, y₀, y₁), C (x, y) | numbers | ~330 |
| MSM witness for msm-single (`w` 64 B, `zInv`) | as msm-single | 98 |
| `u₀..u₅` | numbers | ~200 |
| STATES | one blob, 36 × 6 × 32-B LE limbs = `G₀..G₃₅` | 6,915 |
| QBLOB | odd coefficients, descending (`q₁₅₉, …, q₃, q₁`), 32-B LE | 80 × 32 + 3 |
| B slopes | 2 limbs per affine B step, events 0–15 (16 doublings + 6 additions) | 1,452 |

`q₁₆₁` is structurally zero (`q₁₅₅..q₁₆₁` when all B steps are affine), so it is dropped from the
format (nQ = 80, or 77 all-affine); the build asserts this. The reason is parity, not the B mode:
every factor (lines with terms `X^{0,1,3,6,7,9}`, `τ = 1 + X·g(X²)`) lacks its degree-(top−1)
term, so every degree-174 `R_j` has a zero `X¹⁷³` coefficient.

### Transcript

```
T₀ = SHA256(DOMAIN ‖ enc(n₀) ‖ enc(n₁) ‖ enc(A.x) ‖ enc(A.y) ‖ enc(B.x₀) ‖ enc(B.x₁) ‖ enc(B.y₀)
            ‖ enc(B.y₁) ‖ enc(C.x) ‖ enc(C.y) ‖ enc(u₀) ‖ … ‖ enc(u₅) ‖ STATES)
g  = BIN2NUM(SHA256(T₀ ‖ 0x01) ‖ 0x00) mod p
z  = BIN2NUM(SHA256(T₀ ‖ 0x02 ‖ QBLOB) ‖ 0x00) mod p
```

`enc` is a 32-byte LE NUM2BIN. DOMAIN must commit to the verification key (the prototype uses a
placeholder digest). vk_x and the B slopes are not hashed: both are uniquely fixed by exact checks.

### On-chain steps

1. **Ranges and lengths.** `|STATES| = 6912`, `|QBLOB| = 32·nQ`; every number limb in `[0, p)`;
   `0 ≤ n₀, n₁ < r`; every STATES and QBLOB limb (after BIN2NUM) in `[1, p)`; slopes in `[0, p)`.
2. **Curve checks.** A, C on `y² = x³ + 3` (G1 has prime order); B on the twist.
3. **vk_x** = msm-single GLV Straus(n₀, n₁; w, zInv), reused as is (exact; rejects O and
   exceptional additions); vk_x re-checked on the curve.
4. **Challenges** g and z as above.
5. **Precompute** `z², z³, z⁴, z⁶, s, z³s`, basis `(1, s, z², sz², z⁴, sz⁴)`, `M(z)`; `a₁, a₂, y_P` per
   pair (`y_P·s` for pair 0); `U = u(z²)`, `zU = z·U` so `c^{∓1}(±z) = 1 ∓ zU`; `K(±z) = 1 ± z·κ(z²)`.
   Split STATES into 36 chunks of 192 B.
6. **Initialize** `T_B = (B.x : B.y : 1)`, `T_γ = γ`, `T_δ = δ` (baked); `acc₊ = 1 − zU`,
   `acc₋ = 1 + zU` (`c⁻¹(±z)`); `S = 0`, `g_j = 1`.
7. **For e = 0..64:**
   1. B doubling with the square of both accumulators: projective (`BDBL`), or for e < 16
      `acc± ← acc±²` and an affine step with the witnessed slope, checked `2y·λ == 3x²` (`ABDBL`).
      Then `acc₊ ← acc₊·(e + o)`, `acc₋ ← acc₋·(e − o)` for the step's line.
   2. γ and δ doubling (F2): baked `λ_k`; on-chain `β = λx − y`, `x' = λ² − 2x`, `y' = β − λx'`
      (y kept unreduced, < 2⁵¹³); fold the line.
   3. If `d_e ≠ 0`: `acc₊ ← acc₊·(1 − d_e·zU)`, `acc₋ ← acc₋·(1 + d_e·zU)` (the `c^{−d_e}` fold);
      B addition with `(B.x, d_e·B.y)` (projective `BADD`, or affine `ABADD` with chord check
      `λ(x_Q − x) == y_Q − y` and `x_Q − x ≠ 0`); γ and δ additions (F2 with baked `x_Q`); fold
      every line.
   4. If e = 64: `ψ(B)` and `−ψ²(B)` computed on-chain, B additions with both, γ and δ Frobenius
      lines from baked `(λ, β)` (F1); `acc± ← acc±·K(±z)`; then the **exact B endpoint**
      `X_T = x(−ψ³B)·Z_T`, `Y_T = y(−ψ³B)·Z_T` with `Z_T ≠ 0`.
   5. If e ends segment j: parse `G_j` from its 192-B chunk; `t = z·G_j(z²)`;
      `R₊ = acc₊·(1 − t)`, `R₋ = acc₋·(1 + t)`; `S ← S + g_j·(R₊ − R₋)`; `g_j ← g_j·g`;
      `acc₊ ← 1 + t`, `acc₋ ← 1 − t`.
8. **Quotient.** `Q(z) = z·Horner_{z²}(q₁, q₃, …)`; require `(S − Q(z)·M(z)) mod p == 0`.
9. **Terminal verdict** (groth16_minop, adapted to a 6-limb state):
   `[τ(G₃₅)·c^{p²}] == [c^p·c^{p³}]` in `Fp12*/Fp6*`, with the Frobenius maps written on the torus
   coordinate (`Frob(τ(g)) = τ(γ₁·Frob(g))`): `t₁ = γ₁·Frob(u)`, `t₂ = η·Frob²(u)`, `t₃ = η·Frob²(t₁)`,
   `γ₁ = ξ^{(p−1)/6}`, `η = ξ^{(p²−1)/6}`, `Frob` the Fp6 Frobenius (minop's constants;
   `ref.mjs` uses the full Fp12 Frobenius); with `τ(a)τ(b) = (1 + v·ab) + w(a + b)`, cross-multiply
   `(1 + v·G₃₅t₂)·(t₁ + t₃) == (G₃₅ + t₂)·(1 + v·t₁t₃)` in Fp6 (each limb `(l − r) mod p == 0`).
10. **Accept iff** every check passes and the clean-stack rule holds.

ψ: `ψ(x, y) = (x̄·ξ^{(p−1)/3}, ȳ·ξ^{(p−1)/2})`, `ψ²(x, y) = (x·ξ^{(p²−1)/3}, −y)`, `ξ = 9 + u`.

Variants: **F1** bakes `(λ, β)` for every fixed line (no on-chain fixed T: fewer ops, more bytes);
**F2** bakes λ only. The B walk can be all projective, all affine (witnessed slopes), or an
affine prefix of K events. The measured optimum is affine for events 0–15, projective after,
F2 except F1 at event 64.

## Committed before the challenge vs computed on-chain

**Hashed into T₀ before g and z:** DOMAIN/VK digest, n₀, n₁, A, B, C, `u₀..u₅`, all 36 states.
**Hashed before z (after g):** QBLOB. Q is the only value supplied after g; nothing is supplied
after z.
**Fixed by exact equations (not hashed):** vk_x (msm-single), the affine B slopes (slope
equations with nonzero denominators), the projective B trajectory (Z gates).

**Computed on-chain:** g, z; vk_x; the B, γ and δ walks and all line coefficients; ψ(B), ψ²(B),
ψ³(B); every evaluation at ±z (lines, `c^{±1}`, K, `τ(G_j)`, accumulators, `R_j(±z)`), S, Q(z), M(z);
the terminal Frobenius images.
**Baked:** γ, δ, fixed-line λ (and β for F1 lines), κ, ψ and Frobenius constants, DOMAIN.
**Checked exactly:** ranges, lengths, curve equations, slope equations, `Z_T ≠ 0`, the B endpoint,
the batched equation, the terminal verdict.

## Soundness argument

1. **What the batched identity means.** Every factor polynomial is fixed by T₀: lines depend only
   on A, B, C, vk_x and VK constants (vk_x depends only on n₀, n₁; B lines are exact); `τ(±u)`, K
   and the `G_j` are hashed. Let `r_j = (R_j(X) − R_j(−X)) mod M`. M is even, so reduction commutes
   with `X ↦ −X` and `r_j = 2·odd part of (R_j mod M)`. If `r_j = 0`, `R_j mod M ∈ Fp6`, i.e.
   `P_j·τ(−G_j) ∈ Fp6`. `P_j ≠ 0`: the even (Fp6, `w⁰`) part of every line is `y_P·Φ(c_y)`, where
   `Φ` is the injective map `u ↦ X⁶ − 9`; it is nonzero because `y_P ≠ 0` (G1 has no 2-torsion) and
   `c_y` = 1, `2YZ` or `λ'` is nonzero by item 5. (The single `X⁰` coefficient
   `y_P·(c_y,₀ − 9c_y,₁)` can vanish; the argument does not use it.) τ and K are nonzero.
   So `[P_j] = [τ(G_j)]`.
2. **Two-round Schwartz–Zippel.**
   - g step: if some `r_j ≠ 0`, `Σ_j g^j r_j` vanishes with probability ≤ 35/p (degree ≤ J − 1 = 35).
   - z step: otherwise `S(X) = Σ_j g^j (R_j(X) − R_j(−X))` is not divisible by M, so for Q fixed
     before z, `D = S − Q·M` is a nonzero polynomial of degree ≤ 174 (D is odd, so in fact ≤ 173; the segment degrees are fixed
     by the schedule; `deg Q·M ≤ 2·80 − 1 + 12`): probability ≤ 174/p. D is odd, so `D(0) = 0`
     always and `D(z) = 0 ⇔ D(−z) = 0`; both are inside the bound.
   - On-chain `S(z)` is exactly S evaluated at z, since evaluation is a ring homomorphism and every
     factor is evaluated from exactly computed coefficients. M has no roots in Fp.
   - Per random-oracle query `ε ≤ 1.134·(35 + 174)/p ≈ 2^{−245.7}`; total `q_H·2^{−245.7}`.
3. **Chaining.** With `G_{−1} = −u` (computed), induction gives
   `[τ(G₃₅)] = [f_raw·K·c^{−(6x+2)}]`: the accumulator starts at `c⁻¹`, is squared 65 times and folded
   with `c^{−d_e}` at each nonzero digit.
4. **Residue.** The verdict gives `[f_raw·K] = [c^{6x+2+p−p²+p³}] = [c^λ]`, i.e. `f_raw·K = c^λ·h` with
   `h ∈ Fp6*`. `λ ≡ 0 (mod r)` and `(p⁶ − 1) | (p¹² − 1)/r`, so the final exponentiation of
   `f_raw·K` is 1: the Groth16 equation, since `f_raw` is the optimal-ate Miller product up to Fp2
   line scalings. The usual residue scaling w lies in Fp6 (`ref.mjs` asserts `w.c₁ = 0`) and is
   absorbed. The cross-multiplied verdict is a correct class test because both sides are nonzero
   (`τ(G₃₅)` is invertible, `c ≠ 0`).
5. **B binding and G2 membership.** The walk starts at the hashed, on-curve B. Affine steps have
   checked slopes with nonzero denominators (`x_Q − x ≠ 0` checked; `y ≠ 0` because `E'(Fp2)` has
   odd order). Projective steps have `Z₃ = 8Y³Z` (doubling) and `Z₃ = Z·λ'³` (addition), so Z = 0 is
   absorbing and `Z_T ≠ 0` implies every step was exact with a nonzero line. So
   `T_B = [6x+2]B + ψ(B) − ψ²(B)`, and `T_B = −ψ³(B)` means `α(B) = O` for
   `α = (6x+2) + ψ − ψ² + ψ³`. With `ψ² − tψ + p = 0`, `t = 6x² + 1`: `α = a + bψ`,
   `a = 6x + 2 + p − tp`, `b = 1 − t + t² − p`, `N(α) = a² + abt + b²p = r·n` with
   `gcd(n, 2p − r) = 1` and `gcd(2p − r, r) = 1` (`facts.mjs`). The points of `E'(Fp2)` in `ker α`
   therefore form a group of order dividing r: B ∈ G2, and the B lines are exactly those of the
   proof's B.
6. **Other inputs.** A and C are on-curve, hence in G1. vk_x is computed by msm-single (sound) and
   is never O. γ, δ, the fixed λ/β and κ are VK constants.

## Required spec rules

The reviewer's issues and the fixes; all are included in the measured prototype at negligible
cost (< 0.05M op, < 100 B).

1. **G2 subgroup derivation (major).** Soundness depends on the fused endpoint; it is derived in
   item 5 and checked by `facts.mjs`. The endpoint must be taken after exactly 65 doublings, the
   21 NAF additions, and `+ψ(B)`, `−ψ²(B)`.
2. **Projective zero-line hazard (major).** A zero B line makes `R_j ≡ 0` and frees `G_j`. Keep a
   `Z ≠ 0` gate; the final `Z_T ≠ 0` suffices because `Z_final = Z₀·Π(8Y³ or λ'³)` vanishes on every
   degenerate step (`check-proj.mjs` asserts the factorizations against the formulas the hot loop
   compiles). Affine steps keep their nonzero-denominator checks.
3. **Canonical limbs (minor).** A zero limb has two 32-B encodings (`00…00` and `00…80`, negative
   zero). Check STATES and QBLOB limbs with `WITHIN [1, p)` after BIN2NUM. An honest zero limb is a
   completeness miss of ~2⁻²⁴⁷; structurally zero top Q coefficients are dropped from the format.
   This check is a format (canonicality) choice, not needed for the Schwartz–Zippel argument:
   STATES and QBLOB are hashed as raw bytes before g and z, so a non-canonical encoding only
   costs extra oracle queries (the same reasoning as the SI README, "State and Q words need no
   range checks").
4. **vk_x ≠ O (minor).** msm-single already forces `Z·zInv == 1` and rejects exceptional additions;
   also re-check vk_x on the curve.
5. **Bound statement (minor).** Use `ε ≤ 1.134·(35 + 174)/p` per query; `z ≠ 0` may be required for
   clarity (z = 0 is already a root of D).
6. **Baked constants (minor).** Regenerate every baked constant (fixed λ/β, κ, ψ and Frobenius
   constants) from the VK with noble at build time and assert equality; assert the segment degrees
   (≤ 174) and the Q length.
7. **Verdict non-vacuity (minor).** Document that both cross-multiplied sides are nonzero and keep
   minop's non-vacuity guard.
8. **Reduce before every test (added in the design-record review).** Every nonzero test and
   equality (`Z_T ≠ 0`, the affine `x_Q − x ≠ 0`, the slope equations, the endpoint equalities, the
   batched check) is done on `(a − b) mod p`, as in SI rule 7 and commit-all rule 3. The hot loop
   keeps y values unreduced, so a raw test on an unreduced value could pass while the value is
   0 mod p and let the absorbing point at infinity through. The prototype already does this
   (`nonzero2` reduces with `md`, the endpoint uses `zeroModP`).

## Cost model and measured kernels

`hotloop.mjs` builds the whole hot section (setup, 65 unrolled events via OP_DEFINE/OP_INVOKE, 36
segment closes, the endpoint, Horner and the batched check) with a small SSA-to-stack compiler
and runs the real witness on the bch-spec VM. All 5 fixtures are accepted in standard and
consensus mode for the all-projective, all-affine and mixed variants; perturbing one limb of a
state, of Q, of `u₀` or of `B.y₀` makes the script fail; op is data-independent (±3k across
fixtures). Kernel op below is measured end to end inside the 43-slot single-stack layout,
including INVOKE.

| Kernel | op | bytes | times used |
|---|---:|---:|---:|
| BDBL: projective B doubling + square both accumulators + line at ±z | 133,350 | 593 | 49 |
| BADD: projective mixed addition + line (11 Fp2 mul + 2 sqr) | 181,940 | 566 | 17 |
| SQ + ABDBL: affine B doubling, witnessed slope (ROLLed from deep stack) | 90,498 | 302 | 16 |
| ABADD: affine B addition, witnessed slope (chord check + `dx ≠ 0`) | 81,853 | 289 | 6 |
| CF: `c^{−d}(±z)` fold + push `(B.x, d·B.y)` | 11,194 | 43 | 21 |
| F2 fixed step (γ/δ, baked λ; on-chain T, β, line), incl. 2 × 33-B λ pushes | 57,200 | 266 | 170 |
| F1 fixed line (baked λ, β) | 19,480 | 187 | 6 |
| SC: segment close from a 192-B chunk | 39,974 | 218 | 36 |
| HSTEP: Horner step over QBLOB | 7,240 | 83 | 80 |
| setup: lengths, ranges, curve checks, transcript (7.5 kB), g, z, powers, precomputes | 409,450 | 1,510 | 1 |
| Frobenius Q, K fold, endpoint with `Z ≠ 0` (endpoint alone 67k) | 127,800 | 1,226 | 1 |
| vk_x MSM, msm-single standalone (fixture 0: 10.33M; fixtures 1–3: 5.3–5.5M) | 11,190,941 worst | 3,816 + 98 witness | 1 |
| terminal torus verdict, cashc-zk (default cashc: 460,771 op, 1,691 B, local measurement) | 440,030 | 1,590 | 1 |

Measured trade-off rates (op saved per byte added): affine B addition 1,545; affine B doubling
682; F1 instead of F2 641.

### Revised totals

Measured as **the hot section end to end on the VM (all fixtures) plus standalone VM measurements
of the MSM and the verdict, plus an estimated 300 B / 0.05M for integrating them**, with a sweep
over the affine-prefix length K and the first F1 event (`sweep.mjs`, `best.mjs`).

| Variant | bytes | op (worst MSM) | budget | score |
|---|---:|---:|---:|---:|
| **K = 16, F1 at event 64 (best)** | **36,503** | **37.04M** | **37.20M** | **36,603** |
| K = 16, all F2 | 36,683 | 37.27M | 37.35M | 36,783 |
| design primary: all-projective B, F2 | 34,463 | 38.89M | 35.57M | 38,711 (op-bound) |
| all-projective B, F1 at 64 | 34,283 | 38.66M | 35.43M | 38,424 (op-bound) |
| all-affine B, F1 at 64 | 39,901 | 31.93M | 39.92M | 40,001 |
| all-affine B, F1 everywhere (measured, sweep K = 65, f1From = 0) | 50,177 | 25.58M | 48.14M | 50,277 |

Bytes of the best variant: hot-section redeem 19,238 (kernels 3.2k, setup 1.5k, glue 14.2k of which
~12k is baked λ, final 0.3k) + MSM 3,816 + verdict 1,590 + integration 300 (estimate) + redeem
header 3; witness 11,524 (STATES 6,915, QBLOB 2,563, slopes 1,452) − 66 (pushed vk_x) + 98 (MSM
witness). Op: hot section 25.36M + MSM 11.19M (forced 128-addition worst case) + verdict 0.44M +
integration 0.05M.

Against the design (34.8k): the MSM is 10.3–11.2M, not the 5.7/6.8M inferred from a delta between
two entries; projective B steps came in at 133k/182k, not 112k/142k, so the slope witness cannot
be dropped entirely; the verdict is 0.44M/1.6 kB and setup 0.41M. Partly offsetting: F2 is 57k
after keeping y unreduced, and segment closes are 40k against 52k.

## Reproduce

From the repository root:

```sh
node research/sound-sz-bn254/facts.mjs
cd research/sound-sz-bn254/hybrid-direct/prototypes
node schedule.mjs
for f in 0 1 2 3 4; do node ref.mjs $f; done
node check-proj.mjs
node ktest.mjs
node hotloop.mjs 16 0 --f1=64 --breakdown
node fixtures.mjs                       # all 5 fixtures, proj and aff, plus rejection checks (~8 s)
node best.mjs                           # the measured configuration on all 5 fixtures, with totals
KS=0,16,65 FS=64,65 node sweep.mjs      # part of the sweep; the full default grid takes longer
```

The MSM and the verdict depend on code that is not on `main`:

```sh
# msm-single.mjs is on the single-input-spec branch (commit 5333ec5, draft PR #29) and
# compiles with the zk-language cashc fork; VERIFIER_DIR is a zk-verifier-bench checkout.
VERIFIER_DIR=<zk-verifier-bench> MSM_SINGLE=<path>/densless-msm-spec-single/msm-single.mjs \
  CASHC_ZK=<cashscript-zk>/packages/cashc/dist/index.js node msm.mjs
# verdict.cash imports singleton/bn254/lib/lazy/Bn254LazyG.cash from this repo.
CASHC=<cashscript>/packages/cashc/dist/index.js CASHC_ZK=<cashscript-zk>/packages/cashc/dist/index.js \
  node verdict.mjs
```

`msm.mjs` will not run until the repository's own `cashc` dependency resolves:
`node_modules/cashc` is a link to `../cashscript/packages/cashc`, so a CashScript checkout must sit
next to this repository with `packages/cashc` built (`dist/` present). `CASHC` and `CASHC_ZK` do
not cover this, because the import chain (`chunked/bn254/pairfold5-msm/vkx-msm-asm.mjs` →
`chunked/pairing/_millermath.mjs`) imports the bare `cashc` package; otherwise `msm.mjs` fails with
`ERR_MODULE_NOT_FOUND: Cannot find package 'cashc'`. Without `CASHC`,
`verdict.mjs` uses the same dependency, which must be built. `verdict.mjs` exits with status 1
when a compiler fails to load or a fixture is not accepted. The MSM and verdict figures above
(including the default-cashc 460,771 op / 1,691 B) are local measurements with built compilers;
the repro review reproduced them exactly with explicit `CASHC` and `CASHC_ZK`.

| File | Role |
|---|---|
| `schedule.mjs` | NAF events, factor degrees, byte-optimal segmentation |
| `ref.mjs` | honest-prover reference (affine lines): Miller loop, torus residue, degrees, odd quotients, batched identity, terminal verdict, negative control |
| `witness.mjs` | witness generator for the prototype (projective, affine or mixed B), transcript |
| `sscomp.mjs` | SSA builder, stack compiler, interpreter, VM runner |
| `hotloop.mjs` | the hot-section script builder and runner |
| `check-proj.mjs` | projective formulas and ψ against noble; Z factorizations |
| `ktest.mjs` | differential test of every compiled kernel (VM vs interpreter) |
| `fixtures.mjs`, `best.mjs`, `sweep.mjs` | fixture runs, rejection checks, best configuration, knob sweep. Knobs: `best.mjs` takes `K` (affine-prefix events, default 16) and `F1` (first F1 event, default 64); `sweep.mjs` takes `KS`, `FS` (comma lists) and `OUT` (write the rows as JSON to that path) |
| `msm.mjs` | standalone msm-single measurement (external inputs) |
| `verdict.cash`, `verdict.mjs` | terminal torus verdict on a 6-limb state |

## Open risks

- **Integration not built.** Joining the MSM output and keeping u and `G₃₅` for the verdict are
  estimated (~300 B, 0.05M); tx overhead ~100 B.
- **Thin margin.** The best variant uses 99.6% of its budget with the worst-case MSM; a 1% overrun
  needs padding (about 1 B per 800 op) or a longer affine prefix.
- **Unexploited levers (estimates only):** an MSM with witnessed affine slopes (~1,000 op per
  byte, the largest), the verdict with p kept on the stack (−0.5 kB), one shared kernel body for γ
  and δ (−0.7 kB). A realistic floor is about 35–35.5 kB.
- **Inherited pieces.** The terminal verdict and msm-single are reused; their soundness is
  inherited (the G2 endpoint is re-derived above).
- **Completeness corners (negligible).** Torus normalization needs `F.c₀ ≠ 0` at all 36
  checkpoints and `c.c₀ ≠ 0` (minop's TORUS_KERNEL_SHIFT); a zero state or Q limb is rejected by the
  `[1, p)` check.
- **Baked constants** must be regenerated from the VK at build time; a wrong constant gives a
  verifier for a different equation.

# Commit-all (commit-all-fp6proj): densless folding with everything committed

**Status:** design plus VM measurements. Not built as a script.
**Measured score:** 22,971 B at the balance point on fixture 4, the worst fixture (22,900 B on
fixture 0), including 100 B of transaction overhead. At that point the best mix is 22,820 B with
26.30M op against a 26.26M budget: the op is about 51 B-equivalent (41k op) **over** budget, and
the 22,971 B figure assumes those bytes are added as padding (the `max()` in the score). With
the ~0.4–0.6 kB of padding or rebalancing needed for a liveness margin, plan for
**23.4–23.6 kB**.
**Review:** sound, provided the seven required spec rules below are adopted (the reviewer's six
required changes plus the residue-completeness rewrite). 3 major and 4 minor issues; two of the
major ones concern statement binding.

This is the densless polynomial folding with the #28 gap closed (the densless author has
since withdrawn the densless soundness claims for these gaps; see #28 and #32 F6): every intermediate state is
committed in full (not as a fingerprint), every line value is computed on-chain, states are
classes mod `Fp6*`, all chunk identities are batched with ρ into one odd quotient, and
`e(vk_x, γ)` is moved into GT factors.

## Notation

- `Fp12 = Fp[X]/M`, `M = X¹² − 18X⁶ + 82`; `w = X`, `v = X²`, `u = X⁶ − 9` (noble tower).
  `Fp6` = even polynomials; `conj: X ↦ −X` fixes Fp6.
- `a ~ b` means `a/b ∈ Fp6*`. For nonzero a, b this holds iff
  `W[a, b](X) := a(X)b(−X) − a(−X)b(X) ≡ 0 (mod M)`. W is always odd.
- **Class representative:** `m(X) + X` with m even, committed as the 6 tower limbs of m
  (`m = A₀ + A₁v + A₂v²`, `A_k ∈ Fp2`, limbs `A₀.c₀, A₀.c₁, A₁.c₀, A₁.c₁, A₂.c₀, A₂.c₁`). With
  `t = z⁶ − 9`: `m(z) = A₀.c₀ + A₀.c₁·t + (A₁.c₀ + A₁.c₁·t)·z² + (A₂.c₀ + A₂.c₁·t)·z⁴`, and the
  class value is `m(z) ± z` at `±z`.
- `ε(a) = a₀ + a₁·t` for `a ∈ Fp2` (the value of `Φ(a)` at z).
- NAF of `6x+2` without its leading digit: 65 events, 21 nonzero (13 negative). 88 lines per
  pair: 65 doublings, 21 NAF additions, 2 Frobenius additions.

### Pairing equation and GT factors

Checked: `e(−A, B) · e(C, δ) · e(vk_x, γ) · e(α, β) = 1`, with `e(vk_x, γ)` replaced by GT factors:
- Public inputs `n₀, n₁`; index `i ∈ {0, 1}` throughout. `G_{i+1} = rep(ML(IC_{i+1}, γ))` is the
  factor for `n_i`; `K = rep(ML(α, β) · ML(IC₀, γ))` (baked). `K` always means this constant.
- 4-dimensional decomposition `n_i ≡ Σ_j k_ij p^j (mod r)`, `j ∈ {0..3}`, `|k_ij| < 2⁶⁴` (LLL +
  Babai, `gt-decomp.mjs`). Each `k_ij` is written in signed NAF; digit `d_ij,e ∈ {−1, 0, 1}` is the
  coefficient of `2^{64−e}`. Digit slot `t = 4i + j ∈ [0, 8)` (as in `gt.mjs` and `reference.mjs`).
- Factor for a nonzero digit: `φ^j(G_{i+1})` for +1, `conj(φ^j(G_{i+1}))` for −1 (conj is the
  inverse up to Fp6).
- `acc_i` (i = 0, 1) are the on-chain GT exponent accumulators; `R` is the ρ-weighted sum of
  chunk residuals. `S_c` always means a committed state.

### Lines

A line `(c_y, c_x, c_b) ∈ Fp2³` at `P = (x_P, y_P)` evaluates as
`l(±z) = e₀ ± T`, `e₀ = ε(c_y)·y_P`, `T = ε(c_x)·x_P·z + ε(c_b)·z³`.

- **B, projective** from `(x_B : y_B : 1)`, homogeneous, scaled by 4 (no halving):
  `B = Y², C = Z², E = 3b'C = κ(9 − u)·C` (`κ = 9/82`), `F = 3E`, `H = (Y+Z)² − B − C = 2YZ`,
  `X₃ = 2XY(B − F)`, `Y₃ = (B + F)² − 12E²`, `Z₃ = 4BH`; line `(H, −3X², B − E)` = `H·(1, −λ, λx − y)`.
  Mixed addition with affine Q (`±B`, `ψ(B)`, `−ψ²(B)`): `θ = Y − y_QZ`, `λ' = X − x_QZ`,
  `C = θ², D = λ'², E = λ'D, F = ZC, G = XD, H = E + F − 2G`, `X₃ = λ'H`,
  `Y₃ = θ(G − H) − YE`, `Z₃ = ZE`; line `(λ', −θ, θx_Q − λ'y_Q)`.
- **B, affine option** (witnessed slopes, not chosen): doubling requires `2λy = 3x²`; addition
  requires `x_Q − x ≠ 0` and `λ(x_Q − x) = y_Q − y`; line `(1, −λ, λx − y)`.
- **δ, baked λ:** affine walk from the baked δ with baked `λ_j`; on-chain
  `x' = λ² − x − x₂` (`x₂ = x` or `x_Q`), `b = λx − y`, `y' = b − λx'`; line `(1, −λ, b)`.
  At the measured optimum 21 of the 88 δ steps instead run projectively through the shared
  B kernels.

## Protocol

### Witness (unlocking pushes)

| Item | Encoding | Bytes |
|---|---|---|
| stmt | `A.x‖A.y‖B.x₀‖B.x₁‖B.y₀‖B.y₁‖C.x‖C.y‖n₀‖n₁`, 10 × 32-B LE limbs, one push | 323 |
| GT digit string | 65 events × 16-bit LE word; bits `2t, 2t+1` (t = 4i + j) code digit `d_ij,e`: 01 = +1, 10 = −1, 00 = 0, 11 invalid | 132 |
| chunk mask | 65-bit boundary set in 9 bytes (7 spare bits, must be zero); chunk c covers events `[s_c, e_c)` | 10 |
| ĉ (`chat`) | 6 limbs of the class rep of `c⁻¹`, one 192-B push | 194 |
| states `S₁..S_{N−1}` | 6 limbs each, one 192-B push per state | 31 × 194 (fixture 4) |
| Q | odd coefficients `q₁, q₃, …, q_degQ`, 32-B limbs, descending, in 256-B pieces (8 limbs, top piece zero-padded) | 17 × 259 (fixture 4: deg Q = 265, 133 coefficients) |

### Baked in the redeem

p, r, `b'`; the δ start point and the 88 δ slopes (2 inline 33-B pushes per line; the two
Frobenius additions also carry their `x_Q`); `K, G₁, G₂` (6 limbs each); Frobenius and ψ
constants; `p^j mod r`; the NAF schedule of `6x+2`; a 32-B VK domain tag.

### Transcript (fixed-width, SHA256 hash chain)

```
τ₀ = H(tag ‖ stmt)
τ₁ = H(…H(H(H(τ₀ ‖ digits ‖ mask) ‖ ĉ) ‖ S₁) … ‖ S_{N−1})
ρ  = BIN2NUM(τ₁ ‖ 0x00) mod p
τ₂ = H(…H(τ₁ ‖ piece₁) … ‖ piece_last)          (Q pieces)
z  = BIN2NUM(τ₂ ‖ 0x00) mod p,   require z ≠ 0
```

### On-chain steps

1. **Parse** stmt with SPLIT at 32-B boundaries and unsigned `BIN2NUM(limb ‖ 0x00)`. Require all
   coordinates `< p` and `0 ≤ n_i < r`.
2. **Curve checks.** A, C on `y² = x³ + 3` (G1 has cofactor 1); B on `y² = x³ + b'`.
3. **Challenges** as above; every push SIZE-checked.
4. **Precompute** `t, z², z²t, z⁴, z⁴t, z³, z³t`; per pair `P ∈ {−A, C}`: `y_P, y_P t, x_P z, x_P z t,
   3x_P z, 6x_P z t`. Values at `±z` of: ĉ; `φ^j(G_{i+1})` for j = 0..3 (Frobenius images computed
   exactly on-chain from the baked limbs, then evaluated); K; `φ^k(ĉ)` for k = 1..3.
5. **Fold, chunk by chunk.** `(U₊, U₋) := S_{c−1}(±z)` with `S₀ = ĉ`. For each event e of the
   chunk (at most L_MAX = 4 events, enforced by a counter):
   - `U± ← U±²`;
   - multiply in every B line and δ line value (`l(+z)` into `U₊`, `l(−z)` into `U₋`);
   - `d_e = +1`: multiply by `ĉ(±z)`; `d_e = −1`: multiply by `ĉ(∓z)` (`conj(ĉ) ~ ĉ⁻¹`);
   - for each nonzero GT digit: multiply by `φ^j(G_{i+1})(±z)`, swapped (`∓z`) for −1;
   - `acc_i ← 2·acc_i + Σ_j d_ij,e·(p^j mod r)`.

   Non-last chunk: `V± = S_c(±z)`. Last chunk (merged with the terminal relation):
   `U± ← U±·φ(ĉ)(±z)·φ³(ĉ)(±z)·K(±z)` and `V± = φ²(ĉ)(±z)`.
   `R ← R + ρ^{c−1}·(U₊V₋ − U₋V₊)`; the next chunk starts from `V`.
6. **GT binding.** `(acc_i − n_i) mod r == 0` for i = 0, 1.
7. **Tie and subgroup.** After the last event (which includes the additions with `ψ(B)` and
   `−ψ²(B)`): `X_T = x(ψ³B)·Z_T`, `Y_T = −y(ψ³B)·Z_T`, `Z_T ≠ 0` (all as `(a − b) mod p == 0`).
8. **Accept iff** every check passes and `(R − z·Q'(z²)·M(z)) mod p == 0`,
   `Q'(y) = Σ_k q_{2k+1} y^k` (Horner in z²).

**Prover.** Computes the raw chain f (lines and GT factors), a residue c with
`c^λ ~ f·K` (`chunked/bn254/densless-recovered/root-witness.mjs`), `ĉ = rep(c⁻¹)`; picks the chunk
mask by a DP over degree caps (cost 192 B per state, 32 B per odd Q coefficient); computes the
chunk products U, states `S_c = rep(U)`, `W_c`, `Agg = Σ_c ρ^{c−1}W_c` and `Q = Agg/M` (exact and
odd).

## Committed before the challenge vs computed on-chain

**Before ρ (τ₀, τ₁):** A, B, C, n₀, n₁ (fixed-width, under the VK tag); the GT digit string (the
decomposition is not unique and the digits fix which factors enter each `W_c`); the chunk mask
(it fixes how the identities are partitioned); all 6 limbs of ĉ; all 6 limbs of every state
`S₁..S_{N−1}` (full representatives, not fingerprints).
**Before z (τ₂, after ρ):** every odd coefficient of Q.
**Not hashed but unique:** in the affine-B option only, the B slopes (fixed by exact equations
and the `x_Q − x ≠ 0` check).

**Computed on-chain:** ρ, z; the B walk (projective, from the payload B) and ψ(B), ψ²(B), ψ³(B);
the δ walk; every line value at ±z; the Frobenius images `φ^j(G_{i+1})` and `φ^k(ĉ)` and their
values; all state evaluations; the fold; the ρ-weighted sum R; `Q'(z²)`, `M(z)`; the GT
accumulators `acc_i`.
**Baked:** δ slopes and start point, `G₁, G₂, K`, Frobenius and ψ constants, `b'`, p, r,
`p^j mod r`, the NAF schedule.
**Checked exactly:** ranges, curve equations, the GT congruence mod r, the tie/subgroup
equality with `Z_T ≠ 0`, the final equation.

## Soundness argument

1. **Field and classes.** M is irreducible, so Fp12 is a field. For `V ≠ 0`: `U ~ V` iff
   `U·conj(V) ∈ Fp6` iff `W[U, V] ≡ 0 (mod M)`. W is odd and M is even, so any multiple of M
   equal to a sum of such W has an odd quotient; only odd Q coefficients are committed.
2. **Nonzero factors.** Committed classes `m + X` have X-coefficient 1. Projective lines have
   `c_y = H = 2YZ` (doubling) or `λ'` (addition); `Y ≠ 0` because `#E'(Fp2) = r(2p − r)` is odd,
   and `Z₃ = 4BH = 8Y³Z` and `Z₃ = Zλ'³` make `Z = 0` absorbing, so the final `Z_T ≠ 0` gives every
   `Z ≠ 0` and every `λ' ≠ 0`. Affine unit lines have constant slot `y_P ≠ 0`. G-images, `φ^k(ĉ)`
   and K are nonzero. So `W_c ≡ 0` implies the class relation exactly. (If a line could be zero,
   `W_c` would vanish for any `S_c` and free the next state.)
3. **Schwartz–Zippel with batching.** Every `W_c` is a fixed polynomial once τ₁ is fixed.
   - ρ step: if some `W_c ≢ 0 (mod M)`, `Σ_c ρ^{c−1}(W_c mod M)` is nonzero of degree ≤ N − 1 ≤ 64
     in ρ: probability ≤ 64/p.
   - z step: otherwise `R(X) = Σ_c ρ^{c−1}W_c(X) − Q(X)M(X)` is nonzero (Q is fixed before z,
     and a nonzero polynomial of degree < 12 is not a multiple of M), of degree
     `D ≤ max(max deg W_c, deg Q + 12)`: probability ≤ D/p.
   - With the chunk-length cap L_MAX = 4 and Q capped at 160 odd coefficients, the adversarial
     `D ≤ 1,930` (W_c is odd, so in fact ≤ 1,929; the bound below keeps 1,930): all 8 GT digits in every event, ĉ and the addition lines at the fixed NAF
     digits of 6x+2. Per event the factor degree is `18 + 8·10 = 98` (two lines of degree 9,
     eight degree-10 GT factors), plus `18 + 10 = 28` at a NAF digit (two addition lines, ĉ).
     The worst chunk is the last one, events 61–64 with one NAF digit on its first event:
     `16·10 + 15·98 + 8·28 + 66 + 10 = 1,930` (start state squared 4 times; the terminal
     factors: four Frobenius lines and `φ(ĉ)·φ³(ĉ)·K`, 66; `V = φ²(ĉ)`, 10). A non-last chunk
     reaches at most 1,920, and `deg Q + 12 ≤ 331`. Honest proofs have `max deg W_c` = 161–277
     on the fixtures.
   - Hash-to-field bias ≤ 1.134. Per random-oracle query `ε ≤ 1.134·(64 + 1,930)/p ≈ 2^{−242.5}`;
     total `q_H·2^{−242.5}`. Non-canonical encodings only add oracle queries.
4. **Chain.** By induction over chunks, with `S₀ = ĉ`:
   `S_N ~ f · ĉ^{6x+2}` with `f = ML(−A, B)·ML(C, δ)·Π_e(GT factors)` up to Fp2 line scalings and
   dropped vertical lines (both in Fp6). The last chunk enforces
   `f·ĉ^{6x+2}·φ(ĉ)·φ³(ĉ)·K ~ φ²(ĉ)`. With `c := ĉ⁻¹`: `f·K = c^λ·s`, `s ∈ Fp6*`.
5. **Residue.** `λ ≡ 0 (mod r)` and `(p⁶ − 1) | (p¹² − 1)/r`, so
   `(fK)^{(p¹²−1)/r} = c^{(λ/r)(p¹²−1)}·s^{(p⁶−1)(…)} = 1`, the Groth16 equation after the final
   exponentiation. Completeness: G = `Fp12*/Fp6*` is cyclic of order `p⁶ + 1`, and
   `gcd(λ, (p⁶+1)/r) = 1` (equivalently `gcd(λ/r, (p⁶+1)/r) = 1` and `r ∤ (p⁶+1)/r`), so the
   class of every r-th power has a λ-th root class and no cubic-residue selector is needed
   (`facts.mjs`).
6. **GT factors.** `φ^j(G) = G^{p^j}` exactly and `conj(G) ~ G⁻¹`, so
   `Π_j φ^j(G_{i+1})^{k_ij} ~ G_{i+1}^{Σ_j k_ij p^j}`, which equals `G_{i+1}^{n_i}` modulo
   `(Fp12*)^r` by the checked congruence. With bilinearity, `e(vk_x, γ)` is represented exactly.
   The on-chain `acc_i`
   is built from the same signed digit that drives the fold, and the digit's weight
   `2^{64−e}` matches the number of squarings after event e (square first, then multiply).
7. **B tie and subgroup.** The walk starts at the payload B and every step is exact (Z ≠ 0), so
   `T_final = [6x+2]B + ψ(B) − ψ²(B)`; `T_final = −ψ³(B)` means `φ(B) = O` for
   `φ = (6x+2) + ψ − ψ² + ψ³ = a + bψ`, with `a ≢ 0 (mod p)` (separable) and
   `gcd(N(φ), #E'(Fp2)) = r`. So `ker φ ∩ E'(Fp2) = G2`, and the lines are those of this B.
8. **On-curve checks.** A and C on the G1 curve (cofactor 1). vk_x never appears as a point.
9. **No unchecked prover value.** The densless fixed-table words do not exist here; every line
   value, state evaluation, B point and GT value is computed on-chain from hashed or baked data.

**Swapped ĉ for −1 digits.** The measured Miller section multiplies `U` by `conj(ĉ)` (values
`ĉ(∓z)`) at −1 digits instead of the original design's `ĉ^b` on the V side of each chunk. Both
give the same class relation, since `ĉ·conj(ĉ) ∈ Fp6*`; `conj(ĉ)` is a nonzero polynomial
computed from the committed ĉ, so items 2–4 apply unchanged (it adds degree 10 per −1 digit
inside the chunk and removes the `ĉ^b` term). `reference.mjs` implements both
(`CHAT_NEG=vside` for the original) and accepts all 5 fixtures with identical state and Q
sizes. This change was made during measurement and has not been through the independent
review.

## Required spec rules

The reviewer's issues and the fixes a builder must implement from the start. All are priced
into the measured totals.

1. **Unsigned statement decode (major).** Plain BIN2NUM decodes a limb with its top bit set as
   negative, and a negative `n_i` passes `n_i < r`: the same proof would then verify for
   `n_i = r − k` and for the byte string decoding to `−k`, which changes the statement an
   application sees. Decode every stmt limb as `BIN2NUM(limb ‖ 0x00)`; require
   `0 ≤ n_i < r` and every coordinate `< p`; compare the GT sum sign-safely
   (`(acc_i − n_i) mod r == 0`).
2. **One signed digit per (i, j, e) (major).** Code 11 must reject (here: its OP_INVOKE id is
   undefined). The fold and the mod-r accumulator must use the same decoded digit; a mismatch
   shifts the proven exponent by `2^b p^j` while reporting `n_i`. Event e squares first, then
   multiplies its factors, which are then squared `64 − e` more times. Negative tests: a flipped
   digit and a code-11 word both reject (`gt.mjs`).
3. **Reduce before every test (major).** `z ≠ 0`, `Z_T ≠ 0`, the affine `x_Q − x ≠ 0` and the tie
   equalities must run on reduced values: test `(a − b) mod p == 0` (or `!= 0`). A raw test on a
   signed or unreduced value can pass while the value is 0 mod p, which reopens a free slope or
   lets the absorbing point at infinity through.
4. **Degree bound (minor).** The mask is prover-chosen; a single 65-event chunk would have degree
   ~2⁷². Cap the chunk length on-chain (L_MAX = 4, a counter in the event driver) and the Q
   length (≤ 20 pieces), and quote the bound above.
5. **Residue completeness (minor).** Use the group-theoretic argument (item 5), not the
   `w ∈ {1, v, v²/ξ}` heuristic. Any c with `c^λ ~ fK` is acceptable.
6. **Framing (minor).** Require OP_SIZE equality on every fixed-width push (320, 130, 9, 192 B and
   256-B Q pieces); derive the number of state pushes from the hashed mask; require that the mask
   contains the end event; require the 7 spare bits of the 9-byte mask to be zero. Require at
   least one Q piece. The reviewer also asked for the start event: here it is implicit, because
   the mask encodes chunk ends only, chunk 1 always starts at event 0, and `S₀ = ĉ` is fixed,
   so the number of states is the number of set bits and no encoding of the start exists.
7. **Projective degeneracy (minor).** Every projective `Z₃` must keep Z (or the addition's
   x-difference) as a factor; `check-kern.mjs` asserts the formulas against noble. The measured
   totals also include an explicit `Z ≠ 0` check at the 23 projective additions (+0.12M).

## Cost model and measured kernels

Measured on the libauth bch-spec VM; VM outputs are checked against a BigInt simulation of the
same kernels, and the simulation's end points against noble.

**Miller section, end-to-end** (`miller.mjs`, fixture 0, full schedule: 65 events, 21 NAF
additions, 2 Frobenius additions, 65 fold squarings, 21 ĉ multiplications, ψ ×6, tie with
`Z_T ≠ 0`):

| B / δ variant | op | code + constants | witness |
|---|---:|---:|---:|
| projective / baked λ (anchor) | 19,095,452 | 8,601 B (1,962 functions, 702 driver, 5,937 δ constants) | 0 |
| projective / baked (λ, b) | 15,680,732 | | 0 |
| projective / projective | 26,940,103 | | 0 |
| affine / baked λ | 12,999,523 | | 5,807 |
| affine / baked (λ, b) | 9,586,121 | | 5,807 |

In context a doubling event costs ~202k and an addition event adds ~252k. Per-kernel figures
below are derived from the isolated per-call costs of the fused event functions that
`miller.mjs` prints for each variant (for example, projective doubling = `EV(proj, lamb)` −
baked line − fold square).

| Kernel | op | bytes | times used |
|---|---:|---:|---:|
| B projective doubling + line at ±z + fold (34 MUL, 20 MOD) | 123,800 | 493 | 65 |
| B projective mixed addition + line + fold (56 MUL, 24 MOD) | 156,000 | 587 | 23 |
| δ step, baked λ (x', b, y' on-chain, unit line) | 58,500 | 68 per line | 67 |
| δ step, projective via the shared kernels | 150,500 | 2 per line | 21 |
| fold squaring at ±z | 8,056 | 78 | 65 |
| ψ on the twist (conj + Fp2 constant, both coordinates) | 25,368 | 322 | 6 |
| Frobenius image `φ^j(m + X)`, exact, evaluated at ±z (j = 1, 3; j = 2: 24,560) | 34,800 | 351 | 9 |
| GT decode, all 65 events (computed OP_INVOKE dispatch; 0.7M + 9.9k per nonzero digit) | 2,503,552 | 705 | 1 |
| state/quotient/transcript pipeline (32 boundaries, 133 odd Q coefficients in 17 pieces) | 2,090,689 | ~1,100 | 1 |
| setup: parse, ranges, curve checks, pair constants | 95,027 | 593 | 1 |
| *alternatives not used* | | | |
| B affine step, witnessed slope, exact check (derived, see below) | 62,900 | 66 + 66 witness | 0 |
| δ line with baked (λ, b) | 19,600 | 134 | 0 |

The affine B step has no isolated figure (`miller.mjs` prints `n/a` for affine EV/AD, since
the isolated run has no valid witness slope). 62,900 is the in-context average per B line:
the projective average `(65·123,800 + 23·156,000)/88 = 132,216` minus the saving per line
between the full runs, `(19,095,452 − 12,999,523)/88 = 69,272`.

GT decode: 2.30M on fixture 0 (171 nonzero digits), 0.71M with 13, 2.50M for the densest of
3000 random inputs (192). A first version with IF/ELSE bodies cost 4.35M even for sparse digits,
because unexecuted opcodes still cost 100 op each under the 2025 rules; hence the computed
dispatch. Pipeline: 34.3k per boundary, 5.9k per Q coefficient, 0.11M transcript (standard rate).

### Revised totals

Measured as **an end-to-end Miller section plus separately measured GT, pipeline and setup
blocks, summed, with a balance search over the line implementations** (`total.mjs`). Fixed
non-line parts (worst fixture, densest digits): 5.27M op (GT 2.83M, pipeline 2.09M, setup 0.10M,
driver/review fixes/P2SH hash 0.25M) and 15.5 kB (states + Q 10.4 kB for fixture 4, stmt/ĉ/
digits/mask 0.66 kB, GT code + constants 2.3 kB, pipeline ~1.1 kB, setup 0.6 kB, misc (δ start,
tag, p, glue) 0.4 kB). Pushes are
counted at 194 B per 192-B state and 259 B per 256-B Q piece. `FIX=0 node total.mjs` uses the
fixture-0 shape (32 states, 123 Q coefficients in 16 pieces).

| Configuration | bytes | op | score |
|---|---:|---:|---:|
| **B projective; 67 δ steps baked λ, 21 projective (best mix)** | **22,820** | **26.30M** | **22,971** |
| B projective + δ baked λ | 24,084 | 24.36M | 24,184 |
| B projective + δ (λ, b) | 29,501 | 20.95M | 29,601 |
| B projective + δ projective | 18,028 | 32.47M | 30,688 |
| B affine + δ baked λ | 29,336 | 18.27M | 29,436 |

Score = `max(bytes, op/800 − 10,000) + 100`. At the best mix `op/800 − 10,000 = 22,871`, 51 B above
the byte count, so the mix as measured fails the op budget unless 51 B of padding is added; the
score above already includes that padding. On fixture 0 the best mix is 22,755 B / 26.24M op,
score 22,900 (45 B of padding).

These figures revise the measurement step's own result (23,160 B, 26.45M op, plan
23.5–23.7 kB, best mix 66 δ-λ / 22 δ-projective). That result counted 144 odd Q coefficients on
fixture 4, including zero padding above deg Q; trimmed to the 133 that `reference.mjs` now
reports, the pipeline is 2.09M instead of 2.15M and the best mix moves to 67/21, giving 22,971 B.

B affine loses because the only balancing knob, δ λ-only versus projective, trades ~1.4k op per
byte rather than 800. States + Q measure 9.0–10.4 kB across the fixtures. Against the design
model (23.2 kB): the Miller lines came in cheaper (123.8k against 162.6k naive doubling), the GT
block costlier (2.5M decode + ~0.33M Frobenius against 1.9M), and code plus constants larger.

## Reproduce

From the repository root:

```sh
node research/sound-sz-bn254/facts.mjs
cd research/sound-sz-bn254/commit-all/prototypes
for f in 0 1 2 3 4; do node reference.mjs $f; done
CHAT_NEG=vside node reference.mjs 0     # the original V-side variant
node gt-decomp.mjs
node check-kern.mjs
for v in "proj lam" "proj lamb" "proj proj" "aff lam" "aff lamb"; do node miller.mjs $v; done
node gt.mjs
node pipeline.mjs 32 133              # fixture-4 shape (32 123 for fixture 0)
node setup.mjs
node total.mjs                         # FIX=0 node total.mjs for the fixture-0 shape
```

| File | Role |
|---|---|
| `reference.mjs` | protocol reference (affine lines, DP chunking, NAF GT digits): prover, transcript, value-level verifier, negative control; imports the repo's `root-witness.mjs`. Knobs: `CHAT_NEG=vside` (original V-side ĉ), `GT_MODE=bin` (binary instead of NAF GT digits, for comparison), `WMAX=<deg>` (fixed chunk degree cap instead of the DP) |
| `gt-decomp.mjs` | LLL lattice and Babai decomposition `n ≡ Σ k_j p^j (mod r)` |
| `lib.mjs` | SSA builder, BigInt kernel evaluator (`evaluator()`), frame compiler, VM runner |
| `kern.mjs` | kernel formulas (projective, affine, baked line, ψ, fold) |
| `check-kern.mjs` | kernel formulas against noble |
| `miller.mjs` | Miller section end-to-end, all B/δ variants |
| `gt.mjs` | Frobenius images, GT decode with negative tests |
| `pipeline.mjs` | transcript, state boundaries, quotient Horner, final check |
| `setup.mjs` | statement parse, ranges, curve checks, pair constants |
| `total.mjs` | totals and balance search (constants are outputs of the scripts above); `FIX=0` or `4` (default) picks the witness shape |

## Open risks

- **No liveness margin at the balance point.** The best mix is 51 B-equivalent over budget
  (covered by padding in the score); plan 0.4–0.6 kB of padding or a rebalance toward bytes
  (23.4–23.6 kB).
- **Not built.** Event-driver and pipeline code bytes (~1.8 kB) are estimates (±1 kB). Per-call
  op in the full run is ~6% above isolated kernels; the totals use full-run figures.
- **Prover-chosen chunk mask** needs data-dependent control flow (an event loop with conditional
  checkpoints, under the stack-isolation audit). A fixed worst-case schedule is simpler and costs
  ~1–1.5 kB more quotient.
- **Swapped-ĉ change** (above) is argued and tested here but not independently re-reviewed.
- **The reference differs from the measured spec in encodings:** it uses affine B lines (same
  classes, different Q), a byte list of chunk ends instead of the 65-bit mask, and a flat
  big-endian transcript. A builder's witness generator must follow the on-chain spec.
- **vk_x in GT** departs from reusing msm-single. It removes the γ lines (~5.8 kB + 5.3M) and the
  MSM (~2.1 kB + 5.1M in the design model) but relies on correctly baked `G₁, G₂`, K and
  Frobenius constants and on hashing the digits before ρ. If the benchmark rejects it, the
  design model gives ~30.6 kB for the MSM variant. That figure assumed a 5.1M MSM;
  hybrid-direct measured msm-single at 10.3M (fixture 0) to 11.2M (worst case), so the real
  figure would be several kB higher. It was not re-measured.
- **Proof-dependent size.** States + Q vary 9.0–10.4 kB; the densest random digits were measured
  for the GT decode only. Add ~0.2 kB if chunking degrades.
- **Completeness corners (negligible).** The chart `m + X` cannot represent the identity class
  `[1] = [Fp6*]` (its odd part is always nonzero), so an honest state equal to [1] has no
  representative. This happens with probability about `1/p⁶` per state.
- **Batching rule.** Batching with ρ is sound only because every input to every `W_c` is in τ₁.
  Adding any prover-chosen value that shapes `W_c` without hashing it before ρ would reopen #28.

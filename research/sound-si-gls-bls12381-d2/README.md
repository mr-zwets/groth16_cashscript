# BLS12-381 Groth16, SI-GLS port: design record (designer 2, risk-first)

**Status:** design plus a working protocol reference and measured kernels. Not built as a script, not a bench
entry, not reviewed. The target is one P2SH32 input on the bch-spec VM: 100,000-byte scripts, per-input op budget
`(10,000 + unlockingLen) × 800`.

**Angle:** minimize risk and complexity first (the clearest soundness argument and a fixed, statement-independent
liveness margin), bytes second. This is a direct port of the reviewed BN254 verifier `chunked/bn254/sound-si-gls`
(21,915 B). Every structural choice that verifier made is kept unless BLS12-381 forces a change, and each change
makes the construction simpler.

**Estimated score: ~30.4 kB at a 5% liveness margin (~31.3 kB at 7%), op-bound.** The estimate breaks down as:
- natural unlocking 27.9 kB (redeem ~12.2 kB, WS 10,080 B, WQ 5,664 B), plus ~2.4 kB of padding;
- worst-case op 30.63M (standard mode), estimated from VM-measured kernels and calibrated on the built BN verifier's
  per-section profile;
- the uncertainty is about ±1 kB, mostly glue.

Two optional byte trims reach ~29.3–29.6 kB but add a second kernel kind. They are not recommended for the first
build. For comparison, kallisti's `bch-groth16-bls12381-singleton-fs-spec-zero` is 65,218 B (unreviewed; plan:
derived from the withdrawn #25/#44 decoder). This design is about 47% of that.

Everything below can be re-derived with the scripts in this directory (see Reproduce).

## 1. What changes from BN254 SI-GLS, and why each change is simpler

| | BN254 SI-GLS (built) | BLS12-381 (this design) |
|---|---|---|
| Fp12 | `X¹² − 18X⁶ + 82`, `u = X⁶ − 9` | **`M = X¹² − 2X⁶ + 2`**, `u = X⁶ − 1`, `ξ = 1 + u` |
| Miller loop | NAF of `6x+2`: 65 events, 21 additions (13 with −B), 2 Frobenius end lines per pair | **binary `|x|` = 0xd201000000010000: 63 events, 5 additions, all +B, no end lines** |
| residue exponent | `λ = 6x+2+p−p²+p³` | **`λ = p + |x| = p − x = h1·r`** |
| terminal | B += ψ(B), −ψ²(B) (with lines); 2 δ Frobenius lines; `S_c(ηX)`; `W = Fr(S_c)(X)·Fr(S_c)(ηX)` | **`Rconst` and `W = Frob(S_c)` only; merged into the last chunk** |
| G2 check | endpoint `[6x+2]B + ψ − ψ² + ψ³ = O` | **endpoint `[|x|]B = −ψ(B)` (Scott's ψ(Q) = [x]Q)** |
| vk_x fold | 4-dim LLL lattice, Babai rounding, offset `u = e + 2⁶⁴` and its constant correction | **canonical base-`|x|` digits `n = Σ d_i |x|^i`, 0 ≤ d_i < 2⁶⁴; exact integer binding; no lattice, no offset, no correction** |
| challenges | SHA256 → mod p (bias 1.134) | **SHA256 output < 2²⁵⁶ < p: no reduction, no bias** |
| quotient | variable length 1–132 words, leading word ≠ 0 | **fixed 118 words (zero top words allowed): the unlocking length and the budget are constant** |
| field words | 32 B | 48 B (WS `n_k` stay 32 B) |

## 2. Notation and constants (all asserted against noble 2.2.0 by `math.mjs` at import)

- `p` (381 bits, 48-byte words), `r` (255 bits), `x = −T`, `T = |x| = 0xd201000000010000` (64 bits, bits 63, 62, 60, 57, 48, 16).
- **Fp12 = Fp[X]/M, M = X¹² − 2X⁶ + 2, X = w** (noble tower: `u² = −1`, `v³ = ξ = 1 + u`, `w² = v`).
  An Fp2 element `a₀ + a₁u` maps to `Φ(a) = (a₀ − a₁) + a₁X⁶`, so `Φ(a)(±z) = a₀ + a₁·t` with `t = z⁶ − 1`.
  - `math.mjs` checks the map against noble on random products, and checks `M(w) = 0`.
  - **Irreducibility:**
    - (i) Ben-Or: `gcd(X^{p^k} − X, M) = 1` for k = 1..6, computed;
    - (ii) structural: `w` generates Fp12 over Fp (`w⁶ − 1 = u`), so its minimal polynomial has degree 12 and divides `M`.
- `σ = Frob⁶` is `X ↦ −X` (asserted). `Fp6` = even polynomials. `G = Fp12*/Fp6*` is cyclic of order `p⁶ + 1`.
- `Frob²` is `X ↦ ηX` with `η = 0x5f19672fdf76ce51ba69c6076a0f77eaddb3a93be6f89688de17d813620a00022e01fffffffeffff`
  (the unique primitive 6th root that works; `η² = η − 1`, `η³ = −1`). `Frob(X^j) = Φ(γ₁^j)X^j` with `γ₁ = ξ^{(p−1)/6}`, and `Frob(X⁶) = 2 − X⁶`. So
  `Frob(S)(±z) = (s₀ + 2 − z⁶) + Σ_{j=1..5} s_j·c_j·(±z)^j`, `c_j = Φ(γ₁^j)(z)` (formula asserted).
- Twist `E': y² = x³ + 4(1+u)`. `ψ(x, y) = (x̄·PX, ȳ·PY)` (constants asserted vs noble). On G2, `ψ = [p] = [x]`, so `ψ(Q) = −[T]Q` (asserted).
- **Class representative:** monic degree-6 `S = X⁶ + Σ_{j<6} s_j X^j` (6 words), as in BN. `Frob²` and `σ` keep it monic.
- **Lines (M-twist, noble's 014 slots).** A line `(c₀, c₁, c₂)` (Fp2) at `P = (x_P, y_P)` is the Fp12 element
  `c₀ + (c₁x_P)·v + (c₂y_P)·vw`, i.e. the polynomial `L(X) = Φ(c₀) + x_P X²Φ(c₁) + y_P X³Φ(c₂)`, of degree ≤ 9. At ±z:
  `L(±z) = E ± O`, with `E = c₀(t) + x_P z²·c₁(t)` and `O = y_P z³·c₂(t)`. This is the untwisted line times `w³ ∈ Fp4`, which FE kills.
  - affine line through T with slope λ: `(λx_T − y_T, −λ, 1)` (degree 8, `O = y_P z³` is constant per proof);
  - projective doubling of `(X:Y:Z)`: `(Y² − 3b'Z², −3X², 2YZ)` = `2YZ ×` affine, using `3b' = 12(1+u)`;
  - projective mixed addition with `(x_q, y_q)`: `θ = Y − y_qZ`, `λ' = X − x_qZ`, line `(θx_q − λ'y_q, −θ, λ')` = `λ' ×` affine;
  - point formulas: the BN SI-GLS formulas, unchanged (`Z₃ = 8Y³Z` for doubling, `Z₃ = Zλ'³` for addition);
  - `math.mjs` asserts the lines (class-equal to the affine lines) and the walk (equal to noble).
- **Miller convention:** `f_T(P, Q)` = noble's loop *before* its `xNegative` conjugation. `FE(f_T) = e^{−1}`, a non-degenerate
  bilinear pairing (asserted). Every factor uses this one convention, so FE(f') = 1 ⟺ the Groth16 equation.

### Number-theoretic facts (`math.mjs` FACTS, all asserted)

| fact | use |
|---|---|
| `p ≡ x (mod r)`, `r = x⁴ − x² + 1`, `r \| p⁶ + 1` | residue, GLS |
| `λ = p + T ≡ 0 (mod r)`; `λ/r = h1 = (x−1)²/3` | residue exponent |
| **`gcd(λ, p⁶ + 1) = r`** (so `gcd(λ/r, (p⁶+1)/r) = 1`, `r² ∤ p⁶+1`) | completeness: every class with FE = 1 is a λ-th power in G. **No w witness.** |
| `gcd(λ, p⁶ − 1) = T + 1 = 1 − x`; `gcd(λ, p¹² − 1) = r(1 − x)` | why the full-Fp12* version (Novakovic–Eagen) needs `f·w = c^λ`. The obstruction `(1−x)` divides `p⁶ − 1`, so the right set for w is Fp6*, which the class representation quotients out for free. |
| `3 ∤ p⁶ + 1` | context: no cubic selector in G |
| `#E(Fp) = r·h1`, `gcd(h1, r) = 1`, h1 odd | G1 lemma (§5.6); `y_P ≠ 0` (no 2-torsion) |
| `N(ψ − x) = x² − tx + p = λ`, **`gcd(λ, h2) = 1`**, `gcd(h2, r) = 1`, h2 odd | ψ(B) = [x]B ⟹ B ∈ G2; no 2-torsion on E'(Fp2) |
| `T⁴ > r`; `T^i ≡ (−1)^i p^i (mod r)` | 4 base-T digits; `FE(m)^{T^i} = FE(σ^i Frob^i m)` |
| SHA256 output `< 2²⁵⁶ < p` | challenges uniform on a 2²⁵⁶-set, no bias |

## 3. Protocol

### 3.1 Schedule and chunking

- **Initial step ("event −1"):** handles the top bit of T (the factor `c⁻¹`) and bit 63 of the GLS digits. No squaring, no lines.
- **Events e = 0..62:** each handles bit `62 − e` of T:
  - square;
  - B doubling line;
  - δ doubling line;
  - if the bit is set (e = 0, 2, 5, 14, 46): the B addition line (+B), the δ addition line, and `S_c(−X)` (= `c⁻¹`);
  - the GLS factors of nibble `e + 1`.
- **Chunks** (32 committed states), found by an exact search (`search.mjs`) for the fewest states under each Q cap:
  `[−1,0] [1,2] [3] [4,5] [6] [7,8] [9,10] … [59,60] [61,62]`.
  - States `S_1..S_32` are committed after events 0, 2, 3, 5, 6, 8, 10, …, 60.
  - The two singletons put every addition event second in its chunk. That gives cap 118 instead of 130 with 31 states:
    the trade is +288 B of state against −576 B of Q, and op improves too.
  - The last chunk `[61,62]` is closed by the terminal identity against `W = Frob(S_c)`, with no committed state.

### 3.2 Witness (unlocking `<WQ> <WS> <redeem>`, exactly two items besides the redeem)

| item | bytes | content (all words little-endian, fixed width) |
|---|---:|---|
| WS [0, 384) | 384 | x_A, y_A, x_B.c0, x_B.c1, y_B.c0, y_B.c1, x_C, y_C (8 × 48) |
| WS [384, 448) | 64 | n₀, n₁ (32 B each) |
| WS [448, 576) | 128 | nibble strings N₀, N₁ (64 B each): byte j of N_k holds bit `63 − j` of `d_{k,0..3}` (bit i ↔ digit i) |
| WS [576, 864) | 288 | `s^c`: the monic representative of the residue root c (6 × 48) |
| WS [864, 10080) | 9,216 | states S₁..S₃₂ (6 × 48 each) |
| **WS** | **10,080** | |
| **WQ** | **5,664** | exactly 118 words: the odd coefficients `q₁₁₇ … q₀` of the aggregated quotient, highest first (`q_j` is the coefficient of `X^{2j+1}`; zero top words are normal) |

The digits are `n_k = Σ_{i<4} d_{k,i}T^i` with `0 ≤ d_{k,i} < T < 2⁶⁴`: the canonical base-|x| expansion. The prover
uses it; the verifier accepts any digits < 2⁶⁴ that satisfy the exact binding.

### 3.3 Transcript

```
h0    = SHA256(TAG ‖ WS)                       TAG = "SIGLS-BLS/1" ‖ SHA256(VK encoding)   (fixed length)
ρ_raw = SHA256(h0 ‖ "rho")
z_raw = SHA256(h0 ‖ ρ_raw ‖ WQ)
ρ = BIN2NUM(ρ_raw ‖ 0x00),  z = BIN2NUM(z_raw ‖ 0x00)       (both in [0, 2²⁵⁶) ⊂ [0, p): no reduction)
require z ≠ 0
```

All three preimages are fixed length and made of fixed-width fields, so each parses in exactly one way. (The reference
`protocol.mjs` uses TAG without the VK digest; the build should add it. It costs 32 B and is transcript hygiene across
deployments.)

### 3.4 On-chain steps

1. **Layout and challenges:**
   - DEPTH == 2; SIZE(WS) == 10,080; SIZE(WQ) == 5,664;
   - h0, ρ, z as above; z ≠ 0.
2. **Parse and check:**
   - every 48-byte word is decoded with `RD = BIN2NUM(w ‖ 0x00)` and must be `< p`;
   - n_k is decoded from 32 bytes and must be `< r`;
   - nibble strings: `N & 0x0f…0f == N`;
   - curves: `y_A² = x_A³ + 4` and `y_C² = x_C³ + 4` (mod p), `y_B² = x_B³ + 4(1+u)` in Fp2. Each is tested as `(lhs − rhs) mod p == 0`.
3. **Precompute:**
   - `z²..z⁶`, `t = z⁶ − 1`, `ηz` and its powers, and `c_j = Φ(γ₁^j)(z)` for j = 1..5;
   - per pair: `x_P z²`, `x_P z² t`, `y_P z³`, `y_P z³ t` (P = −A), and for C: `x_C z²`, `x_C z² t`, `y_C z³`;
   - `S_c(±z)`;
   - GLS: `v_{k,i}(±z) = R_{k,i}(±z)`, with `R_{k,2/3}(±z) = R_{k,0/1}(±ηz)`. Tables `TP_k[n] = Π_{i∈n} v_{k,i}(z)` and
     `TM_k[n]` at −z (16 entries each), and `TB[n] = Σ_{i∈n} T^i` (exact integers).
4. **Initial step:**
   - `F₊ = S_c(−z)·TP₀[N₀[0]]·TP₁[N₁[0]]`, and `F₋` likewise at −z;
   - `acc_k = TB[N_k[0]]`;
   - `T_B = (x_B : y_B : 1)`;
   - δ walk state `(x_δ, y_δ, 0)`.
5. **Events e = 0..62:**
   1. `F± ← F±² · L_B(±z)` (projective doubling);
   2. δ step (baked `λ_j`; on-chain `x_j`, `c_j`, exactly the BN recursion):
      - `c_j = (λ_{j−1} + λ_j)x_j − c_{j−1}`;
      - line `(c_j, −λ_j, 1)` at C, so `F± ← F±·(E ± y_C z³)`;
      - `x_{j+1} = λ_j² − x_j − s`;
   3. if bit `62−e` of T is set:
      - B mixed addition with +B and its line, `F± ← F±·L(±z)·S_c(∓z)`;
      - δ addition step;
   4. GLS: `F₊ ←· TP₀[N₀[e+1]]·TP₁[N₁[e+1]]`, `F₋ ←· TM…`, `acc_k ← 2acc_k + TB[N_k[e+1]]`;
   5. after events 0, 2, 3, 5, 6, 8, …, 60: with the next state `S'`, `R ← Rρ + F₊S'(−z) − F₋S'(z)`, then `F± ← S'(±z)`.
6. **Terminal:**
   - `F± ←· Rconst(±z)`; `R ← Rρ + F₊·W(−z) − F₋·W(z)` with `W = Frob(S_c)` (from `s^c`, §2);
   - endpoint: `X_T − x_ψ Z_T ≡ 0`, `Y_T + y_ψ Z_T ≡ 0` (Fp2, `(x_ψ, y_ψ) = ψ(B)`), and `Z_T ≠ 0` (`Z₀ mod p ≠ 0 ∨ Z₁ mod p ≠ 0`);
   - binding `acc_k == n_k` (exact integers, k = 0, 1).
7. **Accept** iff `(R − z·q(z²)·M(z)) mod p == 0`, where `q(y) = Σ_j q_j y^j` is evaluated by Horner over WQ (every word `< p`). Then clean stack.

**Baked (redeem) constants:**
- 68 δ slopes `λ_j` (Fp2, 96 B each);
- `R_{k,0} = rep[m_k]`, `R_{k,1} = rep[σ Frob m_k]`, with `m_k = f_T(IC_{k+1}, γ)`, k = 0, 1;
- `Rconst = rep[f_T(α, β)·f_T(IC₀, γ)]`;
- `γ₁` (or `γ₁^j`), `η`, `PX`, `PY`, `T`, `p`, `r`, TAG.

Each constant is recomputed from the VK and asserted against noble at build time. `math.mjs` already does this for
η, γ₁ (Frob(X^j), Frob(S)), ψ, the δ recursion (all 68 lines equal noble's chord/tangent), the four GLS factors
(class and `FE(R_{k,i}) = FE(m_k)^{T^i}`), and `Rconst`.

## 4. Owner table (soundness policy)

| value the verdict depends on | owner |
|---|---|
| A, B, C, n₀, n₁ | hashed in WS (h0, before ρ and z); canonical decoding (`< p`, `< r`); curve and twist equations |
| B's subgroup | exact endpoint `[T]B = −ψ(B)` with `Z_T ≠ 0` over the on-chain projective walk (§5.4) |
| the B trajectory, B lines, every `±z` evaluation, `S'(±z)`, `W(±z)`, `R`, `Q(z)`, `M(z)` | computed on-chain |
| δ lines | baked `λ_j` (VK constants, asserted against noble); `x_j`, `c_j` computed on-chain |
| GLS digits (choose the factor polynomials) | hashed in WS before ρ; nibble range check; exact binding `acc_k == n_k` |
| `R_{k,i}`, `Rconst`, η, γ₁, ψ constants, T | VK / curve constants, asserted against noble at build |
| residue root `s^c`, states `S_1..S_32` | hashed in WS before ρ; canonical (`< p`) |
| quotient words | hashed before z (z's preimage), after ρ; canonical (`< p`); fixed count 118 |
| ρ, z | computed on-chain from the transcript |
| every guard | evaluated on reduced values, or exact integers for the binding |

There is no prover-supplied evaluation anywhere, and no unchecked witness slope.

## 5. Soundness argument

### 5.1 Identities

For chunk k with event range `[a, b]`:
- `S₀ := 1`;
- each event's factor is `Φ_e = L_B·L_δ·[L'_B·L'_δ·S_c(−X) if the bit is set]·G_e`, with `G_e = Π_{k,i ∈ N_k[e+1]} R_{k,i}`;
- the initial step's factor is `S_c(−X)·G_{−1}`;
- `P_k = S_k^{2^{#squarings}} · Π_e Φ_e^{2^{(squarings after e)}}`, and the last chunk also carries `Rconst`;
- `D_k = P_k(X)·S'(−X) − P_k(−X)·S'(X)`, where `S' = S_{k+1}`, or `W = Frob(S_c)` for the last chunk.

M is even, so σ commutes with reduction mod M. Hence `D_k ≡ 0 (mod M)` ⟺ `P_k·σ(S')` is even ⟺ `[P_k] = [S']` in G,
provided `P_k ≠ 0` and `S' ≠ 0`:
- `P_k ≠ 0`: Fp12 is a field (M irreducible), and every factor is a nonzero polynomial of degree < 12:
  - a line has the `X³` term `y_P·Φ(c₂)` with `y_P ≠ 0` (h1 and h2 odd: no 2-torsion);
  - `c₂ = 2YZ` or `λ'` is nonzero by §5.4, and `c₂ = 1` for δ;
  - representatives are monic.
- `S' ≠ 0`: states are monic, and `W = Frob(S_c)` is the Frobenius of a nonzero element.

Chaining the 33 relations gives `[f'·c^{−T}] = [c^p]`, i.e. **`[f'] = [c]^λ`**, where

`f' = f_T(−A, B) · f_T(C, δ) · f_T(α, β) · f_T(IC₀, γ) · Π_{k,i} (σ^i Frob^i m_k)^{d_{k,i}}`

(up to Fp2 line scalings, which lie in Fp6, and the `w³` line factor, which lies in Fp4; FE kills both).

### 5.2 Residue

`[f'] = [c]^λ` means `f' = c^λ·s` with `s ∈ Fp6*`. Then
`FE(f') = (c^{p¹²−1})^{h1} · s^{(p⁶−1)(p⁶+1)/r} = 1`, because `λ = h1·r` and `r | p⁶ + 1`. No w witness is needed.

**Completeness:** `gcd(λ, p⁶+1) = r`, so every class whose FE is 1 has a λ-th root in G. The prover takes
`u = f'^{p⁶−1}`, `c = 1 + σ(u^{λ⁻¹ mod (p⁶+1)/r})`, and `protocol.mjs` asserts every identity is exactly divisible by M.
The monic map misses a class set of density ~1/p, a negligible completeness loss.

### 5.3 GT-GLS binding

The digits enter through the same hashed nibbles that select the factors. The script's accumulator is
`acc_k = Σ_j 2^{63−j}·TB[N_k[j]] = Σ_i d_{k,i}T^i` over the integers, and the script checks `acc_k == n_k` exactly.

`FE(σ^i Frob^i m) = FE(m)^{(−1)^i p^i}`, and `(−1)^i p^i ≡ (−x)^i = T^i (mod r)`. Asserted for the fixture VK:
`FE(R_{k,i}) = FE(m_k)^{T^i}`. So the GLS part of FE(f') is `FE(m_k)^{n_k}`, and

`FE(f') = [e(−A,B)·e(α,β)·e(IC₀ + n₀IC₁ + n₁IC₂, γ)·e(C,δ)]^{−1}`.

With §5.2 this is exactly the Groth16 equation for the stated n. The digits need not be canonical (< T): any digits
< 2⁶⁴ that meet the exact equality give the same GT element.

### 5.4 B binding and G2 membership

The walk starts at the curve-checked B and has no witness. Doubling has `Z₃ = 8Y³Z` and mixed addition has `Z₃ = Zλ'³`,
so Z = 0 is absorbing. `Z_T ≠ 0` then implies:
- every intermediate `Z ≠ 0`;
- every doubling has `Y ≠ 0`;
- every addition has `λ' ≠ 0` (T ≠ ±B).

So each step is the true group operation, every line scale (`2YZ`, `λ'`) is nonzero, and `T_end = [T]B`.

The endpoint gives `ψ(B) = −[T]B = [x]B`. ψ satisfies `ψ² − tψ + p = 0` on `E'(Fp2)` (order `r·h2`, `gcd(r, h2) = 1`).
The kernel of `ψ − x` has order `N(ψ − x) = λ`, and `gcd(λ, h2) = 1`, so the h2-component of B is O and B ∈ G2.
`ψ = [x]` on G2 (asserted), so honest B passes. This is the same check the reviewed BLS singleton fix uses
(`ψ(B) == −[|x|]B` with `Rz ≠ 0`).

### 5.5 Schwartz–Zippel

Every `D_k` is fixed once WS is fixed: the inputs, nibbles, states and `s^c` are hashed into h0, and lines and
evaluations are deterministic.

- **ρ step:** if some `D_k mod M ≠ 0`, then `Σ ρ^{32−k}(D_k mod M)` is a nonzero polynomial in ρ of degree ≤ 32.
- **z step:** otherwise the verifier checks `Σρ^{…}D_k(z) = z·q(z²)·M(z)` with q fixed before z. The difference is
  nonzero, because M does not divide a nonzero polynomial of degree < 12.
- **Degree of the difference:** at most `max(deg D_k, 2·118 − 1 + 12) = 247` for **every** accepted witness. This is
  structural: ≤ 8 GLS bits per event; the B line has degree 9, the δ line 8, `S_c` 6, each GLS factor 6, and W 11.
  - The worst chunk is `[4,5]` or `[13,14]`: `deg P = 24 + 2·65 + 88 = 242`, so `deg D ≤ 247`, `deg Q ≤ 235`, i.e. 118 odd words.
  - `worst.mjs` shows honest statements reach exactly 118, so the cap is tight; random statements average about 94 words.
- **Error:** ρ and z are uniform on `[0, 2²⁵⁶)`. `ε ≤ (32 + 247)/2²⁵⁶ ≈ 2^{−247.9}` per random-oracle query (`q_H·2^{−247.9}` overall).

### 5.6 G1 (no subgroup check on A, C; same as the reviewed BLS singleton)

BLS12-381 G1 has cofactor `h1 = (x−1)²/3`, and the policy's checks on A and C are curve checks only:
- `FE(f_T(Q, ·))` restricted to `E(Fp)` is a power of the reduced Tate pairing `t_r(Q, ·)`. The HSV relation needs only
  `π(P) = P` and `[r]Q = O`; for Q this holds by §5.4.
- `t_r(Q, ·)` is defined on `E(F_{p¹²})/rE`, and a point of order dividing h1 (coprime to r) lies in `rE`.
- So the verdict for `(A, B, C)` equals the verdict for `(A_r, B, C_r)`, which is then a valid Groth16 proof, and the
  statement is sound.
- The cofactor parts only add proof malleability, which Groth16 has anyway.

The independent BLS singleton review (`work/bls-singleton-review/REVIEW.md`, item 3) accepted this argument and confirmed
it numerically. If the owner wants explicit G1 membership, `φ(P) = [−x²]P` costs about 8M op per point (≈ 21 kB of
budget for both), so it is not recommended.

## 6. Spec rules (carried over from the BN review, adapted)

1. **Injective transcript:**
   - one fixed-size WS push and one fixed-size WQ push, both SIZE-checked;
   - fixed-length, tagged preimages for h0, ρ_raw and z_raw.
2. **Fixed Q width:** exactly 118 words, each `< p`, zero top words allowed (fixed width makes the encoding injective;
   no leading-word rule). The degree bound uses 118.
3. **Projective formulas exactly as written** (Z = 0 absorbing; lines are Fp2 multiples of affine lines). Check `Z_T ≠ 0`.
4. **Unsigned hash-to-field:** `BIN2NUM(h ‖ 0x00)`. It is < p, so there is no mod and no bias. Test `z ≠ 0`.
5. **GLS:** read all 64 nibbles MSB-first from the same hashed strings that feed the binding; exact `acc_k == n_k`;
   `n_k < r`; nibbles ≤ 0x0f.
6. **Constants:** assert at build η, γ₁, ψ, every δ line, the `R_{k,i}` classes and exponents, and Rconst (as `math.mjs` does).
7. **Sign-safe guards:** every equality and nonzero test is on `(a − b) mod p`. The binding is an exact integer
   equality of two nonnegative numbers.
8. **Canonical decoding:** `RD` on every 48-byte word (coordinates, `s^c`, states, Q). `n_k` is unsigned 32 B and `< r`.
9. **Pinned layout:** DEPTH == 2 at entry, consensus clean stack, push-only unlocking.

## 7. Input layout, bytes and op (one P2SH32 input, bch-spec)

| | bytes |
|---|---:|
| locking (P2SH32) | 35 |
| redeem: code (BN 4,057 B, adjusted) | ~3,900 |
| redeem: 33 field constants × 49 B + T | 1,626 |
| redeem: δ slope pile (68 × 96 B + headers) | 6,555 |
| redeem: tag, schedule, separators | ~100 |
| **redeem** | **~12,200** |
| WS + WQ + 3 push headers | 15,753 |
| unlocking without padding | ~27,934 |
| padding for a 5% margin (in the redeem, `<pad> DROP`, or spent on option B constants) | ~2,370 |
| **unlocking** | **~30,300** |
| **score** (+ 35 locking + ~63 tx) | **~30,400** |

Op (worst case: every Q word full length; `total.mjs`, standard mode):

| section | op | basis |
|---|---:|---|
| B doubling + line + F² (63) | 15.44M | 245,080 measured (BN 143,186; built BN 143.2k per event) |
| B addition + line + c⁻¹ (5) | 1.66M | 331,127 measured |
| δ steps (68) | 5.42M | 76,821 measured + BN slope-read glue ×1.2 |
| GT-GLS (64 nibbles) | 2.32M | 30,204 measured + BN glue ×1.1 |
| event control (63) | 0.59M | BN measured per event |
| state boundaries (32) | 2.18M | EV 28,266 + RD 9,990 + fold 14,506 measured, + BN glue |
| quotient (118 words) | 1.08M | Horner4 18,649 + RD measured, + BN glue ×1.2 |
| setup (transcript, parse, powers, GLS tables, loop setup) | 1.47M | tables 4 × 92,427 + 8 × EV measured; the rest is BN ×1.5–1.8 |
| terminal, cleanup, P2SH | 0.48M | BN ×1.44 |
| **total** | **30.63M** | **unc. ±0.6M**; with all glue ×1.5: 31.6M (score 31.7 kB) |

**Liveness.** WS and WQ have fixed sizes, so the unlocking length and the budget `(10,000 + U)·800` are constant for
every statement. The op varies only through word lengths (zero Q words and short numbers are cheaper). The model
prices every Q word at full length, so it already is the worst case. The worst honest witnesses (`worst.mjs`: n_q = 118)
are full; the cheapest is n = 0 (n_q = 46).
- The margin is set by one build-time number, the padding: about 400 B per percentage point.
- Recommended: build at 6% (score ~30.8 kB), so a 1% modelling error still leaves 5% in both modes.
- Sweep: the 118-word witnesses, the zero statement, the bench fixtures, random proofs.
- Standard mode is the binding one (+0.2% over consensus for BN, from hash-iteration pricing).

The op is 1.5 × the BN verifier for the same structure. Each 48 × 48 MUL costs 2.25 × a 32 × 32 one, and a MOD of a
product costs 2.25× too. A constant 100 per instruction dampens this to a measured 1.64–2.04× per kernel. Bytes do not
grow as fast: 8 kB of the 10 kB WS is the 32 states. So **BLS SI-GLS is op-bound**, while BN was byte-bound (95% of budget).

## 8. Optional byte trims (not recommended for the first build)

With the design op-bound, a byte added to the unlocking buys 800 op of budget. Trims that remove more than ~760 op per
added byte (at a 5% margin) lower the score until the design becomes byte-bound:

| option | change | score at 5% |
|---|---|---:|
| baseline | uniform projective B, δ recursion, ~2.4 kB padding | ~30,400 |
| A | 10 doublings in an addition-free span (events 15..45) done affine with **witnessed slopes** (exact check `2yλ = 3x²`; measured 152,868 op vs 245,080). Entering the span needs a witnessed `Z⁻¹` (checked `Z·Z⁻¹ = 1`); leaving it is `Z = 1`. | ~29,300 |
| B | 15 δ lines with `c_j` also baked (VK constants): no recursion for them | ~29,550 |

Both add a second kernel kind and new review surface (A adds a witness value owned by an exact equation and a
projective→affine conversion). The padding is useful slack instead: the builder may bake any derived constant
(`γ₁^j`, `PX`, `PY`, η powers) rather than derive it on-chain, up to the padding level at no score cost.

## 9. Build plan (from `chunked/bn254/sound-si-gls`)

1. `math.mjs`: replace with this directory's version (BLS constants and facts, already asserted). Add the TAG/VK digest.
2. `protocol.mjs`: this directory's version is the honest prover and value-level mirror. Add on-chain-exact encodings
   (TAG ‖ VK digest) and a red-team forge mode modelled on BN's (malformed-input rejection only).
3. `asm.mjs`: this directory's copy (`setPrime`). Its kernels are scheduled against the 48-byte cost model.
4. `script.mjs`: port the BN program:
   - 48-byte RD, and P via a function;
   - kernels `kBDblBLS`, `kBAddBLS` (env +B, `c⁻¹` only), `kDStepBLS` from `kernels.mjs` (already checked in the VM against the reference);
   - the event loop with a 63-byte schedule string (bit 0: addition, bit 1: boundary);
   - the initial step;
   - tables with `TB` from T;
   - terminal: endpoint vs `−ψ(B)`, Rconst, `Frob(S_c)`, binding `acc == n`;
   - fixed-width Horner over 118 words;
   - padding.
5. `build/export/redteam/sweep/profile` as in BN; the sweep must include the 118-word witnesses and n = 0.
6. Bench: VK and fixtures as in `singleton/bls12-381/bls_instance.mjs` and `gen-multiproof-bls12381.mjs`
   (α = 3, β = 5, γ = 7, δ = 11, IC = [2, 4, 6]·G1; B = b·G2, C = c·G1, A solved in the exponent). `mintProof()` in `math.mjs` reproduces them.

## 10. Open risks

- **Not built.** The op total is per-kernel measurements plus BN-calibrated glue, with ±2% (±0.6M, ±0.8 kB) uncertainty.
  Code bytes are estimated (~3,900 B). Because the design is op-bound, a code-byte error changes the padding, not the score.
- **Kernels are VM-measured and output-checked**, but the line-slot formulas are new for BLS. They are checked against
  `projDbl/projAdd + linePoly` at ±z and against noble's walk and lines. There is no formal equivalence proof of
  generated bytecode (same as BN).
- **G1 cofactor:** relies on §5.6 (the reviewed singleton precedent). Proofs are malleable by h1-torsion; this matters
  only if proof bytes are used as identifiers.
- **Statement encoding:** public inputs bind through hashed digits and an exact equality, not through a vk_x point (the
  same open owner decision as BN SI-GLS).
- **Item size:** WS is 10,080 B, which is fine under bch-spec (100,000-B items). Under a 10,000-B item limit it would
  have to be split into two pushes (+1 DEPTH item, +3 B).

## Reproduce

From this directory, with the repository's `node_modules` (`@noble/curves` 2.2.0, `@bitauth/libauth` 3.1.0-next.8):

```sh
node math.mjs          # asserts all constants and facts (silent on success)
node test.mjs          # prover + value verifier on 6 statements, tamper rejection
node worst.mjs         # forced 118-word witnesses and n = 0
node search.mjs        # chunking search (states vs Q cap, honest n_q distribution)
node kernels.mjs 4000  # VM-measured kernels, BLS and BN (writes kernels.json)
node total.mjs         # op/byte totals; MARGIN=0.06, GLUE=1.5 knobs
```

`bn-profile.txt` is the BN verifier's `profile.mjs` output (standard mode, fixture 0) used for calibration.

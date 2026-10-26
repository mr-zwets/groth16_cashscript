# BLS12-381 SI-GLS: one batched torus identity, single input, bch-spec (design 1, angle: minimum bytes)

**Status:** design with measured kernels and an executable protocol reference. Not built as a script.
**Estimate (fixture `committed`, bench primary):** **27,443 B** (35 locking + 27,345 unlocking + 63 tx).
Op cost is 27.87M standard / 27.85M consensus against a 29.88M budget (93.3%). The worst liveness witness is at
93.4%, so the margin is 6.6%. Dense statements cost 29,459 B and a quotient at its cap 30,851 B (87.2%).
**Compared with** kallisti's `bch-groth16-bls12381-singleton-fs-spec-zero`, 65,218 B (unreviewed): **−37.8 kB (42%)**.
The BN254 original is `chunked/bn254/sound-si-gls`, 21,915 B.

This is a port of the reviewed BN254 SI-GLS construction (`chunked/bn254/sound-si-gls`; design record
`research/sound-sz-bn254/single-identity`) to BLS12-381 for the bench's BLS fixture VK. Every accept-relevant value
is computed on-chain, a VK constant asserted at build time, hash-committed before the challenge it meets, or fixed by
an exact field or integer equation. No prover-supplied evaluation is used.

Three things are cheaper on BLS12-381 than on BN254:
- The Miller loop has no Frobenius end steps, and only 5 additions instead of 21.
- The residue exponent is simply λ = p + |x|.
- The GT-GLS digits are the canonical base-|x| digits of n: no lattice, no signs, no offset.

Two things are more expensive:
- 48-byte field words make a mulmod about 1.7× the BN cost.
- The op budget, not the byte count, binds. The design spends bytes on witnessed affine B slopes exactly up to the
  95% budget line.

## 1. BLS-specific mathematics (all asserted in `blsmath.mjs`, printed by `node facts.mjs`)

| item | value / statement |
|---|---|
| curve | E: y² = x³ + 4 over Fp (381-bit p), r = x⁴ − x² + 1 (255-bit), x = −0xd201000000010000 |
| Fp12 | Fp[X]/M, **M = X¹² − 2X⁶ + 2**. Noble's tower maps in as X = w, v = X², **u = X⁶ − 1** (u² = −1, v³ = 1 + u = ξ, w² = v). The map is multiplicative (asserted on random elements), and M(w) = 0. |
| irreducibility | Rabin test on M: X^(p¹²) ≡ X, gcd(X^(p⁶) − X, M) = gcd(X^(p⁴) − X, M) = 1. |
| Φ (Fp2 → Fp12) | Φ(a₀ + a₁u) = (a₀ − a₁) + a₁X⁶, so Φ(a)(z) = a₀ + a₁t with t = z⁶ − 1. |
| conjugation σ = Frob⁶ | X ↦ −X (M is even, so σ commutes with reduction; Fp6 = even polynomials) |
| Frob² | X ↦ ηX with **η = 2^((p−1)/6)** = ξ^((p²−1)/6) ∈ Fp, a primitive 6th root; η² = η − 1 |
| Frob | Frob(X^j) = Φ(γ₁^j)X^j with γ₁ = ξ^((p−1)/6), and Frob(X⁶) = 2 − X⁶. Hence Frob(S) for a monic S = X⁶ + Σs_jX^j is (s₀ + 2 − X⁶) + Σ_{j=1..5} s_j(α_jX^j + β_jX^{j+6}), with (α_j, β_j) = Φ(γ₁^j). |
| twist | M-type, E′: y² = x³ + 4ξ. Untwist (x′, y′) ↦ (x′/w², y′/w³). ψ(x, y) = (x̄/γ₁², ȳ/γ₁³), asserted equal to untwist⁻¹∘Frob∘untwist. |
| line convention | The affine line through T′ with slope λ (twist coordinates) at P = (x_P, y_P), times w³: **L(X) = Φ(λx_T − y_T) − x_P X²Φ(λ) + y_P X³** (degree 8). The generic, projectively scaled line is Φ(ℓ₀) + x_P X²Φ(ℓ₂) + y_P X³Φ(ℓ₃) (degree 9). The w³ factor is a class of order 2 in G, and FE(w³) = 1 (asserted). |
| Miller loop and sign | We loop over \|x\| (63 events e = 0..62, event e ↔ bit 62 − e). There are additions after the doublings of events 0, 2, 5, 14 and 46, and no Frobenius end steps. ê(P, Q) := FE(f_{\|x\|,Q}(P)) = e(P, Q)⁻¹ (asserted against noble, which conjugates for x < 0). ê is a nondegenerate bilinear pairing, so the Groth16 product = 1 test is unchanged. |
| residue | G = Fp12*/Fp6* is cyclic of order p⁶ + 1. **λ = p + \|x\| = p − x = m·r with m = (x − 1)²/3 = h₁**. gcd(λ, (p⁶+1)/r) = 1, 3 ∤ p⁶ + 1, and r² ∤ p⁶ + 1. So [f] = [c]^λ ⇔ FE(f) = 1, roots always exist, and no cubic or 27th-root witness is needed. |
| G2 membership | #E′(Fp2) = h₂·r with h₂ odd and gcd(h₂, r) = 1. ψ² − tψ + p = 0 (t = x + 1) and **N(ψ − [x]) = p − x = h₁r**, with **gcd(h₁r, h₂) = 1**. So (ψ − [x])B = O for B ∈ E′(Fp2) implies B ∈ G2. ψ = [x] on G2 is asserted, and so is ψ ≠ [x] on a non-G2 point. |
| G1 cofactor | E(Fp) has order h₁r with h₁ = 3·11²·10177²·859267²·52437899² (odd, so y_P ≠ 0). ê(P, Q) = ê(P_r, Q) for every P ∈ E(Fp), where P_r is the G1 component: the reduced Tate pairing is a homomorphism on E(Fp)/rE, and the ate value is a power of it on E(Fp). This is asserted on a point with components of every prime order dividing h₁. A curve-checked A or C off G1 therefore only re-encodes a valid proof (the statement stays true). |
| GT-GLS | Frobenius on GT is the p-power and p ≡ x (mod r). Write **n = Σ_{i<4} a_i\|x\|^i** with the base-\|x\| digits 0 ≤ a_i < \|x\| < 2⁶⁴ (r < \|x\|⁴). Then ê(IC, γ)^n = Π_i FE(Frob^i(m)^{(−1)^i})^{a_i}, because \|x\|^i ≡ (−p)^i (mod r) (asserted with noble). The factor polynomials are R₀(X), R₁(−X), R₀(ηX), R₁(−ηX), where R₀ = rep[m], R₁ = rep[Frob(m)], m = f_{\|x\|,γ}(IC). |

## 2. Protocol

**Pairs.** P₀ = −A with Q₀ = B (runtime). P₁ = C with Q₁ = δ (fixed: 68 baked slopes). e(α, β)·e(IC₀, γ) is one baked
class, and e(vk_x, γ)/e(IC₀, γ) is folded in by GT-GLS. A class is represented by a monic degree-6 polynomial
S = X⁶ + Σ_{j<6} s_jX^j (6 words).

**B walk.** Events 0..E_A−1 (**E_A = 15**) are affine with witnessed slopes:
- doubling: check 2yλ = 3x², then x₃ = λ² − 2x, y₃ = λ(x − x₃) − y;
- addition with B: check λ(x_B − x) = y_B − y and x ≠ x_B.

Events 15..62 are homogeneous projective, starting from (x : y : 1):
- doubling: X₃ = 2XY(B−F), Y₃ = (B+F)² − 12E², Z₃ = 4BH, where B = Y², C = Z², E = 3b′C, F = 3E, H = 2YZ;
  line (B − E, −3X², H) = 2YZ·(affine tangent);
- mixed addition: θ = Y − y_BZ, λ′ = X − x_BZ, X₃ = λ′H, Y₃ = θ(G − H) − YE, Z₃ = ZE;
  line (θx_B − λ′y_B, −θ, λ′) = λ′·(affine chord).

Exactly these formulas are required: Z = 0 is absorbing (Z₃ = 8Y³Z, and Z·λ′³).

**δ walk.** Each δ step reads a baked slope λ_j (pile in the redeem). The state is (x_j, c_{j−1}, λ_{j−1}):
c_j = (λ_{j−1} + λ_j)x_j − c_{j−1}, line (c_j, −λ_j, 1) at C, x_{j+1} = λ_j² − x_j − s_j (s_j = x_j or x_δ).
The start is (x_δ, y_δ, 0). All 68 lines and the recursion are asserted against noble at build time.

### 2.1 Witness: unlocking `<WQ> <WS> <redeem>` (exactly two items besides the redeem)

`WS` is one push of **exactly 11,904 bytes**. All field words are 48-byte little-endian and decoded unsigned
(BIN2NUM(w ‖ 0x00) < p). n_k are 32-byte little-endian words, < r.

| offset | bytes | content |
|---|---:|---|
| 0 | 384 | x_A, y_A, x_B.c0, x_B.c1, y_B.c0, y_B.c1, x_C, y_C |
| 384 | 64 | n₀ (offset 384), n₁ (offset 416): the bench's public-input offsets (push 1, le32) |
| 448 | 128 | nibble strings N₀, N₁ (64 B each): byte j holds bit 63 − j of a_{k,0..3} (bit i of the byte = digit i). Byte 0 is applied at the start, byte e + 1 at event e. |
| 576 | 288 | s^c: the monic representative of the residue root c |
| 864 | 9,216 | states S₁..S₃₂ (6 words each), after events 0, 2, 3, 5, 6, 8, 10, …, 58, 60 |
| 10,080 | 1,824 | B slopes λ (2 words each), in walk order for events 0..14: 15 doublings and the additions at 0, 2, 5 and 14 (19 slopes) |

`WQ` (48·n_q bytes, 1 ≤ n_q ≤ **NQ_MAX = 118**) holds the odd coefficients q_{n_q−1} … q₀ of the aggregated
quotient, highest first (q_j is the coefficient of X^{2j+1}). The leading word must be nonzero, tested on the decoded
unsigned value.

### 2.2 Transcript

h₀ = SHA256("SIGLS-BLS/1" ‖ WS); ρ_raw = SHA256(h₀ ‖ "rho"); z_raw = SHA256(h₀ ‖ ρ_raw ‖ WQ).
ρ = BIN2NUM(ρ_raw ‖ 0x00) and z = BIN2NUM(z_raw ‖ 0x00). Both are in [0, 2²⁵⁶) ⊂ Fp, exactly uniform with no
reduction bias, because 2²⁵⁶ < p. Require z ≠ 0.

WS is fixed-width and fixed-size, so h₀'s preimage parses one way. WQ is a whole number of words and is the last
field of z's preimage. The three preimages have distinct fixed prefixes and separators.

### 2.3 On-chain steps

1. **Layout and challenges.** DEPTH == 2, SIZE(WS) == 11,904, SIZE(WQ) ≡ 0 (mod 48), 48 ≤ SIZE(WQ) ≤ 48·118.
   Then h₀, ρ, z, and z ≠ 0.
2. **Decode and checks.** Every field word must be < p (unsigned), and n_k < r. The nibble strings must equal
   themselves AND 0x0f…0f. The curve checks are y_A² = x_A³ + 4, y_C² = x_C³ + 4 and y_B² = x_B³ + 4(1 + u). The
   point at infinity is not encodable, so A, B, C ≠ O.
3. **Precompute.**
   - Powers: z^2..z^6, (ηz)^1..^6, t = z⁶ − 1; per pair, x_P z², x_P z²t, y_P z³ (and y_P z³t for the projective lines).
   - γ₁², γ₁³ and (α_j, β_j) = Φ(γ₁^j), derived from the baked γ₁.
   - The GLS factor values R_{k,0}(±z, ±ηz) and R_{k,1}(±z, ±ηz); the tables TP_k[n] = Π_{i∈n} v_{k,i}(z) and
     TM_k[n] at −z; the shared exact-integer table TB[n] = Σ_{i∈n} |x|^i.
   - S_c(±z), and Rconst′(±z).
4. **Start.** F± = S_c(∓z)·TP/TM₀[N₀[0]]·TP/TM₁[N₁[0]], acc_k = TB[N_k[0]], R = 0.
5. **Events e = 0..62.**
   1. F± ← F±²·L_B(±z), with the B doubling (affine slope check, or projective).
   2. The δ step: F± ← F±·L_δ(±z).
   3. If e ∈ {0, 2, 5, 14, 46}: the B addition with its line and the factor S_c(∓z), then the δ step.
   4. F± ← F±·TP/TM₀[N₀[e+1]]·TP/TM₁[N₁[e+1]], and acc_k ← 2acc_k + TB[N_k[e+1]].
   5. After event 0: F± ← F±·Rconst′(±z).
   6. At a boundary with next state S′: R ← Rρ + F₊S′(−z) − F₋S′(z), then F± ← S′(±z).
6. **Terminal** (after event 62).
   - W(±z) = Frob(S_c)(±z) from s^c, and R ← Rρ + F₊W(−z) − F₋W(z).
   - B endpoint: X·γ₁² ≡ conj(x_B)·Z and Y·γ₁³ ≡ −conj(y_B)·Z (Fp2), with Z ≢ 0, all on reduced values. That is
     [|x|]B = −ψ(B).
   - Binding: acc_k == n_k (exact integers).
7. **Accept** iff (R − z·Q′(z²)·M(z)) mod p == 0, with Q′(y) = Σ_j q_j y^j (Horner in z²) and
   M(z) = z¹² − 2z⁶ + 2. Clean stack.

Baked VK constants, each asserted against noble at build:
- 68 δ slopes and the start (x_δ, y_δ);
- R_{k,0}, R_{k,1} (4 monic polynomials);
- Rconst′ = rep[(m_{α,β}·m_{IC₀,γ})^{2^−62 mod r}]: it sits after event 0 and is squared 62 times, so
  FE(Rconst′^{2⁶²}) = FE(m_{α,β}m_{IC₀,γ}) (asserted);
- p, η, γ₁, |x|, the 0x0f mask and the tag.

## 3. Soundness argument (constructive, per the policy)

**Owners of every accept-relevant value.**

| value | owner |
|---|---|
| A, B, C, n₀, n₁, nibbles, s^c, S₁..S₃₂, B slopes | hash-committed in h₀ before ρ and z; canonical unsigned decoding; curve checks; n_k < r; nibbles ≤ 15 |
| B slopes (additionally) | fixed by exact field equations: 2yλ = 3x², or λ(x_B − x) = y_B − y with x ≠ x_B. y ≠ 0 holds because E′(Fp2) has odd order. |
| B trajectory, all B lines | computed on-chain from the curve-checked B (affine with checked slopes, then projective) |
| δ trajectory and lines | baked slopes (VK constants) and on-chain x/c recursion |
| GLS factor values, tables TP/TM/TB | VK constants R_{k,i} evaluated on-chain; TB exact integers |
| W = Frob(S_c), S_c(±z), states at ±z | computed on-chain from committed words |
| ρ | SHA256 of h₀ (after all of WS) |
| q_j | committed in z's preimage (after ρ); count capped and canonical |
| z | SHA256 of h₀, ρ and WQ; z ≠ 0 |
| endpoint, Z ≠ 0, binding, final identity | exact equations on reduced values or exact integers |

**Identities.** Chunk k over events [a, b) uses S₀ := S_c(−X)·G_init. Then
P_k = S_k^{2^{b−a}}·Π_e (L_{B,e}L_{δ,e}·[L′_{B,e}L′_{δ,e}S_c(−X) if addition]·G_{0,e}G_{1,e})^{2^{b−1−e}}, times
Rconst′ for k = 0, and D_k = P_k(X)S_{k+1}(−X) − P_k(−X)S_{k+1}(X). The terminal uses S₃₃ := W = Frob(S_c).

M is even, so D_k ≡ 0 (mod M) ⇔ P_k·σ(S_{k+1}) ∈ Fp6 ⇔ [P_k] = [S_{k+1}] in G, provided P_k ≠ 0 and S_{k+1} ≠ 0. Every
factor is nonzero:
- Affine lines have X³ coefficient y_P ≠ 0 (odd group orders) and degree < 12.
- Projective lines have X³ coefficient y_P·Φ(ℓ₃), with ℓ₃ = 2YZ or λ′. These are nonzero because Z = 0 is absorbing
  and the endpoint requires Z ≠ 0.
- The GLS factors, S_c(±X) and Rconst′ are monic, and W = Frob(S_c) ≠ 0.

Chaining the 33 relations gives [f′·c^{−|x|}] = [c^p], i.e. **[f′] = [c]^λ**. Here
f′ = f_{|x|,B}(−A)·f_{|x|,δ}(C)·Rconst′^{2⁶²}·Π_{k,i}(Frob^i(m_{IC_{k+1},γ})^{(−1)^i})^{a_{k,i}}, up to Fp2 line
scalings and powers of w³.

**Residue.** f′ = c^λ·s with s ∈ Fp6*, so FE(f′) = c^{m(p¹²−1)}·s^{(p⁶−1)(p⁶+1)/r} = 1. Completeness: gcd(λ, (p⁶+1)/r) = 1,
and the prover takes c = 1 + conj(t) with t = (f′^{p⁶−1})^{λ⁻¹ mod (p⁶+1)/r}.

**GT-GLS binding.** acc_k = Σ_i a_{k,i}|x|^i exactly, built from the same hashed nibbles that select the factors, and
the script checks acc_k = n_k. Since |x|^i ≡ (−p)^i (mod r) and FE(Frob^i(m)) = FE(m)^{p^i}, the GLS part of FE(f′) is
ê(IC₁, γ)^{n₀}·ê(IC₂, γ)^{n₁}. Hence **FE(f′) = ê(−A, B)·ê(α, β)·ê(vk_x, γ)·ê(C, δ) = 1**, which is the Groth16
equation for the stated n (ê = e⁻¹). This holds for vk_x = O too: vk_x never appears as a point.

**B ∈ G2.**
- The affine part is the exact group law: slopes are unique given y ≠ 0 and x ≠ x_B, and no intermediate point is O,
  because a doubling never reaches O without 2-torsion and an addition with x ≠ x_B never gives O.
- The projective part is exact unless Z = 0, which is absorbing and rejected.
- So T_end = [|x|]B, and the endpoint gives (ψ − [x])B = O. With gcd(N(ψ − x), h₂) = 1 and ψ = [x] on G2, B ∈ G2.
- A and C are on E(Fp), and their cofactor parts do not change ê (section 1).

**Schwartz–Zippel.** Every D_k is fixed once WS is fixed. 33 identities give a ρ step error ≤ 32/2²⁵⁶. The z step error
is ≤ deg/2²⁵⁶ with deg ≤ max(max_k deg D_k, 2·NQ_MAX − 1 + 12) = 247 for every witness the script accepts (the worst
case is every GLS bit set in a projective add-second chunk: deg P = 4·6 + 2·65 + 88 = 242, and D is odd of degree
≤ 248, so ≤ 247; `proto.mjs` prints this bound). A nonzero polynomial of
degree < 12 is never a multiple of M, and M has no roots in Fp (it is irreducible). **ε ≤ 279/2²⁵⁶ ≈ 2^−247.9 per
random-oracle query.**

**Spec rules carried over from the BN review (required from the start).**
- Fixed-width, injective transcript.
- Enforced n_q cap and a canonical (nonzero) leading word, decoded unsigned.
- Unsigned SHA → field.
- Canonical decoding of every word: states, Q and slopes included.
- Reduced values before every equality or ≠0 guard.
- Exact push sizes, DEPTH 2, clean stack.
- Exactly the projective formulas above.
- The GLS bits come from the hashed, range-checked nibbles, and the same bytes drive the factors and the binding.
- Every baked constant is asserted against noble at build.

## 4. Size and op cost per input (one input; fixture `committed`, E_A = 15)

| part | bytes | op (standard) |
|---|---:|---:|
| redeem: δ slope pile (68 × 96 + 14 push headers) | 6,570 | (in δ) |
| redeem: field constants (38 words: p, η, γ₁, R_{k,0..1}, Rconst′, x_δ, y_δ) | 1,862 | |
| redeem: code (BN SI-GLS code 4,057, re-sized with the measured BLS kernels and affine B kernels) | 4,651 + 93 data | |
| WS: statement and public inputs | 448 | parse and curve checks 0.26M |
| WS: GLS nibbles | 128 | GLS loop 2.38M, tables 0.68M |
| WS: residue root s^c | 288 | terminal 0.43M |
| WS: 32 states | 9,216 | 2.15M (67k each) |
| WS: 19 B slopes | 1,824 | |
| WQ: 47 words (fixture `committed`) | 2,256 | 0.38M |
| push headers | 9 | |
| B walk: 48 projective doublings / 15 affine doublings | | 11.87M / 2.28M |
| B walk: 1 projective / 4 affine additions | | 0.35M / 0.66M |
| δ: 68 steps | | 5.67M |
| event glue, transcript, powers, misc | | 0.75M |
| **unlocking** | **27,345** | **27.87M** (consensus 27.85M) |
| budget (10,000 + 27,345)·800 | | 29.88M (**93.3%**) |
| **score** (+35 locking +63 tx) | **27,443** | |

**Where the op numbers come from.**
- `kernels.mjs` measures every arithmetic kernel in the libauth bch-spec VM, standard mode, after 20k-iteration
  scheduling. Each kernel's outputs are checked against a BigInt simulation, and the simulation against noble and
  the line polynomials. Per call:

  | kernel | op |
  |---|---:|
  | projective doubling + line + F² | 245,441 |
  | affine doubling with witnessed slope | 146,769 |
  | projective mixed add + c-mul | 331,901 |
  | affine add + c-mul | 145,832 |
  | δ step | 78,991 |
  | state eval + residual + ρ fold | 43,303 |
  | Horner (4 words) | 18,706 |
  | GLS loop, per event | 37,312 |
  | GLS 16-entry table | 92,630 |
  | monic evaluation at ±x | 28,279 |
  | Frob(S_c) at ±x | 101,623 |
  | word decode with < p check | 1,533 per word |

- The glue (stack moves, invocation, loop control, state and quotient handling) is calibrated per category on the
  built BN254 SI-GLS (`profile.mjs`, fixture 0: actual vs its research kernels). Kernels run 0.8–5.6% over the
  research measurement, plus fixed per-event (4.75k), per-addition (14.3k), per-state (14.7k) and per-word glue.
  The set-up and terminal are itemized in `total.mjs`.
- The code size is extrapolated from the built BN code. It has not been built.

**Liveness (≥ 5% in both modes).**
- Op is almost statement-independent and the budget grows with n_q, so the binding witness has the smallest
  quotient, n_q = 46. All digits are zero in the add-second chunks (their degree 103 sets n_q), and nonzero nibbles
  elsewhere keep full lookup cost (a zero nibble multiplies by the 1-byte constant 1, which is cheaper).
- That witness is at 27.87M / 29.84M = **93.4%** (margin 1.97M). The model's GLS loop was measured with random
  (nonzero) nibbles.
- Consensus differs only by hashing (−28k).
- At the cap (n_q = 118) the cost is 30,851 B at 87.2%. Dense statements (n_q 89) cost 29,459 B at 89.6%.
- Standardness: unlocking ≤ 100,000 B and tx ≤ 100,000 B; locking is P2SH32 (35 B).

**The E_A knob.** Each extra affine event adds 96 B of WS and takes about 0.55% off op/budget. The addition at
event 14 is worth about 1.4% for 96 B, which is why E_A = 15 rather than 14 (27,251 B at 94.7%). The builder should
re-tune E_A after measuring the real script, keeping ≥ 5% at the n_q-46 witness.

| E_A | score | op/budget | regime |
|---:|---:|---:|---|
| 0 (all projective) | 24,965 natural; 29,607 padded to 95% | 107.6% | op-bound: infeasible without padding |
| 6 | 26,483 | 99.3% | infeasible |
| 14 | 27,251 | 94.7% | 5.2% margin |
| **15** | **27,443** | **93.3%** | **headline** |
| 16 | 27,539 | 92.7% | |
| 63 (all affine) | 32,051 | 68.9% | byte-bound |

In the balanced regime 1 byte of witness or constants is worth about 1k op (0.565 B and 0.573 B of score per byte
and per 1k op, respectively). That rate is used below to price the alternatives.

## 5. Design choices and rejected alternatives

- **Chunking.** `a2`, 33 chunks / 32 states: [0][1,2][3][4,5][6][7,8]…[61,62]. Every addition is a single event or
  the second event of its chunk. `layout.mjs` scans greedy partitions against the worst case: the robust optimum is
  this layout (cap 118). Uniform pairs (`u2`, 31 states) tie on the primary score (n_q 55, cap 127). 3-event chunks
  (`u3`) are worse (n_q 121–201).
- **Bench-tuned layout (not recommended).** Twenty-three chunks of mostly 3 events would exploit fixture
  `committed`'s tiny inputs (no GLS bits before event 54). That saves about 600 B on the primary score but costs about
  1.3 kB on dense statements, and the cap rises to 257 words. This is the same kind of statement-dependent saving as
  kallisti's zero-PIC codec.
- **Rconst placement.** It sits in chunk 0, pre-exponentiated by 2^−62 mod r, instead of the terminal chunk (−2 Q
  words). In general, any baked GT constant can be placed where the degree has slack.
- **δ.** Baked slopes (96 B + 79k op per line) are the floor. On-chain projective δ costs about 215k per line,
  which is worse at the 1 B ≈ 1k op rate. Baking (λ, c) saves 32k op for 96 B, also worse.
- **R_{k,1} derived on-chain** (Frob of R_{k,0}, degree 11): it saves 576 B of constants for about 0.5M op, a net
  of about −40 B, and raises the dense Q. Not worth it.
- **Projective ↔ affine switching** (affine re-entry for the event-46 addition) needs a 4-word witness and two Fp2
  checks: net worse.
- **G1 subgroup checks on A, C** would cost a 128-bit G1 scalar multiplication (≈ 10M op ≈ 10 kB). They are not
  required: cofactor-equivalence, section 1.
- **GT-GLS digits on-chain** (from n by DIV/MOD) would save the 130 B of nibbles but cost about 0.5M op for bit
  extraction (≈ +150 B net). The committed nibbles are kept, as in the reviewed BN design.

## 6. Comparison

| entry | VM | bytes | status |
|---|---|---:|---|
| kallisti `bch-groth16-bls12381-singleton-fs-spec-zero` | bch-spec | 65,218 (dense 73,860) | unreviewed |
| **this design** | bch-spec | **27,443** (dense 29,459, cap 30,851) | design; sound by construction |
| BN254 SI-GLS (built, reviewed) | bch-spec | 21,915 | reviewed |

## 7. Open risks and builder notes

- **Not built.** Code bytes (±15%) and glue (calibrated, ±3%) are modelled. E_A absorbs op error at 96 B per 0.55%.
  Every other number is measured or exact.
- **Identity fixtures.** The bench's BLS corpus has 4 proofs with A, B or C = O (`a/b/c/all-identity`), and the
  affine encoding rejects them. Honest randomized Groth16 provers produce O with negligible probability. BN SI-GLS
  rejects identity points the same way. The other 6 fixtures are accepted by the protocol reference.
- **Public inputs bind through GT-GLS**, via hashed base-|x| digits and an exact integer check, as in BN SI-GLS.
- **Formula correctness is tested, not proved.** The reference prover asserts exact divisibility of every identity
  by M, and the batched ±z check, on 6 fixtures and 2 B-walk splits. The kernels are VM-checked against the same
  polynomials.
- **Liveness sweep the builder must run.**
  - n_q-46 witnesses with nonzero nibbles in every non-max chunk;
  - all-zero digits;
  - every nibble 15 (the cap);
  - random statements;
  - the 6 fixtures;
  - E_A ± 2.
- **Rejection tests to carry over from the BN red team.**
  - off-curve, aliased (+p) and out-of-range words;
  - n + r;
  - nibble > 15;
  - a wrong or aliased slope;
  - x = x_B at an addition;
  - B off G2 (random cofactor point);
  - state, residue and quotient tampering;
  - a leading zero word, cap + 1 words;
  - layout: extra, missing or reordered pushes, wrong sizes.

## 8. Files and reproduction

| file | role |
|---|---|
| `blsmath.mjs` | field/polynomial map, Miller loop in the verifier's line convention, and every fact of section 1 (asserted at import) |
| `facts.mjs` | prints the facts |
| `proto.mjs` | protocol reference: honest prover (lines, digits, residue root, states, quotient), value-level ±z verifier, worst-case degree bound. `node proto.mjs --eaff=15 --layout=a2` |
| `layout.mjs` | chunk-layout search (exact degrees, greedy partition, Rconst placement) |
| `dsl.mjs`, `asm.mjs` | the BN research scheduler and assembler, with P = BLS12-381 p |
| `kernels.mjs` | kernel measurements → `kernels.json` (`node kernels.mjs 20000`, ~6 s) |
| `total.mjs` | totals and E_A search → `total.json` (`node total.mjs --layout=a2 --eaff=15 --json`; `--margin=0.05` to search) |

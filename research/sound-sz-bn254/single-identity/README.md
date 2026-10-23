# Single-identity (SI-GLS): one batched torus identity at ±z, with e(vk_x, γ) folded into GT

**Status:** design plus measured kernels. Not built as a script.
**Measured score:** 22,711 B on fixture 0 and 22,970 B on fixture 4, the largest quotient of the
5 fixtures (byte-bound; 22.32M op against a 26.12M budget on fixture 0; the worst-case witness,
Q at its 132-word cap, uses 84% of its budget). The score depends on the proof through the
quotient length (69–114 odd words on the fixtures). `total.mjs` counts 66 B of transaction
overhead; at the ~100 B the other two designs use, the score is 22,745 B (fixture 0) and
23,004 B (fixture 4).
**Review:** sound. 1 major issue (transcript injectivity) and 5 minor issues, all folded into
the spec below as required rules. Two parts of the measured configuration changed after the
review and have not been re-reviewed: the GLS witness encoding (65-B nibble strings plus a sign
byte, instead of 8 hashed sub-scalars) and the grouped 16-entry table evaluation.

The design checks the Groth16 equation
`e(−A, B) · e(α, β) · e(vk_x, γ) · e(C, δ) = 1` with one input and no prover-supplied
evaluations. The Miller loop runs over two pairs, `(−A, B)` with runtime B and `(C, δ)` with
fixed δ. There is no vk_x MSM and no γ Miller loop: `e(vk_x, γ)` enters as Frobenius-twisted
GT constants raised to committed GLS sub-scalars of the public inputs.

## Notation

- `Fp12 = Fp[X]/M`, `M = X¹² − 18X⁶ + 82` (irreducible; `facts.mjs`). The noble tower maps in as
  `w = X`, `v = X²`, `u = X⁶ − 9` (so `u² = −1`, `v³ = 9 + u`).
- For `a = a₀ + a₁u ∈ Fp2`: `Φ(a)(X) = (a₀ − 9a₁) + a₁X⁶`, so `Φ(a)(z) = a₀ + a₁·t` with
  `t = z⁶ − 9`.
- `Fp6` = even polynomials. Conjugation `σ = Frob⁶` is `X ↦ −X`. `G = Fp12*/Fp6*` is cyclic of
  order `p⁶ + 1`.
- `Frob²` is `X ↦ ηX` with
  `η = 21888242871839275220042445260109153167277707414472061641714758635765020556617`
  (the unique primitive 6th root of unity in Fp that works; `η³ = −1`). For `f` with Fp
  coefficients, `Frob²(f)(X) = f(ηX)` mod M.
- **Class representative:** a monic degree-6 polynomial `S(X) = X⁶ + Σ_{j<6} s_j X^j`, six words
  `s₀..s₅`. Every class except a set of probability ~1/p has one; `Frob²` keeps it monic since
  `η⁶ = 1`.
- `λ = 6x + 2 + p − p² + p³ = m·r`. `d₀..d₆₄` = the NAF of `6x+2` without its leading digit
  (65 events, 21 nonzero, 13 of them −1).
- Pairs: `P₀ = −A` with `Q₀ = B` (runtime), `P₁ = C` with `Q₁ = δ` (fixed).

### Lines

A line with Fp2 coefficients `(ℓ₀, ℓ₁, ℓ₃)` at `P = (x_P, y_P)` is the polynomial

```
L(X) = y_P·Φ(ℓ₀)(X) + x_P·X·Φ(ℓ₁)(X) + X³·Φ(ℓ₃)(X)        (degree 9)
L(±z) = y_P·Φ(ℓ₀)(z) ± [x_P·z·Φ(ℓ₁)(z) + z³·Φ(ℓ₃)(z)]
```

- Affine tangent/chord through T with slope λ: `(1, −λ, λx_T − y_T)`.
- Projective doubling of `T = (X:Y:Z)` (homogeneous, `b' = 3/(9+u)`):
  `B = Y², C = Z², E = 3b'·C, F = 3E, H = (Y+Z)² − B − C = 2YZ`,
  `X₃ = 2XY(B − F)`, `Y₃ = (B + F)² − 12E²`, `Z₃ = 4B·H = 8Y³Z`.
  Line `(H, −3X², B − E)` = `2YZ · (affine tangent)`.
- Projective mixed addition `T + Q`, `Q = (x_q, y_q)` affine:
  `θ = Y − y_qZ, λ' = X − x_qZ, C = θ², D = λ'², E = λ'D, F = ZC, G = XD, H = E + F − 2G`,
  `X₃ = λ'H, Y₃ = θ(G − H) − Y·E, Z₃ = Z·E = Zλ'³`.
  Line `(λ', −θ, θx_q − λ'y_q)` = `λ' · (affine chord)`.

The Fp2 scale factors `2YZ` and `λ'` lie in `Fp2 ⊂ Fp6`, so they do not change classes.
`kernels.mjs` asserts `projective line ≡ Φ(scale) · affine line (mod M)` for both formulas.

### GT-GLS fold of e(vk_x, γ)

`e(vk_x, γ) = e(IC₀, γ) · Π_{k=0,1} e(IC_{k+1}, γ)^{n_k}`. Write
`n_k ≡ Σ_{i=0..3} e_{k,i}·p^i (mod r)` with the LLL-reduced lattice basis (rows in terms of x)

```
(2x+1, 0,   2x,     1)
(2x,   x+1, −x,     x)
(x+1,  x,   x,    −2x)
(2x+1, −x,  −(x+1), −x)
```

and Babai rounding: `|e_{k,i}| < 2⁶⁴` (column-sum bound 2^63.9). The decomposition is not unique,
so the `e_{k,i}` are witness and must be committed.

Baked constants (monic reps, `m_{P,Q}` = Miller value):
- `Rconst = rep[m_{α,β} · m_{IC₀,γ}]`
- `R_{k,0} = rep[m_{IC_{k+1},γ}]`, `R_{k,1} = rep[Frob(m_{IC_{k+1},γ})]`
- `R_{k,2}(X) = R_{k,0}(ηX)`, `R_{k,3}(X) = R_{k,1}(ηX)` (Frob² and Frob³ images, evaluated on-chain
  at `±ηz`)
- a negative `e_{k,i}` uses the conjugate factor `R_{k,i}(−X)`.

## Protocol

### Witness (unlocking pushes)

| Item | Encoding | Bytes |
|---|---|---|
| A (x, y), B (x₀, x₁, y₀, y₁), C (x, y), n₀, n₁ | 10 numbers; NUM2BIN to 32 B before hashing | 330 |
| GLS nibble strings `N₀, N₁` | 65 B each; byte e = bits `64−e` of `|e_{k,0..3}|` (bit i of the byte = sub-scalar i) | 2 × 66 |
| GLS sign byte | bit `4k+i` = 1 iff `e_{k,i} < 0` | 2 |
| residue root `s^c` | monic rep of c, one 192-B blob (6 × 32-B LE words) | 194 |
| states `S₁..S₃₃` | one 192-B blob each, at fixed boundaries after events 2, 4, …, 64, 65 | 33 × 194 |
| quotient `Q` | odd coefficients `q₁, q₃, …` of the aggregated quotient, 32-B LE words in 256-B blobs (8 words; the top blob may hold 4), padded to a multiple of 4 words, at most 132 words | 3,500 (fixture 0) to 3,759 (fixture 4) |

### Transcript and challenges

```
h  = SHA256(TAG ‖ VKDIGEST ‖ enc(A.x) ‖ … ‖ enc(n₁) ‖ N₀ ‖ N₁ ‖ signs)
h  ← SHA256(h ‖ blob)              for blob = s^c, S₁, …, S₃₃   (each SIZE == 192)
h₀ = h
ρ  = BIN2NUM(SHA256(h₀ ‖ "rho") ‖ 0x00) mod p
h  ← SHA256(h₀ ‖ enc(ρ));  h ← SHA256(h ‖ Qblob) for each Q blob (SIZE checked)
z  = BIN2NUM(SHA256(h ‖ "z") ‖ 0x00) mod p,   require z ≠ 0
```

`enc` is a 32-byte little-endian NUM2BIN. The prover forms `Q = Σ_k ρ^{K−1−k}·Q_k` over the
`K = 34` identities (33 chunks + the terminal) after seeing ρ, and pushes its odd coefficients.

### On-chain computation

1. **Range and curve checks.** All coordinates in `[0, p)`; `0 ≤ n_k < r`;
   `y_A² = x_A³ + 3`, `y_C² = x_C³ + 3`, `y_B² = x_B³ + b'` (in Fp2). Every nibble byte `< 16`
   (`0x0f` AND + EQUALVERIFY).
2. **Challenges** as above.
3. **Precompute.** `z², z³, z⁵, z⁶, z⁹`, `t = z⁶ − 9`; `ηz` and its powers; per pair
   `y_P, y_P·t, x_P·z, x_P·z·t` (and `3x_P z`, `3x_P z t` for the doubling line);
   `R_{k,i}(±z)` and `R_{k,i}(±ηz)`; `S_c(±z)`, `S_c(±ηz)`; `Rconst(±z)`.
4. **GLS tables** (per k): `v_{k,i}(±z)` = the sign-adjusted factor values;
   `TP_k[n] = Π_{i∈n} v_{k,i}(+z)`, `TM_k[n] = Π_{i∈n} v_{k,i}(−z)` (16 entries each);
   `TB_k[n] = Σ_{i∈n} s_{k,i}·π_i` with `π_i = p^i mod r` and `s_{k,i}` the sign (exact integers).
5. **Initial values.** `F₊ = S_c(−z)`, `F₋ = S_c(z)` (the class `[c⁻¹] = [S_c(−X)]`);
   `R = 0`; `acc₀ = acc₁ = 0`; `T = (x_B : y_B : 1)`; δ walk state `(x₀, c₀)` baked.
6. **For each event e = 0..64:**
   1. `F± ← F±²`.
   2. B doubling (projective) and its line: `F± ← F± · L_B(±z)`.
   3. δ line at `P₁ = C` with baked `λ_j`, `λ_{j+1}`: `F± ← F± · (y_C ± o)`,
      `o = −(λ_{j,0}·x_C z + λ_{j,1}·x_C z t) + c_{j,0}·z³ + c_{j,1}·z³ t`; then
      `x_{j+1} = λ_j² − x_j − s` (`s = x_j` for a doubling, `x_δ` for an addition),
      `c_{j+1} = (λ_j + λ_{j+1})·x_{j+1} − c_j`.
   4. If `d_e ≠ 0`: B mixed addition with `±B` and its line; the δ addition line;
      `F± ← F± · S_c(∓z)` for `d_e = +1`, `F± ← F± · S_c(±z)` for `d_e = −1`.
   5. GLS: `i_k = N_k[e]`; `F₊ ← F₊ · TP₀[i₀] · TP₁[i₁]`, `F₋ ← F₋ · TM₀[i₀] · TM₁[i₁]`;
      `acc_k ← 2·acc_k + TB_k[i_k]`.
   6. At a chunk boundary with next state `S'`: `R ← R·ρ + F₊·S'(−z) − F₋·S'(z)`, then
      `F± ← S'(±z)`.
7. **Terminal.** B: `T ← T + ψ(B)` and `T ← T − ψ²(B)`, each with its line; δ: its two Frobenius
   lines from 4 baked pre-mapped words each. `F± ← F± · Rconst(±z) · S_c(±ηz)` (the last factor is
   `[c^{p²}]`). `Fr₁ = Frob(S_c)` is computed from `s^c`:
   `Fr₁(x) = (s₀ + 18 − x⁶) + Σ_{j=1..5} s_j·(α_j x^j + β_j x^{j+6})` with baked `α_j, β_j`
   (`γ^j = α_j + β_j X⁶` for the Frobenius constant γ of X). `W(±z) = Fr₁(±z)·Fr₁(±ηz)`
   (`[c^p·c^{p³}]`). `R ← R·ρ + F₊·W(−z) − F₋·W(z)`.
8. **B endpoint.** `X_T = x(−ψ³(B))·Z_T`, `Y_T = y(−ψ³(B))·Z_T`, `Z_T ≠ 0`, by cross-multiplication.
9. **GLS binding.** `((acc_k mod r) + r) mod r == n_k` for k = 0, 1.
10. **Accept iff** all checks pass and `(R − z·Q'(z²)·M(z)) mod p == 0`, where
    `Q'(y) = Σ_j q_{2j+1} y^j` (Horner in `z²`).

ψ on the twist: `ψ(x, y) = (x̄·γ_x, ȳ·γ_y)` with `γ_x = ξ^{(p−1)/3}`, `γ_y = ξ^{(p−1)/2}`,
`ξ = 9 + u`; `ψ²(x, y) = (x·ξ^{(p²−1)/3}, −y)`.

## Committed before the challenge vs computed on-chain

**Committed before ρ (in h₀):** A, B, C; n₀, n₁; the GLS nibble strings and sign byte (they
choose which factor polynomials enter each identity and are not unique); `s^c`; all 33 states.
**Committed before z:** every odd coefficient of Q (after ρ).
**Not committed, uniquely determined:** nothing else; there are no slopes or evaluations in the
witness.

**Computed on-chain:** ρ, z; the whole B trajectory and its lines (projective, no witness); the
δ walk from baked slopes; ψ(B), ψ²(B), ψ³(B); `Frob(S_c)`; every evaluation at `±z`, `±ηz`; the
GLS tables; the chains `F₊, F₋`; the ρ-fold R; `Q(z)`, `M(z)`.
**Baked:** δ slopes `λ_j` and start `(x₀, c₀)`, the two 4-word Frobenius δ lines, `Rconst`,
`R_{k,0}`, `R_{k,1}`, `π_i`, η, `α_j, β_j`, ψ constants, `b'`, p, r, TAG/VKDIGEST.
**Checked exactly:** curve equations, ranges, nibble bounds, the B endpoint and `Z_T ≠ 0`, the
GLS binding mod r, the final equation.

## Soundness argument

### Identities

For chunk k over events `[a, b)`, with `S₀ := S_c(−X)`:

```
P_k(X) = S_k(X)^{2^{b−a}} · Π_{e∈[a,b)} ( L_e(X) · C_e(X) · G_e(X) )^{2^{b−1−e}}
D_k(X) = P_k(X)·S_{k+1}(−X) − P_k(−X)·S_{k+1}(X)
```

`L_e` is the product of the event's line polynomials (degree 9 each), `C_e = S_c(−X)` for
`d_e = +1`, `S_c(X)` for `d_e = −1`, 1 otherwise, and `G_e` is the product of the GLS factors
selected by bit `64−e`. The claim is `D_k ≡ 0 (mod M)`.

Terminal: `P_fin = S₃₃ · (4 Frobenius lines) · Rconst · S_c(ηX)`, `W = Fr₁(X)·Fr₁(ηX)`,
`D_fin = P_fin(X)W(−X) − P_fin(−X)W(X)`.

**Meaning.** `M` is even, so `σ: X ↦ −X` commutes with reduction mod M, and `D ≡ 0 (mod M)` iff
`P·σ(S')` lies in Fp6. `S'` is monic, hence nonzero. `P` is a product of nonzero field elements:
every line's `w⁰` coefficient is `y_P·(Fp2 scale)`, `y_P ≠ 0` because G1 has prime order (no
2-torsion), and the scale is `2YZ` or `λ'`, nonzero whenever the step's `Z₃ ≠ 0` (below);
representatives are monic. So `[P] = [S']` in G. A zero `P` would make `D_k ≡ 0` for every
`S_{k+1}` and free the next state, which is why the nonzero-line argument is required.

**Projective degeneracy.** Doubling has `Z₃ = 8Y³Z` and mixed addition `Z₃ = Z·λ'³`. So `Z = 0`
is absorbing for both, and the final `Z_T ≠ 0` implies every intermediate `Z ≠ 0`, every
`λ' ≠ 0` (no exceptional addition), and `Y ≠ 0` at every doubling (also implied by the odd
order `r(2p − r)` of `E'(Fp2)`). Hence every line scale is nonzero.

**Chain.** Composing the 34 relations gives `[f'] = [c]^λ` in G, with
`f' = Miller(−A, B) · Miller(C, δ) · m_{α,β} · m_{IC₀,γ} · Π_{k,i} Frob^i(m_{IC_{k+1},γ})^{e_{k,i}}`
(up to Fp2 line scalings, which are in Fp6). The loop contributes `c^{−(6x+2)}`, the terminal
supplies `c^{p²}` on the left and `c^p·c^{p³}` on the right.

### Residue

`[f'] = [c]^λ` means `f' = c^λ·s` with `s ∈ Fp6*`. Then
`f'^{(p¹²−1)/r} = c^{m(p¹²−1)} · s^{(p⁶−1)(p⁶+1)/r} = 1`, because `r | p⁴ − p² + 1 | p⁶ + 1`.
No cubic-residue selector or `w` witness is needed. Completeness: `gcd(λ, (p⁶+1)/r) = 1`
(equivalently `gcd(λ/r, (p⁶+1)/r) = 1` and `r ∤ (p⁶+1)/r`), so a root always exists; the prover takes
`c = 1 + conj(u^{λ⁻¹ mod (p⁶+1)/r})` with `u = f'^{p⁶−1}`.

### GLS binding

Frob is the p-power map on GT, so `FE(Frob^i(m)^e) = FE(m)^{e·p^i}`. With the exact check
`Σ_i e_{k,i}·π_i ≡ n_k (mod r)` (the on-chain `acc_k` is exactly `Σ_i e_{k,i}π_i` over the
integers, built from the same hashed nibbles and sign byte that select the factors),
`FE(f') = e(−A, B)·e(α, β)·e(IC₀ + n₀IC₁ + n₁IC₂, γ)·e(C, δ)`. So accept implies the Groth16
equation for the stated n. This holds also when vk_x = O; vk_x never appears as a point.

### B binding and G2 membership

The B walk starts at the proof's B and every step is the true group operation unless some
`Z = 0`, which is absorbing and rejected. So `T_final = [6x+2]B + ψ(B) − ψ²(B)`, and the endpoint
check gives `φ(B) = O` for `φ = (6x+2) + ψ − ψ² + ψ³`. Reducing with `ψ² − tψ + p = 0` gives
`φ = a + bψ` with `a ≢ 0 (mod p)` and `gcd(N(φ), 2p − r) = 1` (`facts.mjs`), so `φ` is injective
on the cofactor part of `E'(Fp2)` (order `r(2p − r)`) and `B ∈ G2`. A and C are in G1 because
G1 has cofactor 1.

### Schwartz–Zippel

Every `D_k` is fixed once h₀'s preimage is fixed (inputs hashed, lines and evaluations
deterministic, constants baked).
- **ρ step.** If some `D_k mod M ≠ 0`, then `Σ_k ρ^{K−1−k}(D_k mod M)` is a nonzero polynomial in
  ρ of degree ≤ 33: probability ≤ 33/p.
- **z step.** Otherwise `Σ ρ^{…}(D_k mod M) ≠ 0` with degree < 12, and the verifier checks
  `Σ ρ^{…} D_k(z) = Q(z)·M(z)` with Q fixed before z. The difference
  `Σ ρ^{…}D_k(X) − Q(X)M(X)` is nonzero (a nonzero polynomial of degree < 12 is not a multiple
  of M) and has degree ≤ max(deg D_k, 2·132 − 1 + 12) ≤ 275: probability ≤ 275/p.
- Degrees: chunk `[a, a+2)` gives `deg P_k = 4·6 + 2·f(a) + f(a+1)`, where `f(e) = 18 + 24·[d_e ≠ 0]
  + 6·#bits` is the event's factor degree (at most 90 with a NAF addition, 66 without). NAF
  digits are never adjacent. With the fixed boundaries, the nonzero digits at events 20, 26, 34,
  50 and 54 are the first (squared) event of their chunk, so the worst case (all 8 GLS bits set)
  is `deg P ≤ 24 + 2·90 + 66 = 270`. `D_k` is odd, so `deg D_k ≤ 275`, `deg Q ≤ 263`, which is
  132 odd words. `proto.mjs` prints this as `worst`. Fixture 0 has `max deg P = 216`, and Q has
  69–114 odd words on the 5 fixtures.
- Hash-to-field bias ≤ 1.134 (`facts.mjs`). Per random-oracle query:
  `ε ≤ 1.134·(33 + 275)/p ≈ 2^{−245.1}`; with `q_H` queries, `q_H·2^{−245}`.
- `M` is irreducible, so `M(z) ≠ 0`; `z = 0` is excluded explicitly.

## Required spec rules

These are the reviewer's issues, with the fixes a builder must implement from the start.
Their measured cost is included in the totals (about 0.3 kB in all).

1. **Injective transcript (major).** Hash only fixed-width encodings: NUM2BIN every number to
   32 B before CAT; SIZE-check every blob (192-B states and `s^c`, 65-B nibble strings, 1-B sign
   byte, 256-B Q blobs and a 128-B top blob); absorb each blob as its own hash-chain step.
   Variable-length script numbers concatenated without delimiters would let one preimage parse as many witnesses and
   void the Schwartz–Zippel bound. Keep TAG/VKDIGEST and the "rho"/"z" separators.
2. **Cap Q (minor).** At most 132 odd words: at most 16 blobs of 256 B plus an optional final
   blob that must be 128 B, enforced by the blob count and SIZE.
   The bound above uses this cap. The review asked for a cap `n_q ≤ N_MAX` without fixing a
   number; the measurement step implemented it as 128 words. That cap is below the honest worst
   case (132 words, see Degrees) and would reject an honest proof with probability about
   7·10⁻⁴: exceeding 128 words needs `deg P ≥ 263`, i.e. all 8 GLS bits set on a squared
   NAF-addition event and at least 7 of 8 on the following event (5 such chunks,
   `5 · (1/256) · (9/256)`). The worst-case liveness check in `total.mjs` uses 132 words.
3. **Projective formulas (minor).** Use exactly the formulas above. They make `Z = 0` absorbing
   and give a nonzero line whenever `Z₃ ≠ 0`; check `Z_T ≠ 0` at the endpoint. Any later
   "optimised" formula must keep both properties.
4. **Unsigned hash-to-field (minor).** `BIN2NUM(digest ‖ 0x00) mod p` for ρ and z; test
   `z ≠ 0` on the reduced value.
5. **GLS convention (minor).** The loop reads all 65 nibbles (bits 64..0, MSB first) of the
   same hashed strings that feed the binding; a set sign bit selects the conjugate factor
   (`X ↦ −X`) and a negative `π_i` term; keep `0 ≤ n_k < r` and the exact binding mod r.
6. **η and Frobenius constants (minor).** Assert at build time that `Frob²(f) = f(ηX)` mod M
   for the baked η and that `R_{k,2}, R_{k,3}` equal the reps of `Frob²(m), Frob³(m)`
   (`checks.mjs` does the first; it finds exactly one valid η).
7. **Sign-safe comparisons** (added in the design-record review; from commit-all review issue 3). Every equality and nonzero test is done on `(a − b) mod p`
   (BCH MOD keeps the dividend's sign); the binding uses `((acc mod r) + r) mod r`.

State and Q words need no range checks: each is hashed into ρ or z, so altering one changes
the challenges; non-canonical encodings only buy extra oracle queries, which `q_H` covers.

## Cost model and measured kernels

All kernels were assembled by a DAG scheduler (`dsl.mjs`, local search over instruction
orders) or a symbolic-stack assembler (`asm.mjs`), executed in the libauth bch-spec VM
(standard mode), with every output checked against a BigInt simulation and the simulation
checked against noble. The bch-spec op cost is 100 per instruction + pushed bytes + arithmetic
(`MUL`/`MOD`: `lenA·lenB + 2·len(result)`).

| Kernel | op | bytes | times used |
|---|---:|---:|---:|
| B projective doubling + line at ±z + F± squaring | 142,079 | 424 | 65 |
| B projective mixed addition (±B) + line + `S_c(∓z)` multiply | 184,514 | 562 | 21 |
| B projective mixed addition (ψ(B), −ψ²(B)), no c-multiply | 178,376 | 568 | 2 |
| δ step, baked λ, on-chain x, c (doubling; additions 46,420) | 46,390 | 157 | 86 |
| δ line from 4 baked words (Frobenius lines) | 18,757 | 46 | 2 |
| GT-GLS loop, 65 events (two 16-entry tables at ±z, nibble lookup, binding Horner) | 1,403,639 | 82 per event | 1 |
| GLS table build (16 entries, one sign, one group) | 48,546 | 111 | 4 |
| monic degree-6 evaluation at ±x from 6 constants | 15,782 | 46 | 11 |
| GLS signed π + TB table + binding check (one group) | 18,288 | 154 | 2 |
| state boundary: `S'(±z)` + residual + ρ-fold | 24,147 | 69 | 33 |
| state blob absorb (SIZE == 192 + hash-chain step) | 2,126 | 12 | 34 |
| parse a 192-B blob into 6 numbers | 3,437 | 31 | 34 |
| Q word: blob SIZE + absorb + split + BIN2NUM + Horner (8-word blobs) | 3,518 per word | 90 | ≤ 132 |
| challenge: `SHA256(h ‖ tag) ‖ 0x00 → BIN2NUM → mod p` | 2,481 | 14 | 2 |
| terminal `Frob(S_c)` at ±x (folded constants) | 56,458 | 129 | 2 |
| Fp2 × constant (ψ maps, endpoint) | 12,248 | 29 | 6 |
| *alternatives not used* | | | |
| B affine doubling, witnessed slope | 83,514 | 238 | 0 |
| B affine addition + c-multiply, witnessed slope | 79,357 | 237 | 0 |
| projective doubling + line, no square (δ projective tail) | 134,691 | 417 | 0 |

The B kernels sit at the arithmetic floor: MUL+MOD is ~70% of their op (43 MUL / 20 MOD per
doubling); Karatsuba and schoolbook variants are within ±0.5%, and the scheduler gains 1–3% over
a well-ordered DAG. The GLS loop is data-independent (21,594 op per event): grouping the 8
factors into two 16-entry tables replaced up to 520 conditional multiplications (2.48M average,
4.53M worst in the design model).

### Revised totals

Measured as **per-kernel VM measurements plus a glue model** (`total.mjs`): each kernel's op ×
times used, summed, ×1.05 for invocation and stack rearrangement; code bytes from the measured
kernels plus a 25% layout allowance; setup op (0.25M) and setup/terminal (900 B) and
event-function/schedule (500 B) bytes are estimates. The witness shape (33 states, 105 → 108 Q
words on fixture 0) comes from `proto.mjs`; `QWORDS=114` gives fixture 4 (116 words, 15 blobs,
3,759 B), the largest quotient of the 5 fixtures. Push overhead: 194 B per 192-B blob, 66 B per
65-B nibble string, 3 B per 256-B Q blob (the 128-B top blob is also counted at 3 B, 1 B
conservative), +2 B explicit blob count.

| Bytes | |
|---|---:|
| states (33 × 194) | 6,402 |
| δ data (86 baked λ pairs, 2 Frobenius 4-word lines, start x₀, c₀) | 6,072 |
| quotient (108 words; fixture 4: 116 words, 3,759) | 3,500 |
| VK constants | 2,145 |
| kernel code + layout allowance | 1,974 + 494 |
| setup/terminal code; event function/schedule (estimates) | 900 + 500 |
| proof and inputs; residue root; GLS witness; tx | 330 + 194 + 134 + 66 |
| **total** (fixture 0; fixture 4: 22,970) | **22,711** |

| Op | M |
|---|---:|
| B walk and lines | 13.47 |
| δ | 4.05 |
| GLS | 1.78 |
| states | 1.00 |
| quotient | 0.38 |
| residue root | 0.04 |
| terminal | 0.28 |
| setup (estimate) | 0.26 |
| **total (×1.05 glue)** | **22.32** |

| Configuration | score | op / budget | worst witness |
|---|---:|---:|---:|
| **B projective, δ baked λ (headline)** | **22,711** | 22.32M / 26.12M | 83.8% |
| same, fixture 4 (116 Q words) | 22,970 | 22.35M / 26.33M | 83.8% |
| same, 10% / 15% glue | 22,711 | 23.38M / 24.45M | 87.8% / 91.8% |
| B projective, last 24 δ steps tracked projectively | 21,279 | 24.92M / 24.97M | 97.7% (not recommended) |
| B affine, witnessed slopes | 27,892 | 15.90M / 30.26M | 51.8% |

Rows other than the fixture-4 row use the fixture-0 witness shape.

"Worst witness" is the op of a witness with Q at the 132-word cap (22.41M against a 26.74M
budget for the headline), as a fraction of its own budget.

Against the design-phase model (25.9 kB with naive kernels, 23.2 kB at an assumed 20%
hand-scheduling gain): the B kernels came in above target (142k/185k against 120k/150k) but the
GLS fold, the kernel code (p picked instead of pushed inline) and the δ step came in below.

## Reproduce

From the repository root:

```sh
node research/sound-sz-bn254/facts.mjs
cd research/sound-sz-bn254/single-identity/prototypes
for f in 0 1 2 3 4; do node proto.mjs --gls --rep=6 --chunks=2 --fix=$f; done
node proto.mjs --gls --rep=6 --chunks=2 --fix=0 --json   # writes proto-gls-rep6-2-f0.json
node checks.mjs
node kernels.mjs 20000      # writes kernels.json (~7 s)
node gls.mjs                # writes gls.json
node transcript.mjs         # writes transcript.json
GLUE=1.05 node total.mjs    # also GLUE=1.1, GLUE=1.15
QWORDS=114 node total.mjs   # fixture-4 quotient (default: fixture 0, 105 words)
```

`proto.mjs` is the executable protocol reference: honest prover and a value-level verifier
that runs the `±z` chains as the script would. It asserts the Groth16 equation, the torus
residue, exact divisibility of every identity by M, the batched check, and that a perturbed
state is rejected. It also prints `worst`: the worst-case `deg P`, `deg D` and Q word count over
all witnesses for the chosen boundaries (270, 275, 132 for `--chunks=2`), which sets the Q cap.
Without `--gls` it runs the 3-pair base variant (reused MSM, γ lines).
`total.mjs` reads the four JSON files, which are committed so it runs on its own. The
`--json`, `kernels.mjs`, `gls.mjs` and `transcript.mjs` commands above regenerate them
byte-identically.

| File | Role |
|---|---|
| `proto.mjs` | protocol reference: GLS decomposition, states, quotient, transcript, verifier, negative control |
| `dsl.mjs` | kernel DAG, op-cost simulator, local-search scheduler, VM runner |
| `asm.mjs` | symbolic-stack assembler for table lookups and blob handling |
| `kernels.mjs` | B, δ, state and Horner kernels; asserts point/line results against noble and the projective-line identity |
| `gls.mjs` | GT-GLS loop, tables, factor evaluation, binding check |
| `transcript.mjs` | state/Q absorb and parse, challenges, `Frob(S_c)`, Fp2 × constant |
| `checks.mjs` | η and Frobenius shortcut assertions |
| `total.mjs` | totals, δ-mix and B-mode search, liveness check; knobs `GLUE` (op glue factor) and `QWORDS` (honest Q odd words) |

## Open risks

- **Not built.** Glue, stack layout and loop control are modelled (5% op glue, 25% code
  allowance), not measured; setup op and setup/terminal bytes are estimates. The score is
  byte-bound, so op error only matters for liveness (16% headroom).
- **GLS tables are not wired into `proto.mjs`,** which multiplies per set bit. The tables change
  only evaluation order, not the identity, but the reference should be updated before building.
- **Transcript in the reference.** `proto.mjs` hashes one flat preimage of 32-byte big-endian
  words (sub-scalars as `e mod p`). That is injective and fine for testing the identities, but
  it is not the on-chain hash chain above, which the measured kernels in `transcript.mjs` follow.
  A builder's witness generator must implement the on-chain form.
- **Projective lines in the prover.** `proto.mjs` uses affine lines. The states are the same
  (same classes) but Q differs; the prover must reproduce the exact projective line polynomials.
  The Q word count should hold (same degree 9 per line).
- **Statement encoding.** Public inputs are bound through `e_{k,i}` and the congruence mod r, not
  through vk_x. Sound, but the benchmark owner has to accept it; otherwise msm-single is a
  drop-in fallback at about +11.5 to +15 kB (~34–37.5 kB; design model at OPT 0.8–1.0, not
  re-measured).
- **Completeness corners (negligible).** The monic degree-6 map misses a set of classes of
  density ~1/p (see Notation), so an honest state lacks a representative with probability
  ~1/p. The class [1] is representable (for example by `X⁶`).
- **Stack depth.** About 400 witness items plus the working set; the redeem is ~15 kB, inside the
  100,000-byte caps.

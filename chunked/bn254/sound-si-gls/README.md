# BN254 Groth16, SI-GLS: one batched torus identity, sound by construction (one input, bch-spec)

A full Groth16 verifier for the fixed BN254 VK of the densless fixtures (`../densless-recovered/public-fixtures.json`)
with public inputs `n0, n1`, in ONE P2SH32 input on the proposed bch-spec VM (100,000-byte scripts, per-input
op-cost budget `(10,000 + unlocking length) * 800`). Bench entry id: `bch-groth16-sound-si-gls-single`.

The design is the spike's SI-GLS ("single batched torus identity at ±z, GT-GLS folding of e(vk_x, γ)"). It closes
the soundness gaps of the densless entries (issue #28: fixed-table and checkpoint evaluations supplied by the prover).
The densless author has since withdrawn those entries' soundness claims ([#28 reply](https://github.com/mr-zwets/groth16_cashscript/issues/28),
[#32 F6](https://github.com/mr-zwets/groth16_cashscript/issues/32): unconstrained Miller slopes, a terminal that compares
a value with itself instead of checking the B endpoint, and, at the #22 / bench#42 head, line/root values not bound to the
committed state), so this is
the sound BN254 alternative, not a hedge. It is the smallest non-withdrawn BN254 entry in the bch-spec category.
**Every accept-relevant value is either computed on-chain, a baked VK constant, hash-committed before the challenge
it meets, or checked by an exact field or integer equation.** No prover-supplied evaluation is used anywhere.

## Results (fixture 0, harness `pnpm benchmark:json`)

| | |
|---|---|
| **score** (scripts + tx overhead) | **21,915** = 21,852 + 63 |
| locking (P2SH32) | 35 |
| unlocking | 21,817 = redeem 11,185 + WS 6,981 + WQ 3,651 (push headers included) |
| redeem 11,182 | δ-slope pile 5,665 · 42 field constants 1,386 · other data 74 · code 4,057 |
| WS 6,978 | statement 320 · GT-GLS nibbles 130 · residue root 192 · 33 states 6,336 |
| WQ 3,648 | 114 odd quotient words (60–132 depending on the statement) |
| op-cost | 23,336,981 consensus / 23,381,269 standard of 25,453,600 (91.7% / 91.9%) |
| worst-case proof (fixture 4) | 23,348,039 (accepted) |
| liveness sweep | 423 cases, all accepted in both modes; builder's minimum 1,422,175 standard at the every-nibble-1 witness. The independent review found a worse honest witness: **min margin 1,203,221 standard / 1,244,437 consensus (95.0% of budget)**, see Open risks |

Gates: valid accepted, 15/15 invalid vectors rejected, 4/4 proofs runtime-general, standard (relayable), public
inputs bound (9/9 mutated claims rejected), maintainer red-team 90/90 rejected.

Op-cost profile (fixture 0, standard, `node profile.mjs`): B doubling 9.31M (65 × 143k), B mixed additions 4.26M
(23 × 185k), δ steps 4.31M (88 × 49k), GT-GLS 1.32M, state boundaries 1.54M, quotient 0.74M, setup and terminal ~1.9M.

## Protocol

Notation: Fp12 = Fp[X]/M(X), M = X^12 − 18X^6 + 82, X = w (noble tower: u² = −1, v = w², v³ = 9+u), u = X^6 − 9, and
Φ(a0 + a1u) = (a0 − 9a1) + a1X^6. Conjugation σ = Frob^6 is X ↦ −X; Frob² is X ↦ ηX for one baked primitive 6th root η.
G = Fp12*/Fp6* has order p^6+1; a class is represented by a monic degree-6 polynomial S = X^6 + Σ_{j<6} s_j X^j.
λ = 6x+2+p−p²+p³ = m·r; d_0..d_64 is the NAF of 6x+2 (65 events, 21 additions).

**Witness** (unlocking `<WQ> <WS> <redeem>`, exactly two items besides the redeem):

- `WS` (exactly 6,978 B), fixed-width 32-byte little-endian words:
  - `[0,320)`: x_A, y_A, x_B.c0, x_B.c1, y_B.c0, y_B.c1, x_C, y_C, n0 (offset 256), n1 (offset 288);
  - `[320,450)`: two 65-byte nibble strings N_0, N_1. Byte e of N_k holds bit 64−e of u_{k,0..3}, where u_{k,i} = e_{k,i} + 2^64 ∈ [0, 2^65);
  - `[450,642)`: s^c, the monic representative of the residue root c;
  - `[642,6978)`: the states S_1..S_33 (6 words each), after events 2, 4, …, 64, 65.
- `WQ` (32·n_q bytes, 1 ≤ n_q ≤ 132): the odd coefficients q_{n_q−1} … q_0 of the aggregated quotient (highest first; q_j is the coefficient of X^{2j+1}).

**Transcript**: h0 = SHA256("SIGLS/1" ‖ WS); ρ_raw = SHA256(h0 ‖ "rho"); z_raw = SHA256(h0 ‖ ρ_raw ‖ WQ);
ρ = BIN2NUM(ρ_raw ‖ 0x00) mod p, z = BIN2NUM(z_raw ‖ 0x00) mod p, and z ≠ 0.

**Pairs**: P0 = −A with Q0 = B (runtime, projective), and P1 = C with Q1 = δ (fixed). The δ chain uses 88 baked
slopes: the script tracks x_j and c_j = λ_j x_j − y_j on-chain, with c_j = (λ_{j−1} + λ_j)x_j − c_{j−1}.
e(vk_x, γ) is folded in by GT-GLS: e(vk_x,γ) = e(IC0,γ)·Π_k e(IC_{k+1},γ)^{n_k}, with n_k ≡ Σ_i e_{k,i} p^i (mod r) and Frob^i acting as ^p^i on GT.

**On-chain steps** (`script.mjs`):

1. Pin the layout and derive the challenges:
   - DEPTH == 2; SIZE(WS) == 6978; SIZE(WQ) ≡ 0 (mod 32) and 32 ≤ SIZE(WQ) ≤ 32·132; the leading WQ word ≠ 0;
   - compute h0, ρ and z as above.
2. Parse and range-check every word, unsigned (`RD`: BIN2NUM(w ‖ 0x00) < p; n_k < r):
   - nibble strings & 0x0f…0f == themselves;
   - curve checks y_A² = x_A³+3, y_C² = x_C³+3, y_B² = x_B³+b′.
3. Precompute:
   - z^2..z^6 and (ηz)^1..^6;
   - γ1^j (from the one baked γ1 = ξ^((p−1)/6)), and c_j = Φ(γ1^j)(z);
   - π_i = p^i mod r, derived from p and r;
   - the GT-GLS tables: TP_k[n] = Π_{i∈n} R_{k,i}(z), TM_k at −z, and TB[n] = Σ_{i∈n} π_i (exact integers). Here R_{k,0}, R_{k,1} are baked monic representatives of m_{IC_{k+1},γ} and Frob(m_{IC_{k+1},γ}), and R_{k,2/3}(X) = R_{k,0/1}(ηX).
4. 65 events, F± starting at S_c(∓z). Each event:
   1. F± ← F±² · L_B(±z), where L_B is the projective doubling line;
   2. the δ step;
   3. if d_e ≠ 0: the B mixed addition with ±B, times S_c(∓z) or S_c(±z); then the δ step;
   4. F± ← F±·TP_0/TM_0[N_0[e]]·TP_1/TM_1[N_1[e]], and acc_k ← 2acc_k + TB[N_k[e]];
   5. at a boundary: R ← Rρ + F+·S′(−z) − F−·S′(z), then F± ← S′(±z).
5. Terminal:
   - B += ψ(B) and B += −ψ²(B), with their lines; the two δ Frobenius lines;
   - F± ·= Rconst(±z)·S_c(±ηz), where Rconst also carries the GLS offset correction Π Frob^i(m_{IC_{k+1}})^(−2^64);
   - R ← Rρ + F+·W(−z) − F−·W(z), with W(x) = Fr1(x)·Fr1(ηx) and Fr1 = Frob(S_c) computed from s^c;
   - endpoint (X:Y:Z) == −ψ³(B), and Z ≠ 0;
   - binding (acc_k − 2^64Σπ_i − n_k) mod r == 0.
6. Accept iff R ≡ z·q(z²)·M(z) (mod p). Then clean stack.

## Spec rules (every reviewer issue implemented from the start)

| rule | implementation |
|---|---|
| injective, fixed-width transcript (major) | WS is one push of exactly 6,978 bytes of fixed-width fields. WQ is a whole number of 32-byte words and is the last field of z's preimage. h0, ρ_raw and z_raw have distinct, fixed-prefix preimages with a tag and a "rho" separator. Each byte string therefore parses in exactly one way. |
| enforced cap on n_q (degree bound) | 32 ≤ SIZE(WQ) ≤ 32·132 and ≡ 0 (mod 32). NQ_MAX = 132 is derived in `build.mjs` from the NAF schedule and the chunking (asserted). Additions that are the first event of their chunk (events 20, 26, 34, 50, 54) give max deg P = 270, deg D ≤ 275, deg Q ≤ 263. The leading word must be nonzero, so n_q is canonical. This guard decodes the word with signed BIN2NUM; it is equivalent to an unsigned test only because the Horner loop then enforces q < p on the same word (a signed zero is 0 or 2^255, and 2^255 ≥ p is rejected there). |
| unsigned SHA→Fp | ρ, z = BIN2NUM(digest ‖ 0x00) mod p ∈ [0, p); z ≠ 0 is tested on the reduced value. |
| canonical unsigned decoding | Every field word (coordinates, s^c, states, Q) is decoded as BIN2NUM(w ‖ 0x00), so the byte↔value map is bijective on [0, 2^256), and < p is enforced. n_k < r is enforced. Nibbles must be ≤ 0x0f. |
| reduced values before guards | Every equality or ≠0 guard tests `(a − b) mod p` or `x mod p` (exact for any sign under BCH MOD): curve checks, endpoint, Z_T ≠ 0 (Z0 mod p ∨ Z1 mod p), binding mod r, final identity. z ≠ 0 is tested on z ∈ [0, p). |
| exact push sizes / layout pinned | DEPTH == 2 at entry, exact SIZE(WS), WQ size rules, consensus clean stack (exactly one item), push-only unlocking. |
| nonzero line factors | B lines are (2YZ, −3X², Y² − 3b′Z²) for doubling and (λ′, −θ, θx_q − λ′y_q) for addition, both Fp2 multiples of the affine line. Z = 0 is absorbing (Z3 = 8Y³Z, and Z·λ′³), and Z_T ≠ 0 is checked, so every intermediate Z, H = 2YZ and λ′ is nonzero. Then ℓ0 ≠ 0 and y_P ≠ 0 (G1 has odd order), so each line polynomial is a nonzero polynomial of degree < 12. δ lines have ℓ0 = 1. All other factors are monic. |
| GLS bits from the hashed, range-checked e_{k,i} | The only GLS witness is the two hashed 65-byte nibble strings, and the same bytes drive both the factor lookups and the exact binding. u = e + 2^64 is unsigned (65 bits, canonical; there is no sign byte and no −0), and the constant offset is folded into Rconst and the binding. |
| baked constants verified against noble | `math.mjs` asserts the following against noble every time it loads (build, prover, tests): η (Frob² = X ↦ ηX, Frob^6 = X ↦ −X); γ1 and its derived Φ(γ1^j) = Frobenius coefficients and ψ = (γ1², γ1³); π_i; R_{k,2/3} via ηX; every δ slope and the on-chain δ recursion against noble's point arithmetic; and the G2 facts. |

## Soundness argument

**Identities.** For chunk k (events [a, b)):

  P_k(X) = S_k(X)^{2^{b−a}} · Π_{e∈[a,b)} ( L_{B,e} · L_{δ,e} · [L′_{B,e} L′_{δ,e} C_e if d_e ≠ 0] · G_{0,e} G_{1,e} )^{2^{b−1−e}}

The factors are:
- L are the line polynomials y_PΦ(ℓ0) + x_P XΦ(ℓ1) + X³Φ(ℓ3), with ℓ computed on-chain (B) or baked (δ);
- C_e = S_c(−X) for d_e = +1 and S_c(X) for d_e = −1;
- G_{k,e} = Π_{i∈N_k[e]} R_{k,i}(X);
- S_0 = S_c(−X).

Then D_k = P_k(X)S_{k+1}(−X) − P_k(−X)S_{k+1}(X), for k = 0..32, and the terminal identity is:
- P_fin = S_33 · (2 B lines) · (2 δ lines) · Rconst · S_c(ηX);
- W = Fr1(X)·Fr1(ηX);
- D_33 = P_fin(X)W(−X) − P_fin(−X)W(X).

M is even, so σ commutes with reduction. Hence D ≡ 0 (mod M) ⟺ P·σ(S′) is even ⟺ P·σ(S′) ∈ Fp6. With P ≠ 0 (a product of nonzero factors, see the line rule) and S′ monic, this gives [P] = [S′] in G. Chaining the 34 relations gives [f′·c^{−(6x+2)}·c^{p²}] = [c^{p+p³}], i.e. [f′] = [c]^λ, where

  f′ = Miller(−A,B)·Miller(C,δ)·m_αβ·m_{IC0,γ}·Π_{k,i} Frob^i(m_{IC_{k+1},γ})^{e_{k,i}}.

**Residue.** [f′] = [c]^λ ⇒ f′^{p^6−1} = c^{(p^6−1)λ} ⇒ FE(f′) = c^{(p^12−1)m} = 1. No 27th-root witness is needed (3 ∤ p^6+1). gcd(λ, (p^6+1)/r) = 1 (asserted), so honest roots always exist, via c = 1 + conj(u^{λ^{−1}}).

**GT-GLS binding.** The script checks Σ_i u_{k,i}π_i − 2^64Σπ_i ≡ n_k (mod r) exactly over the integers, with u read from the same hashed nibbles that select the factors. FE(Frob^i(m)) = FE(m)^{p^i}, and p^i ≡ π_i on μ_r. Hence the GLS part of FE(f′) is e(IC0,γ)·Π_k e(IC_{k+1},γ)^{n_k} = e(vk_x,γ) for the on-chain-bound n_k ∈ [0, r). Together with the residue, FE(f′) = 1 is exactly the Groth16 equation e(A,B) = e(α,β)e(vk_x,γ)e(C,δ). A and C are in G1 (on the curve, cofactor 1).

**B binding.** The B trajectory is computed on-chain from the curve-checked B (no witness). Exceptional steps force Z = 0 (absorbing), which Z_T ≠ 0 rejects, so every step is a correct group operation. The endpoint check gives λ(ψ)(B) = (6x+2)B + ψ(B) − ψ²(B) + ψ³(B) = O. On E′(Fp2), of order r(2p−r) with 2p−r odd, λ(ψ) = a + bψ, and gcd(N(a+bψ), 2p−r) = 1 (asserted in `math.mjs`), so B ∈ G2.

**Batching and degrees (adversarial).** All D_k are fixed polynomials, determined by h0's preimage (WS) and deterministic on-chain computation, before ρ. If some D_k mod M ≠ 0, the combination Σρ^{33−k}(D_k mod M) vanishes with probability ≤ 33/p. Otherwise S(X) := Σρ^{33−k}(D_k mod M) is a nonzero polynomial of degree < 12, and the verifier checks S(z) = (Q − Q*)(z)·M(z), where Q* is the true aggregated quotient and Q is hashed before z. S − (Q − Q*)M ≠ 0, because M does not divide a nonzero polynomial of degree < 12. Its degree is ≤ max(deg D_k, 2·NQ_MAX − 1 + 12) = max(275, 275) = 275, for every witness the script accepts. (The worst case is all nibbles 15 in a chunk whose first event is an addition: deg P = 24 + 2·90 + 66 = 270.)

**Soundness error** per random-oracle query: ε ≤ 1.134·(33 + 275)/p ≈ **2^−245.15** (1.134 is the SHA256 → Fp bias, ⌈2^256/p⌉/(2^256/p)). With q_H hash queries: q_H·2^−245.

**Completeness.** Honest provers fail only if a monic representative does not exist (probability ~1/p per state) or the leading quotient word is zero after trimming (probability ~1/p, handled by trimming). Babai rounding gives |e_{k,i}| < 2^64 (column-sum bound, asserted), so u always fits in 65 bits. Random statements reach n_q = 132 (seen in the sweep, about 1 in 20,000), which is exactly the cap.

## Deviations from the spike design (and why)

- **GT-GLS sign handling.** The design used signed e with sign bits. This uses unsigned u = e + 2^64, with the constant correction in Rconst and the binding. The encoding is canonical by construction (no −0, no sign bytes or sign logic). The mean n_q is the same (107.9 vs 108.2 words over random statements). Fixture 0 specifically pays 9 words more (114 vs 105, about 290 B), because event 0 carries bit 64 for nonnegative e.
- **Tables.** The GLS fold uses the grouped tables of the measurement (TP/TM per group). There is one shared TB table, since π is now unsigned.
- **δ chain.** Each step reads λ_j (state (x_j, c_{j−1}, λ_{j−1}), start (x_δ, y_δ, 0)), so all 88 lines, including both Frobenius lines, run through one δ step function. There is no baked 4-word line. The 88 slopes sit in a pile of eleven 512-byte pushes at the bottom of the stack.
- **Baked constants.** Only γ1 and η are baked for Frobenius and ψ. The design baked the 10 Frobenius coefficients and the ψ/ψ²/ψ³ constants. 3b′, π_i, η² = η − 1 and x_ψ(δ) are derived on-chain. All derivations are asserted against noble.
- **Range checks on states and Q.** These are kept (the measurement had dropped them), per the canonical-decoding rule.
- **Quotient cap is 132, not 128.** This follows the corrected degree bound: the design put every addition on the second event of a chunk.
- **Chunking.** Uniform 2-event chunks. Option (b), moving each addition to the second event, needs 36 states (+576 B) to save ~8 Q words (−256 B), and is worse. Among cap-greedy partitions the uniform one is optimal.
- **Compiler.** No cashc: a small symbolic-stack assembler with a scheduling kernel compiler (`asm.mjs`). See below.

## Compiler and tooling

- `asm.mjs`: named-item stack assembler for bch-spec.
  - Depths are computed from names; structured IF/ELSE and loops (OP_BEGIN/OP_UNTIL) with asserted layouts; the altstack; and "piles" (runs of items consumed from the top).
  - Functions (OP_DEFINE/OP_INVOKE) come in two kinds. Local functions see only their inputs. Bound functions require the same position for every item their body touches at every call site.
  - Arithmetic kernels are DAGs scheduled by local search on the exact bch-spec op-cost model (100 per instruction + pushed bytes + operand-length products).
- `script.mjs`: the program.
  - The loop's stack layout is the computed fixed point of one event, so the 65-event loop needs no re-arrangement.
  - The GLS/digit group, the state stream, R and WQ live on the altstack between uses.
- `math.mjs`: constants and their noble assertions. `protocol.mjs`: layout, transcript, the honest prover (exact on-chain polynomials, divisibility asserted), its forge mode for red-team witnesses, and a value-level mirror verifier.
- `build.mjs`: deterministic build (twice, byte-compared), the degree bound and cap from the schedule, and a smoke spend. `export.mjs`: bench vectors. `redteam.mjs`: the rejection suite and the bench red-team file. `sweep.mjs`: liveness. `mint.mjs`: proofs under the fixture VK from the bench trapdoor (checked against the VK). `profile.mjs`: op cost by section. `breakdown.mjs`: redeem byte breakdown.

## Reproduce

```sh
# in this directory, with the repository's dependencies (@noble/curves 2.2.0, @bitauth/libauth 3.1.0-next.8)
node build.mjs                                     # redeem 11,182 B, sha256 242c3ce7…8b5d; writes redeem.hex, build.json
node export.mjs vectors.json                       # sha256 9327f938…e64c
node redteam.mjs vectors.json redteam.json redteam-report.json   # 90 runs rejected; redteam.json sha256 2b78a0ef…8b47
VERIFIER_DIR=<zk-verifier-bench> SWEEP_N=400 SWEEP_SPARSE=8 node sweep.mjs sweep.json   # SWEEP_SHARD=k/n to split
```

In zk-verifier-bench: copy `vectors.json` to `src/bch/groth16-sound-si-gls-single-vectors.json` and `redteam.json` to
`src/bch/redteam/bch-groth16-sound-si-gls-single.json`. Then run `pnpm benchmark sound-si-gls` (gates) and
`pnpm benchmark:json` (score).

## Verification

- **Red team** (`redteam.mjs`, 90 runs, all rejected in consensus and standard mode; `redteam-report.json` names the guard that fires). Positive controls: fixture 0, and a lattice-shifted (non-Babai, valid) GLS witness. The runs:
  - forged statements with adaptively rebuilt witnesses (n ± 1, swapped, foreign proof): a fresh transcript, states, residue root and floor quotients, rejected by the final identity;
  - n + r and top-bit encodings;
  - off-curve and identity points, +p coordinate aliases, −A/−B/−C;
  - B off G2: a random cofactor point, and a point of order 10069 (Z = 0 absorbing), rejected at the endpoint;
  - transcript re-parses across field boundaries;
  - state and residue tampering and aliases;
  - quotient word tampering, aliases, a leading zero word, length, the 133-word cap, and an empty or zero quotient;
  - a prover using a signed SHA→Fp for ρ;
  - nibble range, 0x80 and bit flips;
  - lattice-shifted digits with stale identities, and binding off by one;
  - layout: extra, missing and reordered pushes, wrong sizes, a non-push opcode, a non-minimal push, a tampered redeem.
- **Liveness** (`sweep.json`, 423 cases, all accepted in both modes): the 5 fixtures; special inputs (0, 1, r−1, 2^64, …); the maximum-degree witness (every nibble 15, n_q 132, op 23.56M); the minimum-degree witness (every nibble 0, n_q 60); the liveness extreme (every nibble 1: full lookup cost at n_q 78, the smallest margin, 1,422,175 standard); the 8 lowest-n_q statements of a 20k search; the lattice-shifted witness; 400 random proofs (n_q 93–132, minimum margin 1,707,286 standard).

## Open risks

- **Formula correctness is tested, not machine-proved.** The soundness proof assumes the script computes the stated polynomials: the projective B formulas, the line slots and the ±z evaluations. This is checked by the exact divisibility of every honest identity in the prover, by 423 accepted proofs, and by noble cross-checks of the δ recursion and constants. There is no formal equivalence proof of the generated bytecode.
- **The op margin is about 5% at the worst known witness** (6.9% for random proofs). The independent review's worst case zeroes the nibbles at the 5 addition-first events (20, 26, 34, 50, 54), which drops n_q to 66, while keeping the other 120 lookups at full cost (nibble 4): op 23,021,579 standard against a budget of 24,224,800, margin 1,203,221 (4.97%). The every-nibble-1 "liveness extreme" in `sweep.mjs` (n_q 78, margin 1,422,175) is not the worst case. The op cost is almost statement-independent, and the budget shrinks with n_q. Any later change that adds op cost must be re-swept at the n_q-66 witness.
- **GLS encoding cost on fixture 0.** Fixture 0 pays about 290 B for the unsigned encoding versus signed digits, while the random-statement mean is equal. A signed variant would need a canonical "no −0" rule, at about 100 B of code.
- **Public inputs bind through the GT-GLS fold**, via hashed sub-scalars and an exact mod-r check, rather than an explicit vk_x MSM. The benchmark owner should confirm this is acceptable; the bench public-input gate passes (9/9).

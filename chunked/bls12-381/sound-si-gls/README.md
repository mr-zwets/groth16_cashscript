# BLS12-381 Groth16, SI-GLS: one batched torus identity, sound by construction (one input, bch-spec)

A full Groth16 verifier for the fixed BLS12-381 VK of the bench's BLS12-381 fixtures (α = 3·G1, β = 5·G2, γ = 7·G2,
δ = 11·G2, IC = (2, 4, 6)·G1; `singleton/bls12-381/bls_instance.mjs`) with public inputs `n0, n1`, in ONE P2SH32 input
on the proposed bch-spec VM (100,000-byte scripts, per-input op-cost budget `(10,000 + unlocking length) * 800`).
Bench entry id: `bch-groth16-bls12381-sound-si-gls-single`. Review status: **unreviewed** (awaiting the owner review).

This is the BLS12-381 port of the reviewed BN254 SI-GLS verifier (`../../bn254/sound-si-gls`). It follows the
chosen design (`work/bls-si-gls-spec-DESIGN.md`: design 1 of `research/sound-sz-bls12381/si-gls-spec`, with four items
merged from design 2, `research/sound-si-gls-bls12381-d2`). **Every accept-relevant value is either computed on-chain,
a baked VK constant (asserted against noble at build), hash-committed before the challenge it meets, or fixed by an
exact field or integer equation.** No prover-supplied evaluation is used anywhere.

## Results (fixture `committed`, E_A = 10)

| | |
|---|---|
| **score** (scripts + tx overhead) | **26,484** = 35 locking + 26,386 unlocking + 63 |
| unlocking | 26,386 = redeem 12,793 + WS 11,328 + WQ 2,256 (47 words) + push headers 9 |
| redeem 12,793 | δ-slope pile 6,579 · 37 field constants + p 1,813 · other data 192 · code 4,209 |
| WS 11,328 | statement 384 · n0, n1 64 · GLS nibbles 128 · residue root 288 · 32 states 9,216 · 13 affine B slopes 1,248 |
| op cost (`committed`) | 26,070,993 consensus / 26,124,497 standard of 29,108,800 (89.6% / 89.7%) |
| worst forced liveness witness | n_q 53, 119 nonzero GLS nibbles (59 bytes with both nibbles nonzero), the worst of 41 proofs: 27,538,312 standard of 29,339,200, **margin 1,800,888 (6.14%)**; consensus margin 1,854,904 (6.32%) |
| liveness sweep | 279 cases (6 fixtures, 18 forced extremes, 40 proof samples of the n_q 53 extreme, special and low-n_q statements, a non-canonical-digit witness, 200 random proofs), all accepted in both modes; minimum margin = the forced witness above |
| soundness error | ε ≤ 279 / 2^256 ≈ **2^−247.9** per random-oracle query (degree bound 247, 33 batched identities) |

Gates (exact-id driver, `scripts/bench-ids.mts` in the task folder): valid accepted, 16/16 invalid vectors rejected, 6/6 proofs
runtime-general, worst-case proof accepted (27,484,296 consensus), standard (relayable), public inputs bound (9/9 mutated
claims rejected), rejection suite 87/87 rejected (bench red-team gate: 0 accepted), secure packaging.

Other fixtures (score, n_q, standard op % of budget): proof1 26,868 (55, 89.0%), dense 28,500 (89, 91.0%), zero 26,436
(46, 89.5%), max 27,732 (73, 89.1%), msm-identity 28,020 (79, 87.7%). The score depends on the statement only through
n_q (48 B per word; 46 ≤ n_q ≤ 118). 200 random statements: n_q 83..109, minimum standard margin 8.81%.

Op-cost profile (`committed`, standard, `UNLIMITED=1 node --stack-size=60000 profile.mjs`): B projective doublings
12.38M (53 × 234k), δ steps 5.20M (68 × 76k), B affine doublings 1.48M (10 × 148k), additions (B and δ) 1.68M,
GT-GLS lookups 0.91M (2.2M at the forced worst witness), state boundaries 1.88M (32 × 59k), quotient 0.42M, set-up,
tables and terminal ~2.2M.

## Protocol

Notation: Fp12 = Fp[X]/M(X), **M = X^12 − 2X^6 + 2**, X = w (noble tower: u² = −1, v³ = ξ = 1 + u, w² = v), u = X^6 − 1,
Φ(a0 + a1u) = (a0 − a1) + a1X^6. M is irreducible (Rabin test in `math.mjs`). σ = Frob^6 is X ↦ −X; Frob² is X ↦ ηX
with η = 2^((p−1)/6) (η² = η − 1); Frob(X^j) = Φ(γ1^j)X^j with γ1 = ξ^((p−1)/6), Frob(X^6) = 2 − X^6. G = Fp12*/Fp6* has
order p^6 + 1; a class is represented by a monic degree-6 polynomial S = X^6 + Σ_{j<6} s_j X^j.
T = |x| = 0xd201000000010000 (x < 0). The Miller loop runs over T in binary: the top bit is the start, events
e = 0..62 handle bit 62 − e, with additions at events 0, 2, 5, 14, 46. Lines are scaled by w³:
L(X) = Φ(ℓ0) + x_P X²Φ(ℓ2) + y_P X³Φ(ℓ3), with the affine line (λx_T − y_T, −λ, 1) (degree 8) and the projective lines
(degree 9). The pairing ê := FE(f_{T,Q}(P)) = e(P, Q)^−1 is nondegenerate and bilinear, and every VK constant uses it.
FE is the (p^12 − 1)/r power. noble's `finalExponentiate`, which every build-time assertion in `math.mjs` uses,
computes the cube of that power. This makes no difference to any asserted relation: every one is an equality (or
≠ 1 test) in μ_r, and cubing is a bijection on μ_r because gcd(3, r) = 1.
λ = p + T = h1·r (h1 the G1 cofactor).

**Witness** (unlocking `<WQ> <WS> <redeem>`, exactly two items besides the redeem):

- `WS` (exactly 11,328 B at E_A = 10), fixed-width little-endian words:
  - `[0,384)`: x_A, y_A, x_B.c0, x_B.c1, y_B.c0, y_B.c1, x_C, y_C (48 B each);
  - `[384,448)`: n0, n1 (32 B each);
  - `[448,576)`: two 64-byte nibble strings N_0, N_1: byte j of N_k holds bit 63 − j of the four base-|x| digits
    a_{k,0..3} (bit i of the byte = digit i), with n_k = Σ_i a_{k,i} T^i;
  - `[576,864)`: s^c, the monic representative of the residue root c;
  - `[864,10080)`: the states S_1..S_32 (6 words each), after events 0, 2, 3, 5, 6, 8, 10, …, 60;
  - `[10080,11328)`: the 13 witnessed affine B slopes (Fp2) of events 0..9 in walk order (10 doublings, the
    additions at events 0, 2, 5).
- `WQ` (48·n_q bytes, 1 ≤ n_q ≤ 118): the odd coefficients q_{n_q−1} … q_0 of the aggregated quotient (highest first;
  q_j is the coefficient of X^{2j+1}); the leading word is nonzero.

**Transcript**: TAG = "SIGLS-BLS/1" ‖ SHA256(VK encoding) (43 B; the VK encoding is α, β, γ, δ, IC0..IC2 as affine
48-byte LE words); h0 = SHA256(TAG ‖ WS); ρ_raw = SHA256(h0 ‖ "rho"); z_raw = SHA256(h0 ‖ ρ_raw ‖ WQ);
ρ = BIN2NUM(ρ_raw ‖ 0x00), z = BIN2NUM(z_raw ‖ 0x00) (< 2^256 < p: no reduction, no bias), z ≠ 0.

**Pairs**: P0 = −A with Q0 = B (runtime), and P1 = C with Q1 = δ (fixed: 68 baked slopes; the script tracks x_j and
c_j = λ_j x_j − y_j on-chain with c_j = (λ_{j−1} + λ_j)x_j − c_{j−1}, x_{j+1} = λ_j² − x_j − s). e(α, β)·e(IC0, γ) is one
baked class Rconst′ = rep[(m_αβ·m_IC0)^(2^−63 mod r)] in the loop's initial value. e(vk_x − IC0, γ) is folded in by
base-|x| GT-GLS: T^i ≡ (−p)^i (mod r), so factor_{k,i} = σ^i Frob^i(m_{IC_{k+1}}) has FE = FE(m)^(T^i); the factor
polynomials are R_{k,0}(X), R_{k,1}(−X), R_{k,0}(ηX), R_{k,1}(−ηX) with baked R_{k,0} = rep[m_k], R_{k,1} = rep[Frob m_k].

**B walk**: events 0..E_A−1 (E_A = 10) are affine with witnessed slopes: doubling checks 2yλ = 3x², addition checks
λ(x_B − x) = y_B − y and x ≠ x_B (reduced values). Events E_A..62 are homogeneous projective from (x : y : 1):
doubling Z3 = 8Y³Z with line (Y² − 3b′Z², −3X², 2YZ), mixed addition with +B, Z3 = Zλ′³, line (θx_B − λ′y_B, −θ, λ′).
Z = 0 is absorbing.

**On-chain steps** (`script.mjs`):

1. Pin the layout and derive the challenges: DEPTH == 2; SIZE(WS) == 11,328; SIZE(WQ) ≡ 0 (mod 48) and
   48 ≤ SIZE(WQ) ≤ 48·118; the leading WQ word ≠ 0 (unsigned decode); h0, ρ, z as above; z ≠ 0.
2. Parse and range-check every word, unsigned (`RD`: BIN2NUM(w ‖ 0x00) < p; n_k < r): coordinates, s^c; the nibble
   strings & 0x0f…0f == themselves; curve checks y² = x³ + 4 on A and C, y² = x³ + 4(1 + u) on B (each as a reduced
   residue == 0). States, slopes and Q words are RD-checked where they are consumed.
3. Precompute z²..z^6, t = z^6 − 1, (ηz)^1..^6, γ1², γ1³ (endpoint), c_j = Φ(γ1^j)(z) (Frobenius), S_c(±z), Rconst′(±z),
   the GT-GLS tables TP_k[n] = Π_{i∈n} factor_{k,i}(z), TM_k at −z (16 entries per k), and TB[n] = Σ_{i∈n} T^i (exact
   integers), and the line coefficients x_A z², y_P z³ (·t), x_C z², y_C z³.
4. F₊ = S_c(−z)·Rconst′(z)·TP_0[N_0[0]]·TP_1[N_1[0]], F₋ at −z; acc_k = TB[N_k[0]]. 63 events, each:
   1. F± ← F±²·L_B(±z) (affine with a witnessed slope, or projective);
   2. the δ doubling step;
   3. if an addition event: the B addition line (affine or projective), the δ addition step, ·S_c(∓z) (c^−1);
   4. F± ·= TP/TM_0[N_0[e+1]]·TP/TM_1[N_1[e+1]], acc_k ← 2acc_k + TB[N_k[e+1]];
   5. at a boundary: R ← Rρ + F₊S′(−z) − F₋S′(z), then F± ← S′(±z) (S′ the next committed state, RD-checked).
5. Terminal: every affine slope and every δ slope consumed (sizes); endpoint [T]B = −ψ(B):
   X·γ1² − conj(x_B)·Z ≡ 0 and Y·γ1³ + conj(y_B)·Z ≡ 0 (Fp2, reduced), Z ≢ 0; W(±z) = Frob(S_c)(±z) =
   s0 + 2 − z^6 + Σ_j s_j c_j (±z)^j; R ← Rρ + F₊W(−z) − F₋W(z); binding acc_k == n_k (exact integers).
6. Accept iff (R − z·q(z²)·M(z)) mod p == 0 (Horner over WQ, every word < p). Then clean stack.

## Spec rules (all implemented from the first build)

| rule | implementation |
|---|---|
| injective, fixed-width transcript | WS is one push of exactly 11,328 bytes of fixed-width fields; WQ is a whole number of 48-byte words and the last field of z's preimage; the tag is fixed-width (43 B, including the VK digest); h0, ρ_raw and z_raw have distinct fixed-prefix preimages. Each byte string parses in exactly one way. |
| enforced cap on n_q | 48 ≤ SIZE(WQ) ≤ 48·118, ≡ 0 (mod 48). NQ_MAX = 118 is derived in `protocol.mjs` from the schedule and chunking and re-asserted in `build.mjs`: the worst chunk is [45, 46] (projective, addition second) with every nibble 15: deg P 242, deg D ≤ 248 → odd 247, deg Q ≤ 235. The leading word must be nonzero (unsigned decode), so n_q is canonical. |
| unsigned hash to field | ρ, z = BIN2NUM(digest ‖ 0x00) < 2^256 < p; no mod; z ≠ 0. |
| canonical unsigned decoding | Every field word (coordinates, B slopes, s^c, states, Q) is decoded as BIN2NUM(w ‖ 0x00) < p. n_k is unsigned 32 B and < r. Nibbles must be ≤ 0x0f (mask equality). |
| reduced values before guards | Curve and twist residues, slope residues, x − x_B, the endpoint residues and Z are reduced mod p before NOT / BOOLOR; the binding is an exact integer equality (NUMEQUALVERIFY); the final identity is reduced. |
| affine segment | 2yλ = 3x² per doubling; λ(x_B − x) = y_B − y and x ≠ x_B per addition (reduced); the projective walk enters at Z = 1 with no witness. |
| projective formulas | exactly the formulas above (Z = 0 absorbing; Z_T ≠ 0 checked). |
| GLS | the 64 nibbles per k are read MSB-first from the same hashed bytes that feed acc_k; the binding acc_k == n_k is exact. |
| pinned layout | DEPTH == 2 at entry, exact SIZE(WS), WQ size rules, consensus clean stack, push-only unlocking. |
| baked constants verified against noble | `math.mjs` asserts at every load: M(w) = 0 and irreducibility; η, γ1 and Frob(S); the ψ endpoint constants (true on G2, false off G2); all 68 δ slopes against noble's point arithmetic and the on-chain x/c recursion; each GLS factor's class and FE(factor_{k,i}) = FE(m_k)^(T^i); FE(Rconst′^(2^63)) = FE(m_αβ·m_IC0); the residue and G2/G1 facts. `test.mjs` cross-checks these against the second design's independent math module. |

## Soundness argument

**Identities.** Chunks: [0] [1,2] [3] [4,5] [6] [7,8] … [61,62] (33 chunks, 32 states). For chunk k with start
S_k (S_0 = S_c(−X)·Rconst′·G_0) and events [a, b]:

  P_k(X) = S_k^{2^{b−a+1}} · Π_{e∈[a,b]} ( L_{B,e} · L_{δ,e} · [L′_{B,e} L′_{δ,e} S_c(−X) if e is an addition] · G_{e+1} )^{2^{b−e}}

with G_j = Π_{k,i: bit i of N_k[j]} factor_{k,i}(X). D_k = P_k(X)S′(−X) − P_k(−X)S′(X), S′ = S_{k+1} (monic) or, for the
last chunk, W = Frob(S_c) (not monic and of degree 11, see below). Since M is even, D_k ≡ 0 (mod M) ⟺ P_k·σ(S′) ∈ Fp6 ⟺ [P_k] = [S′] in G, provided P_k ≠ 0
and S′ ≠ 0: Fp12 is a field; an affine line has X³ coefficient y_P ≠ 0 (E(Fp) has odd order); in a projective line
Φ(ℓ3) splits the y_P term, with ℓ3 = 2YZ or λ′: the X³ and X^9 coefficients are y_P(ℓ3.c0 − ℓ3.c1) and y_P·ℓ3.c1,
which are not both zero because y_P ≠ 0 and ℓ3 ≠ 0 (Z = 0 is absorbing and Z_T ≠ 0 is checked); δ lines have ℓ3 = 1;
every other factor is monic; W = Frob(S_c) ≠ 0.

**Chain and residue.** The 33 relations give [f′·c^{−T}] = [c^p], i.e. [f′] = [c]^λ, where
f′ = Miller(−A,B)·Miller(C,δ)·Rconst′^{2^63}·Π_{k,i} factor_{k,i}^{a_{k,i}} up to Fp2 line scalings (which lie in Fp6).
Then f′ = c^λ·s with s ∈ Fp6*, so FE(f′) = (c^{p^12−1})^{h1}·s^{(p^6−1)(p^6+1)/r} = 1. No cubic-residue witness is
needed (3 ∤ p^6 + 1); honest roots always exist (gcd(λ/r, (p^6+1)/r) = 1, r² ∤ p^6 + 1, asserted).

**GT-GLS binding.** acc_k = Σ_i a_{k,i}T^i is accumulated from the same hashed nibbles that select the factors, and the
script checks acc_k == n_k exactly over the integers, with 0 ≤ n_k < r. Since FE(factor_{k,i}) = FE(m_{IC_{k+1}})^{T^i}
(asserted), the GLS part of FE(f′) is ê(IC_{k+1}, γ)^{n_k}. Together with the residue, FE(f′) = 1 is exactly
ê(−A,B)·ê(α,β)·ê(vk_x,γ)·ê(C,δ) = 1, the Groth16 equation. The digits need not be canonical: any digits < 2^64 that meet
the binding give the same GT element (a non-canonical witness is a positive control in `redteam.mjs` and the sweep).
vk_x never appears as a point, so vk_x = O (the msm-identity fixture) needs no special case.

**B ∈ G2.** The affine segment is the exact group law: each slope is unique (fixed by its equation), no intermediate
point is O (E′(Fp2) has odd order h2·r, so y ≠ 0; x ≠ x_B at additions), and the projective segment starts at (x : y : 1).
The projective segment is exact because Z = 0 is absorbing and Z_T ≠ 0 is checked. So T_end = [T]B, and the endpoint
check gives ψ(B) = [x]B. N(ψ − x) = λ and gcd(λ, h2) = 1 (asserted), so B ∈ G2. This is the same check as the reviewed
BLS singleton (`work/bls-singleton-review/REVIEW.md`, item 2).

**G1 cofactor.** A and C get curve checks only. ê(·, Q) on E(Fp) is a power of the reduced Tate pairing (the
Hess–Smart–Vercauteren relation for f_{x,Q} with x ≡ p (mod r), carried over to f_{T,Q} through f_T = 1/(f_x·v) with
v a vertical line, which FE kills), so it kills the h1-torsion (gcd(h1, r) = 1; checked numerically in `math.mjs` on a point with components of every prime order dividing
h1). Hence verdict(A, B, C) = verdict(A_r, B, C_r): an off-G1 point only re-encodes a valid proof (cofactor
malleability, no forgery). Precedent: the reviewed BLS singleton (REVIEW.md item 3).

**Batching and degrees (adversarial).** All D_k are fixed by h0's preimage (WS) and deterministic on-chain computation
before ρ. If some D_k mod M ≠ 0, Σρ^{32−k}(D_k mod M) vanishes with probability ≤ 32/2^256 over ρ. Otherwise
S(X) := Σρ^{32−k}(D_k mod M) is a nonzero polynomial of degree < 12, and the verifier checks S(z) = (Q − Q*)(z)·M(z)
with Q committed before z; S − (Q − Q*)M ≠ 0 (M does not divide a nonzero polynomial of degree < 12), of degree
≤ max(247, 2·118 − 1 + 12) = 247 for every accepted witness. The closing state W = Frob(S_c) has degree 11, not 6:
Frob(X^j) = Φ(γ1^j)X^j, and each s_j·Φ(γ1^j)(X)·X^j reaches degree j + 6. `degDBound` (protocol.mjs) counts 11 for the
last chunk and 6 for every other chunk, which closes against a monic degree-6 state; the last chunk reaches only
deg D ≤ 219 + 11 = 230 ≤ 247. **ε ≤ (32 + 247)/2^256 ≈ 2^−247.9** per random-oracle
query (z is uniform on [0, 2^256) ⊂ [0, p): no bias factor).

**Completeness.** Honest provers fail only if a monic representative does not exist (probability ~1/p per state), the
leading quotient word is zero after trimming (~1/p), or z = 0 (2^−256).

## Deviations from the design (and why)

- **Rconst′ placement.** The design applies Rconst′ = rep[m^(2^−62)] after event 0. This build puts
  Rconst′ = rep[m^(2^−63)] in the loop's initial value (with S_c(−X) and GLS nibble 0), so the loop has no special
  case. It is still in chunk 0 (deg P_0 ≤ 206 < 242); FE(Rconst′^(2^63)) = FE(m_αβ·m_IC0) is asserted at build.
- **E_A = 10 (design estimate 15).** The build rule (smallest E_A whose worst forced witness keeps ≥ 6% standard
  margin) gives 10 on the measured script: the kernels came out cheaper than the design model (projective doubling
  234k vs 245k, no inner reduction of the doubling line's X² term, Karatsuba X3/Z3, 3b′Z² left unreduced). Worst
  standard margins by E_A (same kernels, worst of 41 proofs): 9: 5.64%, 10: 6.14%, 11: 6.65%.
- **IF bodies are functions.** The bch-spec VM charges 100 op for every instruction of a skipped branch, so each
  branch body of the event loop (affine/projective doubling and addition, the state boundary) is an OP_DEFINE'd
  function; a skipped branch costs two instructions.
- **Score 26,484 vs the design's ~27,475**: E_A 10 instead of 15 (−576 B) and slightly less code.
- **Rejection suite instead of a red team with forged statements.** Per the constructive policy, `redteam.mjs`
  contains malformed and invalid inputs only (no forged statement with a rebuilt witness).

## Compiler and tooling

- `asm.mjs`: the BN254 SI-GLS symbolic-stack assembler with the kernel cost model on 48-byte field words (plus an
  if/else option to adopt the else branch's layout, and a peephole that cancels a SWAP emitted directly after another
  SWAP, in the kernel scheduler and across roll/kernel boundaries; SWAP SWAP is the identity, so the symbolic stack is
  unchanged).
- `script.mjs`: the program. The event loop is one OP_BEGIN … OP_UNTIL over a flag string (addition, boundary, affine);
  its stack layout is the computed fixed point of one event. The affine kernels pass Z through and the projective
  kernels pass the (then empty) slope blob through, so both branches end in the same layout.
- `math.mjs`: constants and their noble assertions (ported from the design-1 record, plus the VK, fixtures and VK
  constants). `protocol.mjs`: layout, transcript, the honest prover (exact polynomial identities, divisibility
  asserted), its forge mode (rejection tests only), and a value-level mirror verifier.
- `build.mjs`: deterministic build (twice, byte-compared), degree bound and cap, smoke spend. `export.mjs`: bench
  vectors. `redteam.mjs`: the rejection suite and the bench red-team file. `worst.mjs`: the forced liveness witnesses.
  `sweep.mjs`: liveness. `test.mjs`: protocol self-test and the cross-check against the second design's math.
  `profile.mjs`: op cost by section (diagnostics VM in `vm.mjs`). `breakdown.mjs`: redeem byte breakdown.

## Reproduce

```sh
# in this directory, with the repository's dependencies (@noble/curves 2.2.0, @bitauth/libauth 3.1.0-next.8)
node test.mjs                                      # math cross-check + protocol self-test
node build.mjs                                     # redeem 12,793 B, sha256 c93557ac…8f74; writes redeem.hex, build.json
node export.mjs vectors.json                       # sha256 9a3732a8…8e03 (searches 40 proofs for the worst case, ~1 min)
node redteam.mjs vectors.json redteam.json redteam-report.json   # 87 runs rejected; redteam.json sha256 ededc8f4…9191
WORST_PROOFS=40 node worst.mjs                     # forced liveness witnesses, each with 40 sampled proofs
SWEEP_N=200 node sweep.mjs sweep.json              # sha256 e7b60eee…4f72; generated, never edited
# or split: SWEEP_SHARD=k/n node sweep.mjs sk.json for each k, then node sweep.mjs --merge sweep.json s0.json s1.json … (byte-identical)
SIGLS_EA=9 node build.mjs && SIGLS_EA=9 node worst.mjs    # the E_A knob (rebuild with the default afterwards)
```

In zk-verifier-bench: copy `vectors.json` to `src/bch/groth16-bls12381-sound-si-gls-single-vectors.json` and
`redteam.json` to `src/bch/redteam/bch-groth16-bls12381-sound-si-gls-single.json`; then run the gates for the exact id
and `pnpm benchmark:json` (score).

## Verification

- **Rejection suite** (`redteam.mjs`, 87 runs, all rejected in consensus and standard mode;
  `redteam-report.json` names the guard that fires): 
  - off-curve A, C and off-twist B; the identity encoded as (0, 0) for A, B, C (curve checks);
  - +p aliases of all 8 coordinates (also with a rebuilt transcript), a 2^384 − 1 word (RD range checks);
  - B off G2: a random twist point and G2 + cofactor point (rebuilt; the endpoint check fires), and a point of order
    13 that makes the affine walk reach x = x_B at the event-2 addition (rebuilt; the x ≠ x_B guard fires);
  - −A, −B, C from another proof (rebuilt; final identity);
  - n + r, 2^256 − 1, top-bit n, n0 + 1 and swapped n (public-input range and binding);
  - nibbles 0x10, 0x80, 0xff (mask), a nibble bit flip, a digit bit flip with a rebuilt transcript (exact binding);
  - witnessed slopes: +1 byte-level, +p alias, and rebuilt wrong / negated / swapped slopes (the slope equations fire);
  - state, residue and statement tampering, state aliases and top-bit words, swapped states, states of another proof,
    one-byte re-parses across field boundaries;
  - quotient: word tampering, alias, top bit, a leading zero word, missing words, 119 words (cap + 1), a length not a
    multiple of 48, empty;
  - layout: extra, missing and reordered pushes, WS ±1 byte and ±1 slope, one merged push, a flipped redeem byte,
    OP_NOP and a non-minimal push in the unlocking.

  Positive controls (accepted): `committed`, and a valid witness with non-canonical GLS digits.
- **Liveness** (`sweep.json`, 279 cases, all accepted in both modes): the 6 fixtures; the forced extremes of `worst.mjs` for
  n_q targets 46..80 and every nibble nonzero, and 40 sampled proofs (random B, C) of the n_q 53 extreme (minimum
  standard margin **1,800,888 = 6.14%** at n_q 53 with 119 nonzero nibbles, proof sample #27; consensus 1,854,904 =
  6.32%). The forced patterns maximise the nonzero nibble count and then the bytes with both nibbles nonzero (a slot-2
  byte costs more op than two slot-1 bytes); the op cost varies by ~20k with the proof bytes. Special statements (1, r − 1, |x|-power and digit-boundary values); the six
  lowest-n_q statements of a 4,000-statement search (n_q 46); a valid non-canonical-digit witness; 200 random proofs
  (n_q 83..109, minimum standard margin 8.81%). Maximum op 28,166,315 standard (random, n_q ~ 100).
  Sensitivity (E_A knob, worst forced witness over 41 proofs, standard): E_A 9 → 5.64%, 10 → 6.14%, 11 → 6.65%.
- **Protocol** (`test.mjs`): math cross-check against the second design; honest proofs for 6 statements and the 6
  fixtures accepted by the mirror verifier, tampering rejected; identity fixtures unencodable; a false statement has
  no honest witness.

## Open risks

- **Owner decision: identity fixtures.** The 4 bench BLS fixtures with A, B or C = O (b-identity, a-identity,
  c-identity, all-identity) cannot be encoded (affine coordinates, the curve check rejects (0, 0)) and are rejected.
  The BN254 SI-GLS behaves the same way.
- **Owner decision: statement encoding.** Public inputs bind through hashed base-|x| digits and an exact integer
  equality, not an explicit vk_x point (same open decision as the BN254 SI-GLS). The bench public-input gate passes.
- **No G1 subgroup check on A and C**: soundness relies on the reduced-Tate cofactor argument above; the consequence
  is cofactor malleability (a valid proof can be re-encoded), not a forgery.
- **Formula correctness is tested, not machine-proved.** The argument assumes the script computes the stated
  polynomials (affine and projective B formulas, line slots, the ±z evaluations). This is checked by exact
  divisibility of every honest identity in the prover, by every accepted sweep proof, by noble cross-checks of the δ
  recursion and constants, and by the second design's independent math; there is no formal equivalence proof of
  the bytecode.
- **Rconst′ placement** (2^−63 power in the initial value) is new relative to BN; it is a build-time assertion, not a
  runtime check.
- **Op margin is about 6.1% at the worst forced witness** (n_q 53 with 119 nonzero nibbles). The op cost is almost
  statement-independent except for the GT-GLS lookups; the budget shrinks with n_q. Any change that adds op cost must be
  re-checked with `worst.mjs`; E_A is the knob (+1 affine event ≈ +0.5% margin for 96 B).

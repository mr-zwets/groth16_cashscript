# BLS12-381 Groth16, SI-GLS on current BCH: one standard transaction of 4 P2SH32 inputs (bch-2026), sound by construction

A full Groth16 verifier for the fixed BLS12-381 VK of the bench fixtures (`math.mjs`: α = 3·G1, β = 5·G2, γ = 7·G2,
δ = 11·G2, IC = (2, 4, 6)·G1, public inputs n0, n1), on the **current** BCH VM (bch-2026): per-script cap 10,000 B,
per-input op-cost budget (41 + unlocking length) × 800, standard transaction ≤ 100,000 B. The transaction has 4 P2SH32
inputs that all lock to the same redeem R; together they run one SI-GLS check ("single batched torus identity at ±z,
GT-GLS folding of e(vk_x, γ)"), the same mathematics as the reviewed BN254 `chunked/bn254/sound-si-gls` and the BLS
bch-spec build. Bench entry id: `bch-groth16-bls12381-sound-native` (review status: **reviewed**, independent review 2026-10-26).

Design record: `research/sound-sz-bls12381-native` (design 1, the base) and `research/bls-native-sound-design2`
(merged items), judged in `verifier.cash/work/bls-native-sound-DESIGN.md`. Deviations from that design are listed below.

**Every accept-relevant value is computed on-chain, a VK constant (pinned by a hash in the program), hash-committed
before the challenge it meets, or fixed by an exact field or integer equation. No prover-supplied evaluation is used.**

## Results (fixture `committed`, n = (123, 456), B = the G2 generator)

| | |
|---|---|
| **score** (scripts + tx overhead) | **34,229** = 34,037 (4 × 35 locking + 33,897 unlocking) + 192 |
| unlocking per input | 6,397 / 9,755 / 9,720 / 8,025 (each ≤ 10,000; standard) |
| R (the redeem of every input) | 81 B |
| program (shared, loaded by R from two carriers) | 6,465 B (role bodies 1,521 / 195 / 183 / 789; SETUP 1,606 incl. 1,152 B of GLS factor constants) |
| op-cost, standard (consensus) | 4.70M (4.65M) / 6.85M (6.83M) / 6.84M (6.82M) / 5.76M (5.75M) = 24.15M (24.04M) |
| margins at the fixture, standard | 8.7% / 12.7% / 12.4% / 10.7% |
| liveness sweep (667 proofs, both modes) | all valid and standard; **sample minimum margin 6.18% standard, 6.42% consensus** (forced worst cases with random B, C) |
| zero filler (budget only, content pinned) | 311 B in 4 pushes (bench `padBytes` 317) |

Gates (`tools/bench-one.mts bch-groth16-bls12381-sound-native`): valid accepted, 41/41 invalid vectors rejected,
cross-stage stapling 0/3 unbound seams, red team 57/57 rejected, public inputs 9/9 mutations rejected, layout not
malleable, 7/7 proofs runtime-general, standard (relayable), P2SH32 packaging.
The bench `worstCaseProof` is `ALL15, random B and C #32` (`export.mjs`): every nibble 15 on bytes 8..63, n_q = 116,
26.01M consensus op (within 0.2% of the sweep's largest total, 26.04M at random proof #312), the heaviest input and the
largest transaction of the sweep, and the smallest margin of input 1; the smallest input-0 margin of the sweep (forced
n_q = 44, digit 3 first, random B and C #55) ships as an extra valid proof.

## Protocol

Notation (asserted against noble 2.2.0 in `math.mjs` at every load): Fp12 = Fp[X]/M, M = X¹² − 2X⁶ + 2, X = w in noble's
tower (u² = −1, v³ = 1 + u, w² = v), u = X⁶ − 1, Φ(a₀ + a₁u) = (a₀ − a₁) + a₁X⁶. σ = Frob⁶ is X ↦ −X; Frob² is X ↦ ηX
(η² = η − 1). G = Fp12*/Fp6* (cyclic of order p⁶ + 1); a class is represented by a monic degree-6 polynomial.
|x| = T = 0xd201000000010000; 63 events e = 0..62 (bit 62 − e), additions after the doublings of events 0, 2, 5, 14, 46.
λ = p + |x| = h₁·r. Lines are M-type, scaled by w³: L = Φ(c) − x_P X² Φ(λ) + y_P X³ with c = λx_T − y_T.

**Chunks and identities.** 33 chunks: [0] [1,2] [3] [4,5] [6] [7,8] … [61,62] (every addition is a chunk's only or
second event). 32 committed states S₁..S₃₂ (monic, 6 words). Chunk k: P_k = start_k^(2^len) · Π_events (B line ·
δ line · [B add line · δ add line · S_c(−X)] · GLS factors)^(2^…), D_k = P_k(X)S_{k+1}(−X) − P_k(−X)S_{k+1}(X), with
start₀ = S_c(−X)·Rconst′·G₀ (Rconst′ = rep[(m_αβ m_IC0)^(2^−63 mod r)], squared 63 times in the loop) and S₃₃ := W = Frob(S_c).
Structural degree bound (every nibble 15): deg D ≤ 243, so the odd quotient has n_q ≤ **NQ_MAX = 116** words; the
all-zero-nibble statement has n_q = **N_MIN = 44** (`protocol.mjs`, asserted in `build.mjs`).

**The 4 inputs** (`layout.json`; chunks [0,5) [5,15) [15,25) [25,33)):

| input | role | events | own region G | claims CL | other pushes |
|---|---|---|---|---|---|
| 0 | head + Miller | 0–6 (adds 0, 2, 5) | statement (864) ‖ 5 states ‖ 10 slopes = 3,264 | R̃₀ ‖ T̃₀ (240) | ZR = z̃ ‖ ρ̃ (96), K0 piece 0 (513), filler 24, **WQ (last)** |
| 1 | Miller | 7–26 (add 14) | 10 states ‖ 21 slopes = 4,896 | R̃₁ ‖ T̃₁ (240) | K1 piece 0 (171), filler 124, program part 0 (4,229) |
| 2 | Miller | 27–46 (add 46) | 10 states ‖ 21 slopes = 4,896 | R̃₂ ‖ T̃₂ (240) | K2 (2,208), filler 45, program part 1 (2,236) |
| 3 | Miller + terminal | 47–62 | 7 states ‖ 16 slopes = 3,552 | R̃₃ (48) | K0 piece 1 (447), K1 piece 1 (2,037), K3 (1,728), filler 115 |

Every word is 48-byte unsigned little-endian; n0, n1 are 32 bytes at offsets 384, 416 of the statement; N₀, N₁ are
64 nibble bytes each (byte g holds bit 63 − g of the base-|x| digits a_{k,0..3}); s^c is the monic residue root (6 words).
A slope is 2 words (Fp2); one per doubling and one per addition, in event order.

**Constant blocks.** K_i = (x_j, y_j) ‖ λ_j … (the δ walk point before the input's first δ step, then one baked δ slope
per step); input 0 starts at δ itself (constants in the program), so K0 holds slopes only. A block may be split into
pieces hosted in other inputs (budget balancing); its user concatenates the pieces and requires SHA256 = K_HASH[i]
(baked in the program). The program blob is split into two parts, each the last push before R in its carrier.

**R (identical for all 4 inputs, 81 B).**
```
OP_TXINPUTCOUNT 4 NUMEQUALVERIFY
0 BEGIN DUP UTXOBYTECODE INPUTINDEX UTXOBYTECODE EQUALVERIFY 1ADD DUP 4 NUMEQUAL UNTIL DROP
1 INPUTBYTECODE <off1> SPLIT NIP <len1> SPLIT DROP  2 INPUTBYTECODE <off2> SPLIT NIP <len2> SPLIT DROP CAT
DUP SHA256 <H_blob> EQUALVERIFY 0 DEFINE 0 INVOKE
```
The program defines its functions and invokes the role body `INPUTINDEX + 1` (computed OP_INVOKE: no IF ladder).

**Transcript (input 0).** h₀ = SHA256(TAG ‖ SHA256(G₀) ‖ SHA256(G₁) ‖ SHA256(G₂) ‖ SHA256(G₃)), TAG =
"SIGLS-BLS-NATIVE/1" ‖ SHA256(VK encoding) (50 B); ρ_raw = SHA256(h₀ ‖ "rho"); z_raw = SHA256(h₀ ‖ ρ_raw ‖ WQ);
ρ, z = BIN2NUM(raw ‖ 0x00) ∈ [0, 2²⁵⁶) ⊂ [0, p) (no reduction); z ≠ 0. Every G_i has a fixed size per role and WQ is the
last field of z's preimage, so every preimage parses one way.

**Head (input 0), before its Miller events.**
1. Layout pin; WQ rules: SIZE ≡ 0 (mod 48), 48·44 ≤ SIZE ≤ 48·116, and (SIZE = 48·44 or the leading word ≠ 0).
2. Reads G₁, G₂, G₃ and R̃₃ from inputs 1–3 at their pinned offsets; computes h₀, ρ, z; requires ZR = NUM2BIN(z, 48) ‖
   NUM2BIN(ρ, 48) byte for byte.
3. Statement: every coordinate and s^c word < p; n_k < r; N & 0x0f…0f = N; y_A² = x_A³ + 4, y_C² = x_C³ + 4,
   y_B² = x_B³ + 4(1 + u) (reduced residues).
4. GT-GLS binding over the integers: acc_k = Σ_g 2^(63−g)·TB[N_k[g]] = n_k exactly, TB[m] = Σ_{i∈m} |x|^i.
5. Horner over WQ (every word < p): Q(z) = z·q(z²); **final identity R̃₃ ≡ Q(z)·M(z) (mod p).**

**Miller part of input i** (shared code, `WORK` / `SETUP` / `LOOP`): reads z̃, ρ̃, the statement and s^c from input 0
(every word decoded unsigned and range-checked again); for i > 0 the predecessor's last state S_{c0} (< p) and its claims
R̃_{i−1} ‖ T̃_{i−1} (< p); its own states and slopes; its δ block. Setup: z-powers, the line environment, S_c(±z), the
GLS tables TP_k / TM_k at ±z (16 entries each). Two monic reps per group are baked, R_{k,0} = rep[m_k] and
R_{k,1} = rep[Frob(m_k)]; the digit factors are factor_{k,0}(X) = R_{k,0}(X), factor_{k,1}(X) = R_{k,1}(−X) (the
conjugated Frobenius rep), factor_{k,2}(X) = R_{k,0}(ηX) and factor_{k,3}(X) = R_{k,1}(−ηX) (`glsFactorPoly`; `math.mjs`
asserts each factor's class, FE(factor_{k,i}) = FE(m_k)^(|x|^i)). Start: F± = S_{c0}(±z)
(input 0: S_c(∓z)·Rconst′(±z)·TP/TM[N[0]]), R = R̃_{i−1} (input 0: 0). Per event e:
- B doubling with the witnessed slope l (< p): residue 2y·l − 3x² ≡ 0 (reduced, both Fp2 coordinates); x₃ = l² − 2x,
  y₃ = (lx − y) − l·x₃; F± ← F±²·L_B(±z);
- δ step: baked λ_j, c_j = (λ_{j−1} + λ_j)x_j − c_{j−1}, x_{j+1} = λ_j² − x_j − s; F± ← F±·L_δ(±z);
- at an addition (function call, not an IF ladder body): x_B − x ≢ 0 (reduced), l(x_B − x) − (y_B − y) ≡ 0, the chord
  and the δ add step, F± ·= S_c(∓z);
- GLS: F± ← F±·TP/TM₀[N₀[e+1]]·TP/TM₁[N₁[e+1]];
- at a chunk end (function call): decode the next state (< p); R ← Rρ + F₊·S(−z) − F₋·S(z); F± ← S(±z).
Inputs 0–2 end with R̃_i = NUM2BIN(R mod p, 48) and T̃_i = the affine end point (canonical bytes) byte for byte.
Input 3 ends with R ← Rρ + F₊·W(−z) − F₋·W(z), W = Frob(S_c) (Frobenius constants from γ₁), the endpoint
x·γ₁² = conj(x_B), y·γ₁³ = −conj(y_B) (exact, reduced), and R̃₃ byte for byte. Clean stack, TRUE.

## Spec rules (design §5) and where they are enforced

| rule | implementation |
|---|---|
| 1. canonical decoding at every decode | `RD`/`RD2`/`RD6`: BIN2NUM(w ‖ 0x00) and max(words) < p, used for coordinates and s^c (head and every Miller input), states (owner and successor), slopes, WQ, z̃, ρ̃, R̃, T̃. n_k < r; nibbles ≤ 0x0f. Constant blocks are hash-pinned (BIN2NUM without check). |
| 2. fixed layout | every role checks DEPTH and the exact SIZE of every push (WQ: its rules; program parts: their sizes); BCH unlockings are push-only with minimal encodings, so every push of every input sits at a fixed byte offset (`pushesOf`, `offsetOf`). Fillers must be all zero. Clean stack. |
| 3. WQ rule | 44 ≤ n_q ≤ 116, multiple of 48, canonical (exactly 44 words, or the leading word ≠ 0); WQ is the last field of z's preimage. |
| 4. transcript | fixed arity (4 region hashes), fixed-size regions defined by the role table shared by the head and the readers; every committed byte is hashed once, before ρ and z; TAG carries the VK digest. Committed data is never relocated: G_i is input i's own push. |
| 5. reduced guards | slope residues, x_B ≠ x, curve and twist checks, endpoint, final identity: `(a − b) mod p` tested for 0; z ≠ 0 on [0, 2²⁵⁶); claims compared as NUM2BIN of a value in [0, p) (`C48`). |
| 6. pins | R: input count 4, every input's locking equals this input's own, SHA256(program) = H_blob; K_HASH[i] in the program; role = OP_INPUTINDEX by computed OP_INVOKE. |
| 7. no IF ladders | role dispatch by computed OP_INVOKE; the addition and the chunk end are function calls inside one-instruction IF bodies (a skipped branch costs two instructions). |
| 8. build-time assertions | `math.mjs` (every constant, class equality with noble's Miller loop, λ facts, ψ, gcd(p − x, h₂) = 1, odd #E(Fp), GLS factor reps, Rconst′), `protocol.mjs` (degree bound, n_q cap/floor, δ trajectory and K blocks), `build.mjs` (deterministic double build, smoke spend). |
| 9. liveness gate | ≥ 6% standard at the forced worst cases, ≥ 5% measured in both modes on the built artifact: fillers fitted to 6.2% on the forced worst witnesses (`tune.mjs`), measured **≈ 6.18%** standard / 6.42% consensus sample minimum over 667 proofs (`sweep.mjs`; 6.175% over 3,600 more proofs of the review families); every unlocking ≤ 10,000 B (largest 9,805 B, input 0 at n_q = 116), tx ≤ 100,000 B. |
| 10. rejection suite | `redteam.mjs`: 61 rejection cases + 2 positive controls (below). |

## Soundness argument

**From the transaction to one computation.**
- *Pins.* A valid transaction has exactly 4 inputs (R), all spending P2SH32(R) for the same R (each input compares every
  sibling's locking with its own; no hash fixed point). R loads the program from two fixed byte ranges and checks
  SHA256 = H_blob, so every input runs the program, and the program runs the role body of the input's index.
- *Layout.* Each role pins its push count and every push size; with push-only, minimally encoded unlockings this fixes
  every byte offset, so every introspected slice (G_i, CL_i, ZR, constant pieces, program parts) is the intended field.
  The head hashes exactly the bytes G_i that input i computes with (its own push) and that input i + 1 reads its start
  state from.
- *Constants.* δ blocks: SHA256 = K_HASH[i] in the program; everything else is in the program, whose hash is in R.
- *Copies.* z̃, ρ̃ equal the head's computed z, ρ byte for byte; R̃_i, T̃_i equal input i's computed values byte for byte;
  every consumer decodes these bytes with the same unsigned decoding and range checks. So every input runs with the
  true z, ρ, the predecessor's true end point and partial sum.
- *Chaining.* The B walk of input i + 1 starts at T̃_i (the exact end point of input i); the δ walk starts at the baked
  trajectory point (asserted at build against the full δ recursion and noble); R continues across the inputs, so
  R̃₃ = Σ_{k=0}^{32} ρ^{32−k} D_k(z) for the 33 chunk identities. By induction over the inputs, the four programs together
  are exactly the single-input BLS SI-GLS check.

**Owner of every accept-relevant value.**

| value | owner |
|---|---|
| input count, order, code | count = 4 and identical lockings (R, P2SH32); role = OP_INPUTINDEX |
| program | SHA256 = H_blob in R (the hashed bytes are the defined bytes) |
| δ start points and slopes, Rconst′, R_{k,i}, η, γ₁, p, r, TB, TAG | VK/curve constants asserted against noble at build; δ blocks pinned by K_HASH[i] |
| A, B, C, n₀, n₁, N₀, N₁, s^c, S₁..S₃₂, B slopes | hash-committed in h₀ (fixed-size regions, fixed arity) before ρ and z; unsigned decoding with range checks at every decode |
| WQ | committed before z (after ρ); cap 116, floor 44, canonical; words < p |
| ρ, z | computed on chain by the head; reach the other inputs as z̃, ρ̃ fixed by exact byte equality |
| B-walk points | computed on chain from B; every slope fixed by an exact equation with a unique solution; handoffs T̃ by exact equality |
| F±, R across inputs | computed on chain; handoffs R̃_i by exact equality in the producer |
| verdict | final identity, endpoint, exact binding, curve, twist and range checks |

**The single computation** (as in the reviewed BN254 SI-GLS and the BLS design record).
- *B binding.* At a doubling, y = 0 with 2y·l = 3x² forces x = 0, and (0, 0) is not on E′ (b′ ≠ 0): y ≠ 0 and l is
  unique. At an addition the reduced guard x_B ≠ x makes l unique. So every T_j = [k_j]B exactly (never O), and the
  endpoint [|x|]B = −ψ(B) puts B in G2 (the kernel of ψ − [x] on E′(Fp2) has order dividing gcd(p − x, #E′) = r; asserted).
- *Nonzero factors.* Affine lines carry y_P·X³ with y_P ≠ 0 (E(Fp) has odd order); all other factors are monic, and
  W = Frob(S_c) ≠ 0. So every factor is a nonzero polynomial of degree < 12 and [P] = [S′] ⟺ D ≡ 0 (mod M).
- *Identities.* Every D_k is fixed by h₀'s preimage before ρ. If all D_k ≡ 0 (mod M), chaining gives [f′] = [c]^λ, so
  FE(f′) = 1 (FE kills Fp6* and FE(c^λ) = 1), where f′ is the product of the two Miller loops (−A, B), (C, δ),
  m_αβ·m_IC0 (via Rconst′) and the GLS factors; λ = p + |x| = h₁r and gcd(λ/r, (p⁶+1)/r) = 1 (asserted).
- *The accepted relation.* For **all** curve points A, C, all B in G2 and all n₀, n₁ < r (not only valid proofs):
  FE(f′) = e(A,B)·(e(α,β)·e(vk_x,γ)·e(C,δ))^(−1), vk_x = IC₀ + n₀IC₁ + n₁IC₂. Derivation from asserted facts
  (`math.mjs`): FE(miller(P, Q)) = e(P, Q)^(−1) and FE(w³) = 1 (so the w³-scaled lines change nothing), hence
  FE(miller(−A, B)) = e(A, B) and FE(miller(C, δ)) = e(C, δ)^(−1); FE(Rconst′^(2⁶³)) = FE(m_αβ·m_IC0) =
  (e(α,β)·e(IC₀,γ))^(−1); the GLS factors give e(vk_x − IC₀, γ)^(−1) (next bullet). `test-protocol.mjs` checks this
  identity on random, non-valid (A, B, C, n).
- *GT-GLS binding.* FE(factor_{k,i}) = FE(m_{IC_{k+1},γ})^(|x|^i) (asserted); σ∘Frob acts as ^|x| on μ_r and r < |x|⁴.
  The exact integer equation Σ_g 2^(63−g) TB[N_k[g]] = n_k uses the same hashed nibbles that select the factors, so the
  GLS part of FE(f′) is e(vk_x, γ)^(−1) with vk_x = IC₀ + n₀IC₁ + n₁IC₂ for the on-chain-bound n_k < r (the digits need
  not be < |x|: any digits satisfying the equation give the same GT element): byte g's factor is squared 63 − g times,
  so Π FE(factor_{k,i})^(a_{k,i}) = e(IC_{k+1}, γ)^(−Σ_i a_{k,i}|x|^i) = e(IC_{k+1}, γ)^(−n_k). With the relation above,
  FE(f′) = 1 is exactly e(A,B) = e(α,β)·e(vk_x,γ)·e(C,δ).
- *A, C.* Curve checks only: the reduced pairing on E(Fp) × G2 kills the E(Fp)[h₁] component (`G1_COFACTOR_FACT`,
  asserted), so a cofactor component is malleability within the same statement, not soundness (as the reviewed BLS
  singleton).
- *Batching.* Let S = Σ_k ρ^(32−k) D_k (a polynomial in X, fixed before z). If some D_k ≢ 0 (mod M), then
  S mod M = 0 for at most 32 values of ρ: probability ≤ 32/2²⁵⁶. Otherwise S mod M = Rem ≠ 0 (deg Rem < 12), and for
  every committed odd Q, S − Q·M = (S div M − Q)·M + Rem ≠ 0 (if S div M ≠ Q the first term has degree ≥ 12 > deg Rem;
  else it is Rem). Its degree is ≤ max(243, 2·n_q − 1 + 12) ≤ max(243, 2·116 − 1 + 12) = 243, and Q is fixed before z:
  probability ≤ 243/2²⁵⁶. **ε ≤ 275/2²⁵⁶ ≈ 2^−247.9** per random-oracle query (z, ρ uniform on [0, 2²⁵⁶), no reduction
  bias); an adversary that grinds over q oracle queries (to h₀ or to WQ) succeeds with probability ≈ q·275/2²⁵⁶.

**Not claimed.** Witness uniqueness (the residue root is unique up to r-torsion; the digits up to the binding; neither
lets a false statement through). Formal bytecode equivalence: tested (exact divisibility of every honest identity,
value-level split verifier = VM claims, 667 accepted proofs, 61 rejections), not proven. Totality of the class
encoding: G = Fp12*/Fp6* has p⁶ + 1 classes but there are only p⁶ monic degree-6 representatives; the order-2 class [w]
has none (an odd polynomial has no X⁶ term). An honest state or residue root in [w] would make the prover throw
("singular"); this happens with probability about 33/p⁶ per proof, is liveness-only and does not affect soundness.

## Deviations from the chosen design (and why)

- **Chunking** of the BLS bch-spec build ([1,2,1,2,1,2×28], 33 identities, 32 states) instead of [1, 2×31]: with the
  all-affine lines and base-|x| digits it gives NQ_MAX 116 (not 127) and n_q 45 at the fixture (not 55) for one more
  state: about −190 B at the fixture and a smaller WQ window for input 0's cap.
- **Quotient floor N_MIN = 44** (the all-zero-nibble structural length) instead of 70: design 1's 70 came from its
  Babai/offset digits; with base-|x| digits the fixture has n_q 45. The rule is the same (exactly N_MIN words, or the
  leading word ≠ 0).
- **Rconst′ in the loop's initial value** (2^−63 power), as in the BLS bch-spec build: no special case at the end.
- **Committed data is never relocated**; only the δ constant blocks (hash-pinned) and the program (two parts) move between
  inputs. The head therefore hashes each input's own region push, and rule 4 needs no relocation table.
- **Partial sums are chained** (input i starts R at R̃_{i−1}); the head checks only R̃₃, instead of combining four claims
  with powers of ρ.
- **δ start points** are (x_j, y_j) (192 B) resumed with λ_{j−1} := 0, c_{j−1} := y_j; input 0 starts at δ from program
  constants.
- **Two program parts** (design 2's merge item): no single input can carry the 6.5 kB program and its own data within
  10,000 B at the required budget. R is 81 B (design estimate 65–81).
- **Zero fillers (311 B).** At the 6.2% tuning target the worst witnesses need more op budget than the natural bytes buy;
  `tune.mjs` moves constant/program bytes along the available edges first and adds all-zero filler pushes only for the
  remainder. Each filler's content is checked to be zero (no malleability).

## Verification

- **Rejection suite** (`redteam.mjs`, all on the real VM, consensus and standard; `redteam-report.json` names the
  rejecting inputs, and for 45 cases checks that the owning input rejects): positive controls (fixtures `committed`,
  `dense`); pins (5th input, inputs swapped twice, a foreign locking, a changed redeem); layout (a push one byte longer,
  an extra push, a non-push opcode, a claims push one byte short, constant pieces swapped and resized, a non-zero
  filler); program parts tampered; constant blocks tampered (own and relocated pieces, a wrong start point); committed
  bytes changed after the challenges (x_A, a state, a slope, a nibble, s^c); public inputs n₀ + 1 and n₁ + r; quotient
  (a word changed, 43 and 117 words, a leading zero word above the floor, a length not a multiple of 48); claims (z̃, ρ̃,
  R̃_i, T̃_i: + 1, + p aliases, byte flips); + p aliases with a re-derived consistent transcript (slope, state, the
  successor-read last state, x_A, s^c, n₀ + r, a nibble 0x10: only the range checks can reject these); malformed proof
  points with an honest prover (A, C off the curve, −A, B off the twist, B on the twist outside G2, a foreign B); stapled
  inputs from two valid proofs at every seam. 57 of them are the bench red-team file (unlocking patches only).
- **Liveness** (`sweep.mjs`, 667 proofs, all valid in both modes, every unlocking ≤ 10,000 B). Op cost model (measured,
  `worst.mjs`): ~24k op per nonzero GLS nibble, ~0.2k op per extra set bit of a nibble, ~2k op (sd) from B and C; only
  input 0's budget grows with n_q; input 0 also pays for the GT-GLS binding loop, whose TB[N_k[g]] lookups are 1–25 B
  (TB[1] = 1 is 1 B, TB[8] = |x|³ is 24 B), so the same set bits cost input 0 more in the high digits. So the extremes
  are, for inputs 1–3, the every-nibble-15 statement ALL15 (n₀ = n₁ = (2⁵⁶ − 1)·Σ_{i<4}|x|^i, n_q = NQ_MAX = 116) and,
  for input 0, the forced witnesses at the floor n_q = 44 (`maxSlots`: per chunk, the set bits per byte that maximize
  24k·(nonzero nibbles) + 0.2k·(set bits) within the degree bound), with the bits placed both at digit j mod 4
  (`statementFor`) and in digit 3 first (`statementFor(slots, D3FIRST)`, still canonical: asserted against `glsDigits`).
  Cases: the 6 fixtures; forced witnesses at n_q ≤ 44, 45, 46, 47, 48, 50, 52, 54, 56, 60, 64 and n_q ≤ 44 digit 3
  first; every nibble nonzero; ALL15; the zero statement; special public inputs (0, 1, r − 1, 2⁶⁴/2¹²⁸, r/2, r/3);
  40 × each of ALL15, forced 44 and forced 45 and 80 × forced 44 digit 3 first, with random B and C; 40 random
  statements with random B and C; 400 random proofs. n_q 44–116 (random statements 77–113); total op 24.0M–26.2M
  standard; sample minimum margins standard 6.18% / 6.19% / 6.21% / 6.20% (inputs 0–3; input 0 at forced 44 digit 3
  first, inputs 1–3 at ALL15), consensus 7.24% / 6.42% / 6.44% / 6.46%; largest input-0 unlocking 9,805 B (ALL15,
  n_q = 116, the cap-size regression case); largest tx 37,497 B. Random proofs stay above ALL15 on inputs 1–3. These
  are minima over a sample, not bounds: B and C spread input 0's margin at forced 44 by ~0.05%. An independent re-run
  of the review families (seed review-r1: f44d3 900, f44s 600, f44 600, f44d2 300, m15 900, rand 300; 3,600 proofs) on
  this build: all valid, minimum standard 6.175% / 6.181% / 6.187% / 6.180% (input 0 at f44d3, inputs 1–3 at m15).
- **Build**: double build byte-identical; `test-protocol.mjs` (prover and value-level verifier on all fixtures,
  divisibility of every identity, split claims equal to the reference; the accepted relation FE(f′) = e(A,B)/(e(α,β)e(vk_x,γ)e(C,δ)) on
  random non-valid (A, B, C, n)).

## Tooling

- `math.mjs` (BLS facts and VK constants, asserted against noble), `asm.mjs` (named-stack assembler with scheduled
  arithmetic kernels; bch-2026 introspection opcodes), `protocol.mjs` (schedule, role table, layout, transcript, honest
  prover, split claims, value-level verifier), `script.mjs` (R and the program), `vm.mjs` (bch-2026 runners),
  `transaction.mjs` (built artifact + transaction).
- `measure.mjs` (per-event op from a VM trace), `layout.mjs` (chunk ownership and placement search), `tune.mjs` (fits the
  placement and fillers on the VM to the worst witnesses), `layout.json` (the result, checked in), `check.mjs`,
  `profile.mjs`, `fnprof.mjs`, `worst.mjs` (forced liveness witnesses), `m1.mjs` (prototype driver).

## Reproduce

```sh
# in this directory, with the repository's dependencies (@noble/curves 2.2.0, @bitauth/libauth 3.1.0-next.8), Node >= 22
node test-protocol.mjs                                  # prover + value-level verifier on all fixtures
node build.mjs                                          # R 81 B, program 6,465 B; redeem.hex, program.hex, build.json
node export.mjs vectors.json                            # bench vectors (41 invalid)
node redteam.mjs redteam.json redteam-report.json       # 63/63 as expected
for k in 0 1 2 3 4 5 6 7; do SWEEP_SHARD=$k/8 node sweep.mjs sweep/sweep-$k.json & done; wait   # 667 proofs
node tune.mjs                                           # the reproducible layout step: reads layout.json, re-fits
                                                        # placement and fillers on the VM (MARGIN 0.062; forced 44
                                                        # (both placements), 45-47, ALL15, random B, C); layout.json
                                                        # is its fixed point (re-running leaves it unchanged)
# layout search (only after a program change; a heuristic seed, not unique: different seeds tune to different fixed points)
WIT=committed,dense,forced:44,forced:44d3,random:1,random:2,random:3 node measure.mjs measure.json   # per-event op of the current layout
MARGIN=0.06 node layout.mjs measure.json 3              # candidate {cuts, place}
node tune.mjs '<a candidate {"cuts", "place"}>'         # fits it on the VM; writes layout.json
```

In zk-verifier-bench: copy `vectors.json` to `src/bch/groth16-bls12381-sound-native-vectors.json` and `redteam.json` to
`src/bch/redteam/bch-groth16-bls12381-sound-native.json`, then `npx tsx tools/bench-one.mts bch-groth16-bls12381-sound-native`.

## Open risks

1. **Thin liveness margins.** ≈ 6.17–6.18% standard at the worst measured witnesses (sample minima: 6.18% over the
   667-proof sweep, 6.175% over 3,600 review-family proofs; fillers fitted to 6.2% on the forced worst cases). The
   forced cases (ALL15 for inputs 1–3, forced n_q = 44 with the bits in digit 3 first for input 0) are the extremes of
   the measured op model; B and C move the op cost by ~2k op (sd ≈ 0.03% of a budget), so a margin below 6.0% would
   need a ~6σ outlier. Any change to the program moves the byte balance: re-run `measure.mjs`, `layout.mjs`, `tune.mjs` and the
   sweep.
2. **Correctness is tested, not proven**: the kernels (affine doubling/addition, δ step, evaluations, tables), the
   handoffs and the terminal are checked by exact divisibility of every honest identity, the split reference claims and
   the VM runs, not by a formal equivalence proof (same status as SI-GLS BN254).
3. **The quotient floor N_MIN = 44** is an encoding-uniqueness rule (not a soundness rule) and is new relative to the
   reviewed BN rule; the floor makes input 0's minimum budget deterministic.
4. **Input 0's cap at the structural maximum.** The cap check uses NQ_MAX = 116: input 0 is 6,349 B at n_q = 44, so
   9,805 B at n_q = 116 (195 B under the 10,000 B cap). This is a real honest case: the canonical statement ALL15 reaches
   n_q = 116 and verifies in both modes (kept in the sweep as the cap-size regression test). Random statements have
   n_q 77–113 (the sweep's random proofs and random-B, C statements).
5. **Public-input binding through GT-GLS** (exact integer equation on hashed nibbles) rather than an on-chain vk_x MSM;
   the owner accepted this mechanism for SI-GLS BN254.
6. **G1 cofactor malleability** of A and C (curve checks only): statement-preserving, as documented for the reviewed
   BLS singleton.
7. **The fixture understates typical proofs**: random statements have n_q ≈ 77–113 (≈ +1.5–3.3 kB of WQ in input 0,
   which also raises its budget); the score is measured on fixture `committed` like every other entry.
8. **Zero fillers (311 B)** are budget-only bytes; they are pinned to zero and reported by the bench as padding.

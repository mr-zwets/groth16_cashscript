# BLS12-381 Groth16 on current BCH (bch-2026): MI-SI-GLS, a sound multi-input design (designer 2)

**Status:** design record with VM prototypes. It is not a built verifier and not a zk-verifier-bench entry.
Every number below is either measured in the libauth VM (marked *measured*) or derived from measured parts by
`model.mjs` (marked *model*). Branch `wip/bls-native-sound-design2`.

**Target:** current BCH (`bch-2026`), one standard transaction of P2SH32 inputs. Each unlocking is ≤ 10,000 B
(the redeem push included). Each input's op cost is ≤ (41 + unlocking length) × 800. The transaction is ≤ 100,000 B.

**Angle (designer 2):** minimize risk and complexity, with the clearest soundness argument and the largest
liveness margin. Bytes come second.

## Result

| configuration | inputs | score (*model*) | worst op margin over 48 proofs, standard / consensus | op (std) |
|---|---|---|---|---|
| **recommended: broadcast hub, 2-part code blob, ≥20% target** | 5 | **47,014 B** | **20.48% / 20.62%** | 29.96M |
| same, ≥15% target | 5 | 44,261 B | 15.56% / 15.69% | 29.96M |
| same, N = 6, ≥25% target (extra-conservative) | 6 | 51,205 B | 25.46% / 25.59% | 30.58M |
| base (every input re-derives the challenges), ≥10% | 5 | 45,434 B | 10.44% / 11.13% | 32.56M |
| base, N = 6, ≥15% | 6 | 50,140 B | 15.46% / 16.05% | 33.93M |

The reference is kallisti's `bch-groth16-bls12381-intratx-fs-fused-coordinator-head`: 60,285 B in 9 inputs,
unreviewed and conditionally qualified. The recommended configuration is 22% smaller with a ≥20% op margin on every
input. Its soundness argument is written out below, with an owner for every accept-relevant value (§4).

Four inputs are infeasible even at a 5% margin. Five inputs reach at most about a 23% margin.

### What is measured and what is modeled

- **Measured in the VM** (libauth 3.1.0-next.8, BCH 2026 instruction set, consensus and standard accounting):
  - The 13 arithmetic kernels, each checked against the reference (`measure.mjs`, `kernels.json`).
  - The whole 64-event Miller/GT-GLS loop as straight-line segments on 57 proofs, checked against the value-level
    mirror at the end of every segment (`proto_worker.mjs`, `chunks.mjs`, `sweep.mjs`).
  - **A real 5-input transaction on the recommended layout** (`proto_skeleton.mjs`): the uniform loader redeem (input
    count, every sibling's locking, the hash-checked 2-part code blob), and per role:
    - the layout pin;
    - the transcript over all inputs by introspection and the challenges;
    - the hub's environment, GT-GLS tables and broadcast check;
    - the consumers' broadcast decode;
    - the handoff decode and the producer's check;
    - the whole terminal: Rconst, Frob(c), the B endpoint, the quotient Horner, **the final identity (it holds in the
      VM)**, the exact GT-GLS binding, and the curve, range and nibble checks.
  - 29 rejection checks (`rejections.mjs`, all as expected).
- **Modeled:**
  - Loop control flow: an allowance of +6k op per event. That is about 2× the measured overhead of role-sized
    segments over chunk sums, which is at most 3.1k per event from blob splits.
  - The size of the all-roles code blob: 7,000 B estimated. The measured role blobs are 1.1–3.95 kB, and the loop
    kernels add about 1.9 kB.
  - Summing the per-role setup and terminal (measured, almost proof-independent) with the per-proof loop chunks.

## 1. The verifier in one paragraph

The design keeps the math of SI-GLS, our reviewed BN254 bch-spec verifier (`chunked/bn254/sound-si-gls`), ported to
BLS12-381, and splits it across 5 identical P2SH32 inputs.

The Miller loops of (−A, B) and (C, δ) and the GT-GLS fold of e(vk_x, γ) are evaluated at ±z only. They are checked
as 33 chunk identities between hash-committed Fp12*/Fp6* class states, batched with ρ and closed by one committed
quotient. A residue root c turns the final exponentiation into the identity [f′] = [c]^(p+|x|). The B walk is
computed on chain and ends in the endpoint ψ(B) = [x]B, which is a G2 membership proof.

Every input has the same locking. The 81-byte redeem checks the input count, checks that every sibling has the same
locking, and loads the shared code from two inputs' witnesses under one SHA-256. Input 0 (the hub) derives the
challenges from a transcript over all inputs and publishes the challenge-dependent values in its witness. It checks
that copy against its own computation, and the other inputs use the copy. Consecutive inputs hand over the B point
and the batch accumulator, and the producer checks them against its successor's witness. Every handoff is an exact
equation.

## 2. Protocol math (BLS SI-GLS)

All constants are recomputed and asserted against noble 2.2.0 at import: `blsmath.mjs` for the facts, `protocol.mjs`
for the VK constants and the identity chain.

### 2.1 Field, class group, notation
- Fp12 = Fp[X]/M(X), with M = X¹² − 2X⁶ + 2 and X = w. The noble tower is u² = −1, v³ = 1 + u, w² = v, so u = X⁶ − 1.
- An Fp2 element a0 + a1u maps to Φ(a) = (a0 − a1) + a1X⁶. It is even, so Fp2* ⊂ Fp6* (the even polynomials).
- G = Fp12*/Fp6* is cyclic of order p⁶+1. Conjugation σ = Frob⁶ is X ↦ −X, and it is inversion in G.
- Frob² is X ↦ ηX for one baked η ∈ Fp (a primitive 6th root, η² = η − 1).
- Frob(X^j) = Φ(γ1^j)X^j, with γ1 = ξ^((p−1)/6) and ξ = 1 + u. Frob(X⁶) = 2 − X⁶.
- A class is committed as a monic degree-6 representative S = X⁶ + Σ_{j<6} s_j X^j (6 words).
- |x| = 0xd201000000010000 (x < 0). p ≡ x (mod r).
- λ = p + |x| = h1·r, where h1 = (x−1)²/3 is the G1 cofactor.
- gcd(λ, (p⁶+1)/r) = 1, 3 ∤ p⁶+1, and (p⁶+1)/r is even. All are asserted.

### 2.2 Statement and Miller schedule
- **Statement:** A, C ∈ E(Fp): y² = x³ + 4; B ∈ E′(Fp2): y² = x³ + 4(1+u); n_0, n_1 ∈ [0, r).
  vk_x = IC0 + n_0·IC1 + n_1·IC2. The fixture key is the bench's synthetic key α=3, β=5, γ=7, δ=11, IC=[2,4,6].
- **Events** e = 0..63, where event e handles bit 63−e of |x|. Bits 63, 62, 60, 57, 48 and 16 are set, so the
  additions are at events {1, 3, 6, 15, 47}.
  - Event 0 is the initialization: F := S_c(−X)·G_0 and T := B. Here [S_c(−X)] = [c⁻¹].
  - Event e ≥ 1: F := F²·L_B,dbl·L_δ; T := 2T. If bit 63−e is set: F := F·L_B,add·L_δ′·S_c(−X); T := T + B.
    Then F := F·G_e.
- **B lines** (P = −A, projective, noble's mul014 slots 1, w², w³): L = Φ(c0) + x_P Φ(c1) X² + y_P Φ(c2) X³.
  - Doubling (noble's formulas scaled by 4): (c0, c1, c2) = (3b′Z² − Y², 3X², −2YZ).
    T′ = (2XY(B−F), (B+F)² − 12E², 4BH), with B = Y², E = 3b′Z², F = 3E, H = 2YZ, and 3b′ = 12 + 12u.
  - Mixed addition with affine B: t0 = Y − y_B Z and t1 = X − x_B Z. The line is (t0 x_B − t1 y_B, −t0, t1),
    and Z′ = Z t1³.
  - Z = 0 is absorbing in both formulas. A doubling at Y = 0 gives Z′ = 8Y³Z = 0, and an addition with T = ±B gives
    t1 = 0. The final check Z ≠ 0 therefore certifies that every step was a valid group operation with a nonzero line.
- **δ lines** (fixed Q = δ, at C): L_δ,j = Φ(c_j) − x_C Φ(λ_j) X² + y_C X³. Here (c_j, λ_j) = (λ_j x_Tj − y_Tj, λ_j)
  are the tangent/chord lines of the fixed δ trajectory: 68 lines, 4 words each (`VKC.lines`, checked against noble's
  point arithmetic). The script evaluates a line in 3 multiplications (`kDBaked`, 33k op). The BN slope recursion
  would cost 79k op for 2 words less data. Since the design is op-bound, baked lines are cheaper.
- The B and δ loops built from these polynomials are asserted to lie in the class of noble's f_{|x|,B}(−A) and
  f_{|x|,δ}(C) (`prove()`).

### 2.3 GT-GLS in base |x| (public inputs)
- |x| ≡ −p (mod r), and σ is inversion on μ_r, so σ∘Frob acts as ^|x| on GT. Since r < |x|⁴, every n ∈ [0, r) is
  n = Σ_{i<4} d_i |x|^i with 0 ≤ d_i < |x| < 2^64.
- **Witness:** for k ∈ {0, 1}, a 64-byte nibble string N_k. Byte e holds bit 63−e of d_{k,0..3} as bits 0..3.
- **Factors:**
  - R_{k,0} = monic rep of m_k = f_{|x|,γ}(IC_{k+1});
  - R_{k,1} = monic rep of σFrob(m_k);
  - R_{k,2}(X) = R_{k,0}(ηX) and R_{k,3}(X) = R_{k,1}(ηX).

  Event e multiplies G_e = Π_k Π_{i ∈ N_k[e]} R_{k,i}. The fold shares the Miller loop's squarings, so
  Π_e G_e^(2^(63−e)) = Π_{k,i} R_{k,i}^(d_{k,i}).
- **Binding (exact integers, no reduction):** Σ_e 2^(63−e)·TB[N_k[e]] = n_k, where TB[m] = Σ_{i∈m} |x|^i.
  - This is simpler than BN's offset-encoded Babai digits: no sign handling and no 2^64 offset.
  - Any digits that satisfy the equation give the right pairing value. Honest digits are canonical (< |x|).

### 2.4 Residue and terminal
- f′ = f_{|x|,B}(−A)·f_{|x|,δ}(C)·m_αβ·m_IC0·Π_{k,i} (σFrob)^i(m_k)^(d_{k,i}).
- FE(f′) = 1 is exactly e(−A,B)·e(α,β)·e(vk_x,γ)·e(C,δ) = 1, because FE(f_{|x|}) = (noble's pairing)⁻¹.
- The prover supplies the class root c with [f′] = [c]^λ (the closed form from SI-GLS).
- The loop accumulates F = f′/(m_αβ m_IC0)·c^(−|x|). So [F·Rconst] = [c]^p = [Frob(c)], where Rconst = monic rep of
  m_αβ·m_IC0.
- The terminal identity uses W = Frob(S_c) = s0 + 2 − X⁶ + Σ_j s_j Φ(γ1^j) X^j. That is one Frobenius, against two
  for BN, and there are no Frobenius lines.

### 2.5 Chunk identities, batching, quotient
- There are 32 chunks of 2 events, and the state S_{k+1} is committed after chunk k (S_0 := S_c(−X)).
- **Chunk identity:** D_k = P_k(X)S_{k+1}(−X) − P_k(−X)S_{k+1}(X), where P_k is the event recursion over the
  chunk's events starting from S_k.
- **Terminal identity:** D_32 = P_fin(X)W(−X) − P_fin(−X)W(X), with P_fin = S_32·Rconst.
- **Accept** iff R = Σ_k ρ^(32−k) D_k(z) ≡ z·q(z²)·M(z) (mod p). The quotient q has a fixed width of 132 odd
  coefficients (X¹..X²⁶³).
- **Degree bound** (structural, adversarial: 8 GLS factors at every event): deg P_k ≤ 270, so deg D_k ≤ 276 and
  132 quotient words suffice. An optional addition-aware chunking (singles at events 4 and 13) gives 33 states and
  120 words, saving 288 B.

## 3. Multi-input architecture

### 3.1 Uniform loader redeem: every input pins every sibling
All N inputs lock to P2SH32(R), with the same R (81 B, measured):

```
OP_TXINPUTCOUNT <N> OP_NUMEQUALVERIFY
OP_0 OP_BEGIN OP_DUP OP_UTXOBYTECODE OP_INPUTINDEX OP_UTXOBYTECODE OP_EQUALVERIFY OP_1ADD OP_DUP <N> OP_NUMEQUAL OP_UNTIL OP_DROP
<h1> OP_INPUTBYTECODE <off1> OP_SPLIT OP_NIP <len1> OP_SPLIT OP_DROP
<h2> OP_INPUTBYTECODE <off2> OP_SPLIT OP_NIP <len2> OP_SPLIT OP_DROP OP_CAT
OP_DUP OP_SHA256 <H_blob> OP_EQUALVERIFY OP_0 OP_DEFINE OP_0 OP_INVOKE
```

- The count check plus "every sibling's locking equals mine" means every input in the transaction runs R. There is
  no hash fixed point, because a sibling is compared with the input's own locking.
- R pins the blob by its SHA-256, so every input runs the same program. That program dispatches on OP_INPUTINDEX,
  so the order is the role assignment.
- The hashed bytes are exactly the defined bytes: one stack item, DUP, hash, define.
- A blob of about 7 kB in a uniform redeem cannot fit: R would be about 7 kB per input, the data would not fit,
  and 11 or more inputs would exceed 100 kB. So code sharing is necessary, not an optimization.
- This is the same mechanism as kallisti's code carriers, here with all-sibling pinning.

### 3.2 Roles and data placement (recommended layout, N = 5)
- **Input 0 is the hub.** It derives the challenges and the challenge-dependent values, checks the broadcast, and
  runs events 0–9.
- **Inputs 1–3** run events 10–23, 24–39 and 40–53.
- **Input 4** runs events 54–63 and then the terminal: Rconst, Frob(c), the endpoint, the quotient, the binding, and
  the curve, range and nibble checks.
- Input boundaries fall on chunk boundaries. An input's F± therefore starts from a committed state's evaluation, so
  only (T, R) cross between inputs.

### 3.3 Witness of input j: one push of fixed size L_j
`W_j = P1_j ‖ Q_j ‖ K_j ‖ IN_j ‖ BC ‖ CB_j ‖ PAD_j`. Every field word is 48-byte little-endian, decoded as
BIN2NUM(w ‖ 0x00) and required to be < p.

| part | content | owner |
|---|---|---|
| P1_0 | STMT (x_A, y_A, x_B.c0, x_B.c1, y_B.c0, y_B.c1, x_C, y_C; n_0, n_1 as 32-B LE) ‖ N_0 ‖ N_1 ‖ s^c_0..5 ‖ input 0's states | transcript (phase 1) |
| P1_j, j ≥ 1 | the closing states S_{k+1} of input j's chunks (6 words each) | transcript (phase 1) |
| Q_j | a slice of WQ = q_131 ‖ … ‖ q_0 (highest first) | transcript (phase 2) |
| K_j | input j's δ lines (c.c0, c.c1, λ.c0, λ.c1) | SHA-256 constant per role in the blob |
| IN_j, j ≥ 1 | T = (X0, X1, Y0, Y1, Z0, Z1) and R after input j−1 | producer j−1: exact equation |
| BC (hub only) | 83 words: z, ρ, z²…z⁶, t = z⁶−1, x_A z²·(1, t, 3, 3t), y_A z³·(1, t), x_C z²·(1, t), y_C z³, c⁻¹(±z), TP_0, TM_0, TP_1, TM_1 (16 each) | the hub: (computed − claimed) mod p = 0 |
| CB_j | blob part (inputs 2 and 4, 3,500 B each) | SHA-256 in R |
| PAD_j | zero bytes (pinned) | — |

Pinning: DEPTH = 1, SIZE(W_j) = L_j (role table), the P2SH unlocking is push-only, and the final stack is [1].

### 3.4 Transcript and challenges (hub)
- h ← SHA256(TAG ‖ U_0[0, 3+|P1_0|]), then h ← SHA256(h ‖ U_j[0, 3+|P1_j|]) for j = 1..N−1. Here U_j is input j's
  unlocking bytecode, read by OP_INPUTBYTECODE. The 3 bytes are W_j's PUSHDATA2 header, fixed by the size check.
- ρ_raw = SHA256(h0 ‖ "rho"). z_raw = SHA256(h0 ‖ ρ_raw ‖ QS), where QS is the 132 quotient words gathered from
  their fixed slices.
- ρ = BIN2NUM(ρ_raw ‖ 0x00) and z = BIN2NUM(z_raw ‖ 0x00). Both are uniform in [0, 2^256) ⊂ [0, p), so no
  reduction or bias is involved. z ≠ 0 is checked.
- Every hashed slice has a fixed length and position, so the chain's input is injective.

### 3.5 Per-input program (all roles, one blob)
1. Loader (R): count, sibling lockings, blob hash, define, invoke.
2. Layout pin: DEPTH and SIZE(W_j).
3. **Hub:**
   - transcript, ρ, z;
   - decode the statement and s^c (range-checked);
   - z powers, the loop environment, η·z powers;
   - GT-GLS tables (8 monic evaluations, 4 subset-product tables) and c⁻¹(±z);
   - check every BC word: (computed − claimed) mod p = 0, claimed < p.

   **Consumers:** decode BC from input 0 (in 8-word pieces), and the statement words they need from input 0's P1
   slice.
4. Check K_j against its SHA-256 constant.
5. Start state: input 0 starts at F± = c⁻¹(±z) and T = (x_B, y_B, 1). Input j ≥ 1 starts at
   F± = S_start(±z), with S_start the last state of P1_{j−1} (introspection, range-checked), and decodes T and R
   from IN_j.
6. Event loop over its events. At each chunk boundary it decodes the next state from P1_j, then
   R ← Rρ + F+·S′(−z) − F−·S′(z) and F± ← S′(±z).
7. **Non-terminal:** read IN_{j+1} from the successor, check (T, R) − decoded ≡ 0 (mod p) word by word.
   **Terminal:**
   - F± ← F±·Rconst(±z), then R ← Rρ + F+·W(−z) − F−·W(z);
   - endpoint X = ψ_x(B)·Z and Y = −ψ_y(B)·Z (mod p), with Z ≠ 0;
   - Horner over QS (each word < p), then R ≡ z·q(z²)·M(z);
   - exact GT-GLS binding;
   - curve checks of A and C, the twist check of B, n_k < r, nibbles ≤ 0x0f.
8. Clean stack: [1].

## 4. Soundness argument (constructive, per the policy)

### 4.1 Owner of every accept-relevant value

| value | owner |
|---|---|
| R (redeem) | P2SH32 hash; every sibling's locking equals the input's own; input count = N |
| code blob | SHA-256 constant in R (hashed item = defined item) |
| δ lines (68 × 4 words) | VK constants (asserted against noble's point arithmetic at build), pinned by a per-role SHA-256 in the blob |
| R_{k,0..1}, Rconst, η, γ1, ψ, b′, p, r, \|x\|^i | blob constants, asserted against noble (`blsmath.mjs`, `protocol.mjs`) |
| A, B, C, n_0, n_1 | hash-committed (P1_0) before ρ; canonical (< p, < r); curve / twist checks; B ∈ G2 by the endpoint equation |
| nibbles N_0, N_1 | hash-committed; ≤ 0x0f; exact integer binding to n_k |
| s^c, states S_1..S_32 | hash-committed before ρ; every word < p where decoded (the hub, and each state's two users) |
| ρ | SHA-256 of h0 (computed by the hub) |
| quotient q (132 words) | hash-committed after ρ, before z (z's preimage); every word < p (Horner) |
| z | SHA-256 of (h0, ρ_raw, QS) (computed by the hub) |
| broadcast (83 words) | exact equation: hub's computed value − claimed ≡ 0 (mod p), claimed < p |
| B trajectory T, line coefficients | computed on chain; handoffs exact (producer checks the successor's IN; the consumer decodes the same canonical words) |
| F±, R | computed on chain (F± from committed states at input boundaries; R by handoff, exact) |
| verdict | exact equation R ≡ z·q(z²)·M(z) (mod p); endpoint; binding |

No prover-supplied evaluation, slope or line value is used anywhere.

### 4.2 From the transaction to one computation
1. **Pinning.** A valid transaction has exactly N inputs, all locked by P2SH32(R). All of them execute R, hence the
   blob with hash H_blob, hence the role program for their index.
2. **Layout.** Each U_j is one push of exactly L_j bytes plus R. Every introspected slice is therefore the intended
   field of the intended input. More importantly, every input reads the same bytes from the same place: the hub
   hashes exactly the bytes the consumers compute with.
3. **Exact copies.** Each copied value equals the value the single computation has at that point:
   - every broadcast word is ≡ (mod p) the hub's computation from the committed data and the challenges;
   - every handoff word is ≡ the producer's computed T or R;
   - all copies are canonical, so the consumer's arithmetic mod p is unchanged.

   By induction over the inputs, the conjunction of the five programs computes exactly the single-input BLS SI-GLS
   check of §2: the same statement, states, challenges, evaluations and final equation. `split.mjs` implements
   that check and agrees with the VM at every handoff and at the end.

### 4.3 Soundness of the single computation (same argument as the reviewed SI-GLS, BLS constants)
- **Identities.** M is even, so D_k ≡ 0 (mod M) ⟺ P_k·σ(S_{k+1}) is even ⟺ [P_k] = [S_{k+1}] in G. This uses that
  every factor is a nonzero polynomial of degree < 12:
  - B and δ lines have c2 ≠ 0 (Z ≠ 0 at the end, y_P ≠ 0 since E(Fp) has odd order);
  - GLS factors, Rconst, S_c and the states are monic.

  Chaining the 32 chunk identities and the terminal identity gives [f′·c^(−|x|)] = [c^p], i.e. [f′] = [c]^λ. Then
  FE(f′) = c^((p¹²−1)·h1) = 1, because f′ = c^λ·w with w ∈ Fp6* and (p⁶−1) | (p¹²−1)/r.
- **GT-GLS.** The same hashed nibbles select the factors and enter the exact equation. So the GT part of FE(f′) is
  Π_k e(IC_{k+1},γ)^(−n_k) with the committed n_k (FE commutes with σ and Frob, and σFrob = ^|x| on μ_r). Then
  FE(f′) = 1 is exactly the Groth16 equation.
- **B.** The walk is computed on chain from the curve-checked B, with no witness. Exceptional steps are absorbing
  (Z = 0) and rejected by Z ≠ 0. So T_end = [|x|]B, and the endpoint gives ψ(B) = [x]B. Then:
  - ψ − [x] has degree p − x = λ, so its kernel has λ points;
  - its intersection with E′(Fp2) has order dividing gcd(λ, #E′(Fp2)) = r, with r ∥ #E′(Fp2) (asserted);
  - hence B ∈ G2.
- **A and C** (curve checks only; G1 has cofactor h1):
  - for every P ∈ E(Fp) the ate value FE(f_{|x|,Q}(P)) is a power of the reduced Tate pairing t(Q, P);
  - t(Q, ·) is trivial on E(Fp)[h1] ⊂ rE(Fp), since gcd(h1, r) = 1;
  - so acceptance implies the Groth16 equation for the G1 projections (A_r, B, C_r): a valid proof of the same
    statement exists;
  - adding h1-torsion to A or C is accepted (malleability, not soundness). This is the same position as the
    reviewed BLS singleton, and `cofactor_check.mjs` checks it numerically with the protocol's own lines.
- **Batching and quotient (adversarial).** All D_k are fixed by h0's preimage and deterministic computation before
  ρ:
  - the B walk is on chain;
  - the δ lines are constants;
  - the GLS factors are constants selected by hashed nibbles;
  - c⁻¹ and the states are hashed.

  If some D_k ≢ 0 (mod M), then Σ ρ^(32−k)(D_k mod M) vanishes for at most 32 values of ρ. Otherwise
  S := Σ ρ^(32−k)(D_k mod M) is a nonzero polynomial of degree < 12. q is hashed before z, and the check is
  (Σ ρ^(32−k) D_k − Q·M)(z) = 0, where the left polynomial is ≡ S (mod M), so it is nonzero, with degree
  ≤ max(276, 263 + 12) = 276.

### 4.4 Encoding, ranges, guards
- Every word is decoded unsigned, BIN2NUM(w ‖ 0x00), so the byte↔value map is bijective. v < p is enforced
  everywhere a word is decoded. n_k is 32-B unsigned, with n_k < r. Nibbles must be ≤ 0x0f.
- Every equality or ≠0 guard tests a reduced quantity:
  - broadcast and handoff checks: (computed − claimed) mod p = 0;
  - endpoint: X − ψ_x Z and Y + ψ_y Z mod p, and (Z0 mod p) ∨ (Z1 mod p);
  - curve checks and the final identity: mod p;
  - z ≠ 0 on z ∈ [0, 2^256);
  - the binding: an equality of nonnegative integers.
- All lengths are fixed: no variable-length push, a fixed-width quotient (no leading-word rule needed), fixed
  transcript slices, a fixed blob and fixed padding.

### 4.5 Soundness error
Per random-oracle query: ≤ (32 + 276)/2^256 ≈ **2^−247.7**. ρ and z are uniform on [0, 2^256), and Schwartz–Zippel
applies on that subset of Fp. With q_H hash queries the bound is q_H·2^−247.7.

### 4.6 Not claimed
- **Witness uniqueness.** The residue root is unique only up to the r-torsion of G (gcd(λ, p⁶+1) = r). GLS digits
  satisfying the exact equation need not be < |x|; a d < |x| check is an optional ~60k op. Neither affects
  acceptance of a false statement, and both need a full re-proof, so neither is third-party malleability.
- **Formal equivalence.** The generated bytecode is not formally proven equivalent to the formulas. This is tested
  instead, as for SI-GLS: kernel-by-kernel against the reference, end-to-end segments against the mirror, and the
  VM final identity.

## 5. Layout: bytes and op per input (recommended, *model* from VM-measured parts)

| input | role | events | chunks / states | P1 (transcript) | Q | δ consts | IN | broadcast | blob part | pad | witness W_j | unlocking | budget | op cons / std | margin cons / std |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 0 | hub + events | 0–9 (10) | 5 | 2304 | 0 | 2304 (12 lines) | 0 | 3984 | 0 | 593 | 9185 | 9272 | 7.450M | 5.913M / 5.960M | 20.6% / 20.0% |
| 1 | events | 10–23 (14) | 7 | 2016 | 3888 (81 w) | 2880 (15 lines) | 336 | 0 | 0 | 9 | 9129 | 9216 | 7.406M | 5.914M / 5.924M | 20.1% / 20.0% |
| 2 | events | 24–39 (16) | 8 | 2304 | 0 | 3072 (16 lines) | 336 | 0 | 3500 | 440 | 9652 | 9739 | 7.824M | 6.249M / 6.259M | 20.1% / 20.0% |
| 3 | events | 40–53 (14) | 7 | 2016 | 2448 (51 w) | 2880 (15 lines) | 336 | 0 | 0 | 1449 | 9129 | 9216 | 7.406M | 5.914M / 5.924M | 20.1% / 20.0% |
| 4 | terminal + events | 54–63 (10) | 5 | 1440 | 0 | 1920 (10 lines) | 336 | 0 | 3500 | 1878 | 9074 | 9161 | 7.362M | 5.879M / 5.889M | 20.1% / 20.0% |
| total | | 64 | 32 | 10,080 | 6,336 | 13,056 | 1,344 | 3,984 | 7,000 | 4,369 | 46,169 | 46,604 | | 29.87M / 29.96M | |

**Score 47,014 B** = 46,604 unlocking + 5 × 35 B P2SH32 lockings + 235 B transaction framing.
- The transaction is about 47 kB, under the 100 kB standard limit.
- The largest unlocking is 9,739 B.
- The redeem is 81 B measured (the model counts 83).
- The skeleton's stack peaks at 127 items / 33 kB (terminal role, measured). The loop's state adds about 20
  items, far below the 1,000-item limit.

Where the op goes (standard, *measured*):
- **Hub setup 1.615M:** transcript 196k, statement 61k, environment 136k, tables 632k, broadcast check 366k, plus
  loader, pin and cleanup.
- **Consumer setup 0.58M:** broadcast decode 209–227k, plus the statement, start state, handoff, loader and cleanup.
- **Terminal 1.69M:** Rconst / Frob / endpoint 344k, Horner over 132 words 985k, binding 271k, checks 94k.
- **Event loop 21.93–23.45M:** about 345k per regular event, and +366k per addition (worst proof).
- Per-kernel costs:
  - B doubling 246k; B mixed addition 329k; baked δ line 33k (slope recursion 79k);
  - monic evaluation at ±x 28k; 16-entry table 93k; GT-GLS step 15k per sign;
  - boundary 15k; 4-word Horner step 18.7k; decode 1.5k per word.

The ≥15% layout (44,261 B) runs events 0–9 / 10–19 / 20–35 / 36–51 / 52–63, with 1,616 B of padding (table
generated by `node layout_table.mjs layout-rec15.json`).

## 6. Liveness
- Op cost is nearly witness-independent: every push has a fixed size and every operand has a fixed width.
  - GT-GLS lookups cost the same for every table index. A zero nibble selects the entry 1 and is cheaper.
  - The loop over 57 proofs ranges from 21.93M (n = 0: every nibble 0) to 23.45M (forced: every nibble nonzero).
  - Random proofs fall within 0.3% of the forced maximum.
- The per-input budget is fixed, because every unlocking has a fixed length.
- **Sweep:** 48 proofs (`sweep.mjs`), of which 42 are random and 6 are forced or edge cases:
  - every GLS nibble nonzero, for two B values;
  - n = 0 and n = r−1;
  - n = (1, 2^64);
  - B = G2 with C = G1.

  Every proof's chunks run end-to-end in the VM with its own challenges.
  - **Worst margin on the recommended layout: 20.48% standard / 20.62% consensus.** The mean is 20.77%.
  - The ≥15% layout: worst 15.56%.
  - The layouts are sized from the per-chunk maximum over all 57 measured proofs, +1%.
- **Headroom against model error.** A 5% op overrun in the build still leaves ≥15%. Rebalancing (moving a chunk, or
  re-sizing padding) is cheap. The extra-conservative N = 6 layout gives ≥25% for +4.2 kB.
- **Consensus vs standard** differ only in hash cost (about 0.05M at the hub).

## 7. Rejection tests (ordinary negative tests, `rejections.mjs`, recommended layout)
29/29 as expected, in standard and consensus mode:
- all 5 honest inputs are accepted;
- each of the following is rejected by the input that owns the check:
  - a 6th input; a sibling with a foreign locking; swapped inputs;
  - a 1-byte-longer witness; an extra push;
  - either blob part tampered; a δ constant tampered;
  - a state, statement, quotient, nibble or s^c byte tampered: the transcript changes and the hub's broadcast check
    fails;
  - broadcast words z, ρ, c⁻¹, a TP entry and a TM entry changed, or aliased by +p;
  - a handoff T or R word changed (the producer's check fails) or aliased by +p (the consumer's decode fails);
  - n_0 + 1 (the terminal's binding fails);
  - a quotient word changed (the terminal's final identity fails).

## 8. Relation to kallisti's fused-coordinator design (PR #24, 60,285 B / 9 inputs)
Read from `chunked/bls12-381/README.md` and the bench entry's header only.
- **Shared ideas:**
  - the Fp12*/Fp6* residue with λ = p + |x| (gcd(λ, p⁶+1) = r);
  - a Fiat–Shamir polynomial identity check with a committed quotient;
  - code loaded from other inputs by introspection ("carriers");
  - a coordinator that derives values the others use.
- **Different here:**
  - **Pinning:** every input pins every sibling through the identical locking. kallisti's root pins an ordered
    worker commitment and the workers pin forward.
  - **Prover inputs:** no prover-chosen evaluation, slope or density padding map. Every line and evaluation is
    computed on chain, and every witness value has an owner (§4.1).
  - **Public inputs:** bound by GT-GLS in base |x| with an exact integer equation, instead of an on-chain vk_x MSM.
  - **Layout and liveness:** a fixed-width layout (fixed quotient, fixed slices), with a ≥20% op margin and an
    almost proof-independent op cost.
- Their entry states its results are corpus evidence, not a universal resource or soundness claim. This design
  states its argument and its error bound (§4).

## 9. Risks, open questions, build plan
- **Model vs build.**
  - The loop's control flow is an allowance (6k per event), not measured: the measured segments are straight-line.
  - The all-roles blob size is estimated at 7,000 B. If it grows past the two 3,500 B slots, a 3rd part costs about
    +0.2 kB (`node model.mjs 5 0.20 bcast 3`: 47,249 B).
  - Mitigation: the 20% target. The build must re-measure every input on the built artifact and keep ≥15% at the
    worst sweep witness.
- **Formula correctness is tested, not proved** (as for SI-GLS). Mitigations: kernels against the reference,
  segments against the mirror, the VM final identity, and noble assertions for every constant.
- **Public-input binding by GT-GLS** instead of vk_x is the same decision the owner accepted for SI-GLS BN. An
  on-chain vk_x variant would add a third Miller pair with fixed γ lines: either baked (+2.2M op and 13 kB) or as
  slopes (+5.4M op and 6.5 kB). It would also need the G1 MSM (about 4–8M op). That is roughly +1–2 inputs and
  +12–20 kB.
- **G1 cofactor.** A and C are curve-checked only; this is malleability, not soundness (§4.3). Full G1 checks would
  cost about 20M op and 2–3 inputs.
- **Optional byte savings** (each re-measured):
  - addition-aware chunking: −0.3 kB;
  - reduced kernel outputs, so the hub compares with NUMEQUAL instead of a MOD per word: about −0.25M at the hub;
  - an affine B walk with exact-equation slopes is not worth it: the design is near the byte/op balance, so it
    would trade about 6 kB of slopes for about 6M op.
- **Coordination with bls-si-gls-spec.** This design is the same BLS SI-GLS math. `blsmath.mjs` and `protocol.mjs`
  (identity chain checked against noble) can serve both tracks. The bch-spec single input is the same computation
  without the split, at about 10,000 + op/800 bytes.
- **Cross-check with the bls-si-gls-spec track** (`work/bls-si-gls-spec`, M1 prototype): it makes the same
  choices: λ = p + |x|, the base-|x| GT-GLS with an exact binding, ψ(B) = [x]B, and the same synthetic VK.
  - Its single-input bch-spec build measures 26.23M op standard. The same computation here is
    23.45M (loop) + about 1.3M (setup) + about 1.7M (terminal) ≈ 26.4M, an independent check of the cost basis.
  - That track folds Rconst into the loop's initial value; adopting it saves the terminal's Rconst evaluation
    (about 30k).
  - **Build rule from that track:** skipped IF branches still cost 100 op per instruction. Role dispatch must
    therefore be `OP_INPUTINDEX <base> OP_ADD OP_INVOKE` over role functions, never an IF ladder: an IF ladder
    over a 7 kB blob would charge each input for the other roles' code. The addition branch of the event loop must
    likewise be a function invocation. The measured prototypes here are straight-line and contain no IF.
- **Build plan:**
  1. Assemble the all-roles blob with the sound-si-gls assembler (loop with a fixed-point layout, bound kernel
     functions, hierarchical blob splits).
  2. Export intratx vectors: 5 steps sharing one inputs array. For the bench public-input gate, n_0 and n_1 are at
     input 0, push 0, offsets 384 and 416, encoding le32.
  3. Gates, red-team, and a ≥400-proof liveness sweep on the built artifact, including the forced witnesses.
  4. Independent review.

## 10. Files and reproduce
Run from this directory in the groth16_cashscript worktree (dependencies from the repository's `node_modules`).

```sh
node -e "import('./blsmath.mjs')"          # facts and constants against noble (throws on any mismatch)
node measure.mjs kernels.json               # 13 kernels in the VM, checked against the reference
node proto_worker.mjs 2 18 1                # one event segment end-to-end, checked against the mirror
node chunks.mjs 6 chunk-costs-9.json        # per-chunk costs, 9 proofs
for i in $(seq 0 11); do node sweep.mjs measure $((i*4)) 4 sweep/chunks-$i.json & done; wait   # 48 proofs
node sweep.mjs merge chunk-costs-9.json sweep/chunks-*.json        # -> chunk-costs.json (57 proofs)
node model.mjs 5 0.20 bcast 2 --json layout-rec.json               # the recommended layout (47,014 B)
node layout_table.mjs layout-rec.json
node proto_skeleton.mjs layout-rec.json 3   # the real 5-input transaction, every role (final identity in the VM)
node rejections.mjs layout-rec.json 3       # 29 rejection checks
node sweep.mjs margins sweep/chunks-*.json -- layout-rec.json layout-rec15.json layout-n6-25.json
node cofactor_check.mjs
```

| file | content |
|---|---|
| `blsmath.mjs` | tower ↔ polynomial map, η, Frobenius, ψ, lines, residue / G2 / cofactor facts, base-\|x\| digits |
| `protocol.mjs` | VK constants (δ lines, GLS reps, Rconst), event schedule, honest prover (identity chain checked against noble), degree bound |
| `split.mjs` | multi-input value-level protocol: witnesses, transcript, broadcast, handoffs, conjunction |
| `asm.mjs`, `kernels.mjs` | scheduling assembler (sound-si-gls's, field-parametrized) and the BLS kernels |
| `measure.mjs`, `proto_worker.mjs`, `chunks.mjs` | kernel and loop measurements in the VM |
| `proto_skeleton.mjs`, `rejections.mjs` | the 5-input VM skeleton (loader, roles, terminal) and the rejection checks |
| `model.mjs`, `layout_table.mjs`, `sweep.mjs` | layout search, tables, liveness sweep |
| `kernels.json`, `chunk-costs*.json`, `skeleton.json`, `layout-*.json`, `sweep/`, `sweep-summary.json`, `rejections.json`, `skeleton-runs.json` | measured data and generated layouts |
| `cofactor_check.mjs` | numeric check of the G1-cofactor claim |

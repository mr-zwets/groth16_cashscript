# BLS12-381 Groth16 on current BCH (bch-2026): sound multi-input SI-GLS (design 1, minimum bytes)

**Status:** design record with VM-measured prototypes. It is **not** a verifier and **not** a bench entry. Every
op figure below comes from a kernel or input section run in the libauth VM, except the items marked EST in
`prototypes/layout.mjs`. The protocol has been run end to end at value level, and the pieces below run on the VM
with checked outputs: a Miller input's whole range (setup, events, boundaries, terminal), the head's own work,
and the multi-input loader/pinning glue (in a real bch-2026 standard transaction).

**Target (bch-2026, standard, one transaction):**
- P2SH32 inputs; per input, unlocking ≤ 10,000 B and op ≤ (41 + unlockingLen) × 800;
- transaction ≤ 100,000 B;
- score = Σ (locking + unlocking) + tx overhead = Σ U_i + 78·n + 20.

## Result

| variant | inputs | score (fixture 0) | min. std op margin per input | notes |
|---|---|---|---|---|
| **all-affine B walk (recommended)** | 4 | **≈ 33,900 B** | 4.8% | one kernel family; worst cases swept in the model |
| mixed (affine, projective from event 56) | 4 | ≈ 33,550 B | 1.5% | adds the projective kernel (+400 B code) |
| reference: kallisti fs-fused-coordinator-head | 9 | 60,285 B | (finite corpus) | unreviewed, conditionally qualified |

- Uncertainty is about ±0.7 kB. It comes from the estimated shared-program size (5.3 kB ± 1 kB moves the score by
  about ±0.6 kB) and the loop-control glue (4k op per event; at 8k the score is +0.23 kB).
- Measured lazy-reduction kernels (−0.57M op, about −0.3 kB) are not counted.
- Typical statements carry a longer quotient than fixture 0: median n_q is 96 words instead of 70, so the
  unlocking is about 1.25 kB larger. The score is measured on fixture 0, like every other entry.
- Why it is small:
  1. One quotient for all 32 chunk identities.
  2. The verifier code exists once in the transaction: every redeem is a 53-byte loader.
  3. Data lives wherever the op budget needs bytes (introspection reads cost 3 op per byte).
  4. The B walk uses witnessed affine slopes, which save 80k op per doubling for 96 B.
- The transaction is op-bound and byte-bound at the same time: Σ bytes ≈ Σ op / 800.

## Protocol

### Mathematics (BLS-specific; all asserted against noble in `prototypes/math.mjs`)

- Fp12 = Fp[X]/M(X), with M = X¹² − 2X⁶ + 2.
  - X = w in noble's tower (u² = −1, v³ = 1 + u, w² = v), so u = X⁶ − 1 and Φ(a₀ + a₁u) = (a₀ − a₁) + a₁X⁶.
  - The map is a ring isomorphism (asserted).
- Conjugation σ = Frob⁶ is X ↦ −X; Frob² is X ↦ ηX for one baked primitive 6th root η (η² = η − 1).
- The classes of G = Fp12*/Fp6* (cyclic, order p⁶+1) are represented by monic degree-6 polynomials.
  - [P] = [S] ⟺ P(X)S(−X) − P(−X)S(X) ≡ 0 (mod M), for nonzero P, S.
- Miller loop: binary |x|, x = −0xd201000000010000.
  - Events e = 1..63 (each a doubling); additions at e ∈ {1, 3, 6, 15, 47}.
  - Pairs: (P₀, Q₀) = (−A, B) with B runtime, and (P₁, Q₁) = (C, δ) with δ fixed.
  - M-type line: L(X) = Φ(c₀) + x_P Φ(c₁) X² + y_P Φ(c₂) X³.
  - Our line product equals noble's Miller value up to Fp6 (asserted).
- Residue: λ = p − x = p + |x| = m·r, with gcd(λ/r, (p⁶+1)/r) = 1 (asserted). [f′] = [c]^λ ⟹ FE(f′) = 1.
- G2 criterion: ψ(B) = [x]B.
  - deg(ψ − [x]) = p − x is coprime to the twist cofactor h₂ (asserted, h₂ = noble's), and r ∤ h₂.
  - So the endpoint [|x|]B = −ψ(B) puts B in G2.
- GT-GLS: Frobenius acts on μ_r as p ≡ x (mod r), so π_i = x^i mod r.
  - Lattice basis rows (−x,1,0,0), (0,−x,1,0), (0,0,−x,1), (−1,0,1,−x); index r (asserted).
  - Babai gives |e_{k,i}| < 2⁶³, so u = e + 2⁶³ ∈ [0, 2⁶⁴): 64 bits, one per GLS position g = 0..63.
  - Position 0 is the initial factor; position g ≥ 1 is folded after event g.
  - The constant offset is folded into Rconst and into the binding.

### Witness, regions, transcript

Statement in the head's commit region:

| field | size | encoding |
|---|---|---|
| x_A, y_A, x_B.c0, x_B.c1, y_B.c0, y_B.c1, x_C, y_C | 8 × 48 B | unsigned LE |
| n₀, n₁ | 2 × 32 B | unsigned LE |
| N₀, N₁ | 2 × 64 B | nibble strings; bit i of N_k[g] = bit 63−g of u_{k,i} |
| s^c (residue root, monic representative) | 6 × 48 B | unsigned LE |

Total: 864 B.

Per Miller input, in its commit region:
- the states that end its chunks (6 × 48 B each);
- the B-walk slopes of its events (2 × 48 B each, one per doubling and one per addition).

Chunking:
- chunk 0 = event {1}, starting from S_c(−X)·G₀;
- chunk j ≥ 1 = events {2j, 2j+1};
- states S₁..S₃₁ (8,928 B);
- chunk 31 is multiplied by Rconst and compared with W = Frob(S_c), so the terminal is merged and needs no extra state.

Quotient WQ (in the head, its own push): the odd coefficients q_{n−1}..q₀ as 48-byte unsigned LE words.
- 70 ≤ n ≤ 127, and the size is a multiple of 48.
- Canonical form: either n = 70 (left-padded with zero words if the true length is shorter), or the leading word is ≠ 0.
- 127 is the structural cap: NQ_MAX for all-affine, from the worst chunk {6,7}.

Transcript, with fixed arity and fixed-size regions, hence injective:
- h₀ = SHA256(TAG ‖ SHA256(region₀) ‖ … ‖ SHA256(region₃));
- ρ_raw = SHA256(h₀ ‖ "rho"), ρ = int(ρ_raw);
- z_raw = SHA256(h₀ ‖ ρ_raw ‖ WQ), z = int(z_raw);
- z ≠ 0 is required.

Since 2²⁵⁶ < p, z and ρ are uniform 256-bit integers and are already reduced.

### Programs and pinning (validated on bch-2026 in `prototypes/glue.mjs`)

- **Redeem of input i:** `<K> <i> LOADER` (53 B; LOADER is 19 B).
  - LOADER reads the program blob from the carrier input's unlocking (OP_INPUTBYTECODE, fixed offset), requires
    SHA256(blob) = K, then OP_DEFINEs and invokes it.
  - The shared program P (about 5.3 kB) contains every kernel, every role, the VK constants used everywhere
    (R_{k,i}, η, p, r, x_δ, y_δ) and one hash K_const_i per input for that input's constant block.
- **Pinning, run by P in every input:**
  - OP_TXINPUTCOUNT = 4;
  - for every j: OP_UTXOBYTECODE(j) = P2SH32(`<K> <j> LOADER`), rebuilt from K (on the stack) and the LOADER bytes baked in P;
  - this fixes the input count, order and code of every input, with no hash fixed point (K = H(P), and P contains no hash of a redeem);
  - in the glue test, a reordered transaction and a tampered blob are rejected.
- **Push layout:** P checks DEPTH and the exact SIZE of every push of its own input (consensus already forces
  push-only, minimal encodings), so every field sits at a fixed offset in every unlocking. Clean stack at the end.
- **Relocated data:** a block that one input uses may sit in another input's unlocking, as a fixed-size pinned
  push; the user reads it by introspection at a fixed offset.
  - Committed data is hashed by the head from the same physical bytes.
  - Constant blocks are hash-checked against K_const_i.

### Input roles

**Head (input 0)**, in addition to its own Miller chunks:
1. Pins; reads every sibling's unlocking; hashes the four commit regions and WQ.
   - Derives ρ and z; requires z ≠ 0.
   - Enforces the WQ rules (size, cap, canonical leading word or exact N_MIN).
2. Claims: its claim push holds z̃ and ρ̃ (48-byte canonical LE).
   - The head requires NUM2BIN(z, 48) = z̃ and NUM2BIN(ρ, 48) = ρ̃ (byte equality).
3. Statement checks:
   - every coordinate and s^c word is unsigned < p, and n_k < r;
   - N & 0x0f…0f = N;
   - y_A² = x_A³ + 4 and y_C² = x_C³ + 4;
   - y_B² = x_B³ + 4(1+u). All guards test reduced values (`(a − b) mod p`).
4. GT-GLS binding over the integers: acc_k = Σ_g 2^{63−g} TB[N_k[g]], with TB[n] = Σ_{i∈n} π_i.
   - π_i is derived on-chain from p mod r.
   - Requires (acc_k − 2⁶³Σπ_i − n_k) mod r = 0.
5. Horner: Q(z) = z·q(z²), every word unsigned < p.
6. Final: Σ_i ρ^{32 − j₁(i)} R̃_i ≡ z·q(z²)·M(z) (mod p), with R̃_i read from input i.

**Miller input i**, owning chunks [j₀, j₁):
1. Pins; loads its constant block and checks it against K_const_i.
   - The block holds the δ-walk start state (x_j, c_{j−1}, λ_{j−1}) and the δ slopes of its steps.
   - The terminal input's block also holds Rconst, the ψ constants and the Frobenius constants.
2. Reads from the head: z̃, ρ̃, the statement, s^c, and its nibble slice.
   - If j₀ > 0, it also reads the start state S_{j₀} (committed, from the predecessor's region) and the start point T̃.
3. Setup:
   - z powers and the line environment;
   - GLS tables TP_k[n] = Π_{i∈n} R_{k,i}(z) and TM_k at −z, with R_{k,2/3}(X) = R_{k,0/1}(ηX);
   - S_c(±z).
4. Per event e:
   - F± ← F±²·L_B(±z), with the slope witness λ decoded unsigned < p and checked by 2yλ = 3x²;
   - affine doubling, with c = λx − y and line (c, −λ, 1);
   - δ step (baked slope, on-chain recursion);
   - if e is an addition: affine addition with λ(x_B − x) = y_B − y and the guard x_B ≠ x (reduced); F± ·= S_c(∓z);
   - GLS lookups F± ·= TP/TM₀[N₀[e]]·TP/TM₁[N₁[e]].
5. At each chunk end: decode the next state, unsigned < p; R ← Rρ + F₊S(−z) − F₋S(z); F± ← S(±z).
6. If it owns chunk 31:
   - F± ·= Rconst(±z), then compare against W = Frob(S_c);
   - endpoint check (x_T, y_T) = −ψ(B) (affine, exact).
7. Claims: R̃_i (its partial sum) and, unless it is the last input, T̃_i (the affine end point).
   - Both are required to equal the computed values (canonical bytes).

## Soundness argument (constructive, per the policy)

**Owner of every accept-relevant value:**

| value | owner |
|---|---|
| A, B, C, n₀, n₁, N₀, N₁, s^c, S₁..S₃₁, B slopes | hash-committed in h₀ (fixed-width regions, fixed arity) before ρ and z; decoded unsigned with range checks |
| WQ | hash-committed before z; canonical length rule; words < p |
| ρ, z | computed on-chain from the transcript (head); reaches the workers as z̃, ρ̃, fixed by exact byte equality in the head |
| B-walk points T_j | computed on-chain from B and the slopes; every slope fixed by an exact field equation |
| line coefficients | computed on-chain (B) or VK constants (δ slopes, noble-checked at build) with an on-chain recursion |
| GLS factors R_{k,i}, Rconst, η, ψ and Frobenius constants | VK/curve constants, noble-checked at build |
| partial sums R̃_i | post-challenge; fixed by exact equality with the on-chain value in input i |
| T̃_i (handoff) | fixed by exact equality with the producer's computed point; the consumer starts from the same bytes |
| sibling code, count, order | introspection pins in every input |
| program bytes | SHA256 = K (loader) |
| constant blocks | SHA256 = K_const_i |

No value at z is supplied by the prover.

**B binding.**
- Doubling: if y = 0, the equation 2yλ = 3x² forces x = 0, and (0, 0) is not on E′ (b′ ≠ 0). So a valid slope
  forces y ≠ 0 and λ is unique.
- Addition: the guard x_B ≠ x makes λ unique.
- So every T_j = [k_j]B exactly, never O, and handoffs are exact equalities.
- The last input's check T₆₃ = [|x|]B = −ψ(B) gives B ∈ G2 (gcd(p − x, h₂) = 1, r ∤ h₂).

**Nonzero factors.**
- Affine lines have y_P·X³ with y_P ≠ 0: A and C are on E(Fp), whose order is odd (h₁ odd), so no 2-torsion.
- So each line is a nonzero polynomial of degree < 12. R_{k,i}, S_c, the states and Rconst are monic.
- W = Frob(S_c) ≠ 0.
- In the mixed variant, projective lines are nonzero because Z = 0 is absorbing and Z_T ≠ 0 is checked, as in the BN build.

**Identities.**
- For each chunk j, P_j is the product of the committed or computed factors (squared along the chunk), and
  D_j = P_j(X)W_j(−X) − P_j(−X)W_j(X), with W_j = S_{j+1} or Frob(S_c).
- All D_j are fixed polynomials determined by the region bytes before ρ.
- If every D_j ≡ 0 (mod M), the chain gives [S_c(−X)·G₀·Π(lines·G)·c-factors·Rconst] = [Frob(S_c)], hence
  [f′] = [c]^{p+|x|} = [c]^λ and FE(f′) = 1.

**GLS and Groth16.**
- FE(Frob^i(m)) = FE(m)^{π_i}. The binding is exact mod r and uses the same nibble bytes that select the factors.
- So the GLS part is e(vk_x, γ)^{−1} with vk_x = IC₀ + n₀IC₁ + n₁IC₂.
- FE(f′) = e(A,B)·e(C,δ)^{−1}·e(α,β)^{−1}·e(vk_x,γ)^{−1} = 1, which is the Groth16 equation. The signs are checked by
  the prover asserting FE = 1 for valid proofs and rejecting tampered ones.
- A and C are only curve-checked, as the policy asks. The pairing on E(Fp) × G2 factors through G1, so cofactor
  components are malleability, not a different statement. This matches the BLS singleton review.

**Batching (Schwartz–Zippel).**
- If some D_j mod M ≠ 0, then Σ ρ^{31−j}(D_j mod M) = 0 with probability ≤ 32/2²⁵⁶ over ρ.
- Otherwise S := Σρ^{31−j}(D_j mod M) is a nonzero polynomial of degree < 12, so S − (Q − Q*)M ≠ 0 (M does not divide a
  nonzero polynomial of degree < 12), with degree ≤ max(deg D, 2·127 + 12) ≤ 276.
- Q is committed before z, so this vanishes at z with probability ≤ 276/2²⁵⁶.
- Total ε ≤ 308/2²⁵⁶ ≈ 2^−247.7 per random-oracle query. Since 2²⁵⁶ < p there is no bias factor.
- The partial sums are only a re-association: Σ_i ρ^{32−j₁(i)}R̃_i = Σ_j ρ^{31−j}D_j(z) exactly, given the R̃ equalities.

**Multi-input.**
- Every input pins count, order and code, and its own push sizes.
- Every cross-input value is either:
  - a committed field at a fixed offset, hashed from the same physical bytes;
  - a hash-checked constant;
  - or a post-challenge claim fixed by exact equality in its pinned producer.
- A valid transaction therefore executes exactly the computation above.

## Liveness (worst cases, standard and consensus mode)

Op is data-independent except:
- the GLS lookups: dense nibbles cost 34.2k per event, measured in `worst.mjs` (fixture 0 ≈ 10k); the model uses 34.2k on every event;
- the head's Horner and WQ size, which are linear in n_q: n_q = 70 (N_MIN) has the smallest budget, n_q = 127 the largest unlocking.

Both extremes are modeled. With all-affine, the margins in standard mode (tighter than consensus by the hashing surcharge) are:

| case | in0 | in1 | in2 | in3 |
|---|---|---|---|---|
| n_q = 70 (fixture 0 / N_MIN) | 4.8% | 5.1% | 4.9% | 6.9% |
| n_q = 127 | in0 U = 9,329 ≤ 10,000; 1.98M | 272k | 380k | 542k |

Honest completeness:
- G2 has odd order, so honest slopes always exist;
- additions never hit x_T = x_B, since the prefixes k at additions are in [2, r−1);
- monic representatives fail only with probability ~31/p, and n_q ≤ 127 is structural.

A build must re-sweep: dense nibbles at n_q = 70 (forced), all-15 nibbles (n_q = 127), random B, and fixture 0.

## Input layout (all-affine, n = 4, fixture 0; `prototypes/layout-n4-affine-5pct.txt`)

| input | role / chunks (events) | unlocking U (B) | natural bytes | op std (cons) | budget | margin |
|---|---|---|---|---|---|---|
| in0 | head + chunks 0–3 (events 1–7, adds 1, 3, 6) | 6,593 (gives 1,106 to in2) | WQ 3,363 · claims 98 · statement 864 · 4 states 1,152 · 10 slopes 960 · δ consts 960 · R̃ 48 · T̃ 192 · redeem 54 · headers 8 | 5.05M (5.01M) | 5.31M | 4.8% |
| in1 | chunks 4–10 (events 8–21, add 15) | 7,098 (holds 1,900) | 7 states 2,016 · 15 slopes 1,440 · δ 1,440 · R̃ · T̃ · redeem | 5.42M (5.41M) | 5.71M | 5.1% |
| in2 | chunks 11–21 (events 22–43) | 9,923 (holds 2,229) | 11 states 3,168 · 22 slopes 2,112 · δ 2,112 · R̃ · T̃ · redeem | 7.58M (7.57M) | 7.97M | 4.9% |
| in3 | chunks 22–31 + terminal (events 44–63, add 47); program carrier | 9,973 (gives 3,023 to in1/in2) | program 5,300 · 9 states 2,592 · 21 slopes 2,016 · δ 2,016 · terminal consts 960 · R̃ 48 · redeem 54 | 7.46M (7.44M) | 8.01M | 6.9% |
| **total** | | **33,587** + 4 × (35 + 43) + 20 = **33,919** | | 25.5M | | |

Op composition per Miller input (in2, 22 events):
- setup 0.81M (GLS tables 0.63M);
- B doublings 3.36M; δ steps 1.77M; GLS 0.75M; boundaries 0.63M; loop glue 0.09M;
- reads, loader and pins 0.14M.

Head extras:
- binding 0.32M, Horner 0.58M, transcript and statement 0.19M, final 0.10M;
- sibling reads 0.08M.

## Measured kernels (BLS12-381, 48-byte limbs; `prototypes/kernels.json`, `worker.mjs`, `head.mjs`)

| kernel / section | op | code |
|---|---|---|
| affine doubling, witnessed slope (+ decode) | 148,159 (152.8k in loop) | 262 B |
| projective doubling + line + F² | 233,993 (232.5k in loop) | 423 B |
| affine addition, witnessed slope | 147,866 (154.3k in loop) | 282 B |
| projective mixed addition | 329,561 | 585 B |
| δ step (slope bake + recursion) / fully baked line | 78,448 (80.6k in loop) / 32,752 | 147 / 47 B |
| GLS fold per event (dense / zero nibbles) | 34.2k / 10.4k | |
| chunk boundary (decode 6 words, EV, R update) | 57k | |
| monic EV at ±x / 16-entry product table | 28,256 / 92,180 | 46 / 111 B |
| per-input setup: env 117k, tables 630k, S_c 31k, start 35k | 813k | |
| terminal (Rconst, W, R) / affine endpoint / projective endpoint | 176k / 45k / 98k | |
| head: transcript 67k, statement 33k, curves 91k, binding 319k, Horner 8k per word, final 98k | 1.17M at n_q = 70 | |
| lazy variants (not counted): doubling −3.8k, δ step −4.9k | | |

## Design choices and alternatives (exchange rates in op saved per byte added)

At balance a knob pays off only if its rate beats the knob it displaces (affine ↔ projective doubling: about 830).

| choice | op/B rate | verdict |
|---|---|---|
| affine additions vs projective | 182k / 96 B ≈ 1,900 | used |
| affine doublings vs projective | 80k / 96 B ≈ 830 | the balancing knob; all-affine at 5% margin |
| baked δ slopes vs on-chain projective δ walk | 152k / 96 B ≈ 1,600 | slopes baked |
| fully baked δ lines (λ, c) vs slope + recursion | 46k / 96 B ≈ 480 | not used |
| head-claimed GLS tables (2.9 kB) vs per-input build | about 830 | not used (neutral) |
| shared program loaded by OP_DEFINE vs code per input | about 8 | always: about −16 kB |
| chunks of 2 vs 3 events | 3-event chunks: Q +4–6 kB, states −2.9 kB; worst Q > 10 kB | 2 events |
| n = 4 vs 5 inputs | n = 5 pays one more setup (0.81M) + 78 B | n = 4 (33.9k vs 34.3k) |

The byte cap per input makes n = 3 impossible (needs ≥ 33 kB of bytes).

## Open risks

1. **Estimated program size** (5.3 kB). It is not compiled as a whole; the kernels and head code are measured
   separately. ±1 kB moves the score by about ±0.6 kB.
2. **Loop control.** The prototypes are straight-line with inlined kernels. The real loop (schedule string, bound
   functions) is modeled at +4k op per event (SI-GLS BN measures about 4k). A build must re-measure.
3. **Relocation layout.** The model moves 1.1–3.0 kB blocks between inputs, with read costs charged
   conservatively. The exact block placement is a build decision, and the head's WQ stays in place.
4. **Formula correctness is tested, not proven**, as in the BN build:
   - the value-level prover/verifier agrees with noble (FE = 1, divisibility of every identity);
   - the VM runs reproduce the reference partial sums and the head's acceptance.
5. **Public-input binding through GT-GLS** (exact mod r, as in the reviewed BN entry) rather than an explicit vk_x MSM.
   The owner has accepted this for sound-si-gls.
6. **N_MIN = 70 canonical padding** is a new encoding rule. It must be reviewed with the transcript rules: the
   length is fixed or the leading word is nonzero, so the encoding is injective.

## Reproduce (from the repository root, after `pnpm install`; Node ≥ 22)

```sh
cd research/sound-sz-bls12381-native/prototypes
node math.mjs                 # asserts every BLS constant and fact against noble
node measure.mjs              # kernels -> kernels.json (VM, checked against formulas)
node test-protocol.mjs        # prover + split verifier, rejections
node worker.mjs 4 12 aff      # a Miller input's range on the VM (R_i == reference); also 0 4 / 24 32 / 23 32 55
node worst.mjs                # dense-nibble GLS worst case
node head.mjs                 # head on the VM (accepts)
node glue.mjs                 # 4-input bch-2026 standard tx: loader, OP_DEFINE, pins, negative cases
node nq-dist.mjs              # quotient length distribution
NS=4 MARGIN=0.05 DETAIL=1 node layout.mjs   # the recommended layout (about 1 min)
```

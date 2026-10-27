# native-bls design 2 (angle B, structure): a smaller sound BLS12-381 native verifier on BCH 2026

Task: `native-bls-design2`, Track 3. This is a design only; nothing has been built.
Base: `bch-groth16-bls12381-sound-native` (34,229 B, 4 P2SH32 inputs, origin/main 17b05a7). The current entry stays.
Proposed new id: `bch-groth16-bls12381-sound-native-v2`.
Angle: structure. That covers split points, input count, hash-authenticated code sharing, and reusing the reviewed
single-input SI-GLS design split across inputs.

Measured inputs: `work/native-bls/BREAKDOWN.md` and `breakdown/opcat.json` on `wip/native-bls-breakdown`.
Model script: `chunked/bls12-381/bls-native-sound/design2/model.mjs` on `wip/native-bls-design2` (run `node model.mjs`).

## 0. Verdict

**Structure alone cannot make this verifier much smaller.** I checked every structural lever against the measured
build. Each one either:
- adds about as many bytes as the op budget it saves, or
- cuts bytes while op-cost still binds, so the fillers grow back.

The reason is the 2026 budget rule. A 48-B word buys 36k op of budget (750 op/B). Every per-input quantity that could
be shared costs 8–28k op per word to compute locally. So sharing never pays. Every split-point change only moves op
between inputs, and the tuner already balances that.

The structural package below (**stage 1**) is small, cheap and keeps the soundness argument simple:
- −53 B on its own, because op binds and the fillers grow back: **34,176 B**;
- **−294 B** once any op lever (angle A) saves ≥ 0.5M op.

Two packaging levers then turn further op savings into bytes:
- **P2S packaging**, which pays from 0.55M op saved.
- **An SI-GLS projective tail** in input 3, which pays from 1.2M op saved.

| op saved at the worst witnesses by other levers (angle A) | today's structure | **v2-B** (stage 1 + best packaging) | choice |
|---|---|---|---|
| 0 | 34,229 | **34,176** | P2SH32 |
| 0.5M | 33,918 | **33,624** | P2SH32 |
| 1.0M (angle-A low estimate) | 33,918 | **33,480** | P2S |
| 1.5M (angle-A high estimate) | 33,918 | **33,265** | P2S, projective tail k = 8 |
| 2.0M | 33,918 | **32,977** | P2S, k = 11 |

The "today's structure" column also explains why angle A alone stalls at 33.9 kB. Once the fillers are gone, natural
bytes bind. Angle B's job is to lower that natural floor, and to provide converters that trade op slack for bytes.

**Recommendation.**
- Build stage 1 together with angle A's op work.
- Let the tuner choose P2S and the tail length k from the measured slack.
- Expect **≈ 33.3–33.5 kB** (−0.75 to −0.95 kB, −2.2 to −2.8%).
- A score below about 32.5 kB needs a different per-event arithmetic, not a different structure (§5).

## 1. The score model this design is judged against

From the breakdown (standard mode, which binds, at the 6.2% tuning margin):

    S_op  = Σ_i worst op_i / 750 − 4·41 + locking + 192 + 56     (56 calibrates to the measured 34,229)
    N     = natural bytes: everything except the zero fillers, with locking and tx overhead included (33,918 today)
    score = max(N, S_op)

The worst witnesses are forced 44d3 for in0 (4.793M) and ALL15 for in1–in3 (7.349M, 7.323M, 6.052M). They total 25.517M.

How a change reaches the score:
- **dN only** (a byte cut) reaches the score only while N binds.
- **dW only** (an op cut) reaches the score only while S_op binds.
- **Today S_op binds** by 311 B, which is the size of the fillers.

**Exchange rates for converting op slack into byte cuts** (op added per byte removed):

| converter | op per byte removed | fixed cost | status |
|---|---|---|---|
| P2S packaging (R moves from the unlocking into the locking) | 0 op; costs 66 B of budget per input | none | §2 C5 |
| SI-GLS projective doubling in place of a witnessed B slope | 927 | 505 B of code | §2 C6 |
| norm-inverse slope (witness N(2y)⁻¹, 1 word, in place of λ, 2 words) | ≈ 900–950 (estimated, +40–45k per event) | ≈ 100 B | rejected: no better than C6 and not reviewed |
| baked δ (c, λ) (4 words) in place of the λ-only recursion (2 words) | wrong direction (+96 B to save 50k) | – | rejected (design 1 already measured it) |

## 2. The design (v2-B)

The parts kept unchanged:
- the mathematics (SI-GLS, base-|x| GT-GLS, monic Fp12*/Fp6* states, λ = p + |x|);
- 33 chunk identities and 32 states;
- the transcript (except C2), the quotient rule (44 ≤ n_q ≤ 116, canonical), the role table and chunk cuts
  [0,5) [5,15) [15,25) [25,33);
- the two-carrier program, the K blocks hash-pinned by K_HASH[i], and the role dispatch by computed OP_INVOKE.

The tuner (`tune.mjs`) re-fits placement and fillers after every change, as it does now.

### Stage 1 (unconditional; structural only)

**C1. The binding moves from R into the hash-pinned program.** It saves 52 B and costs no op.

The new R has 65 B, so it needs only a 1-byte push header:

```
1 INPUTBYTECODE <off1> SPLIT NIP <len1> SPLIT DROP  2 INPUTBYTECODE <off2> SPLIT NIP <len2> SPLIT DROP CAT
DUP SHA256 <H_blob> EQUALVERIFY 0 DEFINE 0 INVOKE
```

Function 0 of the program begins with today's 16 B binding:
`TXINPUTCOUNT 4 NUMEQUALVERIFY 0 BEGIN DUP UTXOBYTECODE INPUTINDEX UTXOBYTECODE EQUALVERIFY 1ADD DUP 4 NUMEQUAL UNTIL DROP`.

- The binding instructions are the same, and each input still executes them once, so op is unchanged.
- Bytes: −16 × 4 (R) − 1 × 4 (headers) + 16 (once in the program).

Rejected variant: only in0 runs the sibling loop, and the others check UTXOBYTECODE(0) = own. It saves only about 10k
op, and it turns a one-line argument into a two-step one.

**C2. The challenges are handed off as raw digests.** It saves 33 B and about 15k op.

- **Today:** ZR = NUM2BIN(z,48) ‖ NUM2BIN(ρ,48) is 96 B with a 2-byte header.
- **New:** ZR = ρ_raw ‖ z_raw is 64 B with a 1-byte header. These are the two SHA256 outputs the head already computes.
- **Head:** `<ρ_raw ‖ z_raw> ZR EQUALVERIFY`, an exact byte equality, in place of two NUM2BINs and a compare.
- **Consumers (in1–in3):** z = BIN2NUM(z̃ ‖ 0x00) and ρ likewise. The values are in [0, 2²⁵⁶) ⊂ [0, p), so the range
  check is vacuous: a 32-byte string has exactly one unsigned value below p. That saves the two word decodes and the
  range check in READ0.
- The transcript definition of ρ and z is unchanged.

**C3. Layout pins and K pins driven by one shared descriptor function.** It saves about 200 B (range −120 to −260) and
costs about 10k op.

Today each role body has its own code for:
- DEPTH;
- one `ROLL SIZE <n> NUMEQUALVERIFY` per push;
- the filler check and the drops;
- the K-piece gather (introspection per relocated piece);
- the K_HASH compare;
- the δ start decode.

Together that is 584 B over four roles (137/124/131/192). In the new design:
- One shared function `PIN` takes a per-role descriptor constant, which is part of the hash-pinned program. The
  descriptor holds the push sizes, the K pieces as (host, offset, length), and the K_HASH index.
- The δ start decode (4 × unsigned decode) moves into WORK, where it is shared.
- Per role, the code is the descriptor (about 2 B per push, 5 B per piece) plus one call.
- A computed-depth ROLL adds about 100–300 op per push.

**C4. Each input reads each sibling at most once.** It saves about 10 B and about 35k op.

- in1 introspects in0 twice today: READ0 reads ZR, the statement and s^c, and WORK reads the predecessor's last state
  and claims (here the predecessor is in0).
- in0 introspects in3 twice: once for the K0 piece and once for G₃ and R̃₃.
- One INPUTBYTECODE per sibling, sliced at the same build-time offsets, saves about 2·U_sibling op per merged read.
  That is 13–20k in in1 and about 16k in in0.

**C7 (build rule). The fillers are re-fitted.** Today's rule applies unchanged: fillers are all zero, have a fixed
size, and exist only for the op budget.

**Stage 1 total:**
- dN ≈ −294 B (range −200 to −340);
- dW ≈ −0.04M (range −0.03 to −0.08M);
- score 34,176 B on its own (range 34,122–34,189), and 33,624 B once A ≥ 0.5M.

### Stage 2 (conditional converters; the tuner switches them on only when it measures enough op slack)

**C5. P2S packaging.** In BCH 2026 the 65 B R is a standard bare locking (≤ 201 B), and the bench accepts the `p2s`
envelope.
- Each input's locking becomes R itself, and the unlocking no longer pushes R.
- Bytes: −36 B per input (locking +30, unlocking −66), so −144 B.
- Budget: −66 B per input, so −211k op of budget in total, which is +120 B on the S_op side.
- The sibling check is unchanged: it compares UTXOBYTECODE, which is now R itself.
- It pays only when N binds with ≥ 264 B of op slack. The model puts that at A ≥ 0.55M.

**C6. SI-GLS projective tail in input 3** (the E_A knob of the reviewed BLS bch-spec design).
- Events 63−k … 62 run the homogeneous projective doubling from that design, starting at (x : y : 1). There is no
  witnessed slope.
- Events 47–62 contain no addition, so with k ≤ 16 only PROJDBL is needed.
- Code: PROJDBL is 445 B, the same as the sibling's measured kernel. The projective endpoint plus the Z ≠ 0 guard add
  about 60 B.
- Bytes: −96 B per event.
- Op: +89k per event (AFFDBL 145k, against PROJDBL 234k measured in the sibling).
- Projective lines have degree 9 instead of 8. That raises the degree of the tail chunks by 3. NQ_MAX and N_MIN must be
  re-derived in `protocol.mjs`; the model books +1 word (48 B) at the fixture.
- in0 has 195 B of cap headroom at n_q = 116. If NQ_MAX rises by 2 or more, that headroom falls to ≤ 99 B; the build
  must assert it.
- It pays from A ≈ 1.2M (k = 6). At A = 1.5M the model picks k = 8; at A = 2.0M, k = 11.

### Per-input layout

The layout is for the fixture (n_q = 45). Pushes are in order, and the last push before R is unchanged where it carries
a program part. Placement of the relocatable bytes (program parts, K pieces) and the filler sizes are the tuner's
output. The figures below are today's placement with the stage-1 deltas applied.

| input | role, chunks (events) | pushes | natural U (stage 1, P2SH32) | op at worst witness (stage 1) |
|---|---|---|---|---|
| in0 | head + chunks 0–4 (events 0–6) | G₀ 3,264 (statement 864 ‖ 5 states ‖ 10 slopes) · CL₀ 240 · **ZR 64** · K0 piece ≈ 513 · WQ 48·n_q · R 65 | ≈ 6,335 | ≈ 4.775M (forced 44d3) |
| in1 | chunks 5–14 (events 7–26) | G₁ 4,896 · CL₁ 240 · K1 piece ≈ 171 · program part 0 · R 65 | ≈ 9,500 (program part −200) | ≈ 7.33M (ALL15) |
| in2 | chunks 15–24 (events 27–46) | G₂ 4,896 · CL₂ 240 · K2 2,208 · program part 1 · R 65 | ≈ 9,700 | ≈ 7.32M (ALL15) |
| in3 | chunks 25–32 (events 47–62) + terminal | G₃ (7 states ‖ 16 − k slopes) · CL₃ 48 · K0 piece 1 · K1 piece 1 · K3 · R 65 | ≈ 8,010 (−96k with C6) | ≈ 6.05M (+89k·k with C6) |

Notes on the layout:
- **Program:** 6,465 + 16 (C1) − 200 (C3) ≈ 6,281 B, plus 505 B with C6. Every input still introspects the two
  carriers once and hashes the program once.
- **Byte caps:**
  - in0 stays ≤ 10,000 B at n_q = 116, because ZR shrinks by 33 B and R by 17 B.
  - in3 has about 2 kB of cap headroom, so the C6 code can sit there.
  - in1 and in2 gain about 200 B of headroom.
- **Transaction:** 4 inputs, P2SH32 (or P2S with C5), about 33.6 kB, standard, ≤ 100 kB.

## 3. Soundness sketch (constructive; every new or changed binding)

These are the only changes to the reviewed argument (README § Soundness argument). Every other owner is unchanged.

| value or binding | owner today | owner in v2-B | why the argument stays simple |
|---|---|---|---|
| input count = 4; every input's locking equal; order → role | R (count + sibling loop), role = INPUTINDEX | **the program's function 0** (same 16 B, executed by every input before its role body); role = INPUTINDEX | R pins the program by H_blob, so an input that runs R runs these checks. A transaction is valid only if every input's script succeeds, so the post-condition is the same: exactly 4 inputs, all locked to R. If R reads carriers 1 and 2 before the count check, a missing carrier makes R fail, which is liveness only. A 5th or foreign input fails the program's count or sibling check in every one of our inputs. |
| P2S (C5): the code of each input | P2SH32 = SHA256 of R | **literal equality**: the locking is R, and UTXOBYTECODE(j) = UTXOBYTECODE(own) for all j | Strictly simpler: no hash is involved, and the sibling comparison is over the code itself. |
| program bytes | SHA256 = H_blob in R | same | Unchanged; the hashed item is the defined item. |
| ρ, z reaching in1–in3 (C2) | z̃, ρ̃ = NUM2BIN(z, ρ, 48), byte equality in in0 | **ρ̃_raw ‖ z̃_raw = ρ_raw ‖ z_raw**, byte equality in in0; consumers decode BIN2NUM(· ‖ 0x00) | The 64 B are the head's own SHA256 outputs, fixed by exact equality, and they decode to exactly ρ and z. Each 32-byte string has one unsigned value, and 2²⁵⁶ < p, so there is no alias. The range check is vacuous; it may be kept or dropped. |
| layout: DEPTH, exact SIZE of every push, the zero fillers, push-only | inline code per role | **one shared PIN function** driven by a per-role descriptor constant inside the hash-pinned program | Same checks, same constants. The descriptor is a VK/build constant pinned by H_blob, and the build asserts descriptor = role table (`protocol.mjs` stays the single source for offsets, the hasher and the readers). |
| δ blocks K_i | SHA256 = K_HASH[i], gathered per role | same, gathered by PIN from (host, offset, length) descriptor entries | Unchanged owner. A wrong offset gives a wrong hash, so the input rejects. |
| sibling reads (C4) | several INPUTBYTECODE of the same input | one INPUTBYTECODE per sibling, sliced at the same build-time offsets | The same bytes at the same (input, offset, length). The head still hashes exactly the bytes the readers compute with (rule 4). |
| B walk at projective events (C6) | witnessed slope, fixed by 2yλ = 3x² | **computed on chain** with the reviewed SI-GLS homogeneous formulas from (x : y : 1); Z = 0 is absorbing; Z_T ≠ 0 is checked (reduced) at the endpoint; endpoint X_T·γ₁² = conj(x_B)·Z_T, Y_T·γ₁³ = −conj(y_B)·Z_T | This is the BLS bch-spec argument item 5 verbatim. The affine prefix is the exact group law, entering at (x : y : 1). The projective segment is exact because Z = 0 is absorbing and Z_T ≠ 0 is checked, so T_end = [|x|]B and ψ(B) = [x]B gives B ∈ G2. No new witness, so no new owner. |
| line factors at projective events (C6) | affine lines, y_P·X³ ≠ 0 | projective lines y_P·Φ(2YZ) ≠ 0 (since Z ≠ 0); the class changes only by an Fp2 ⊂ Fp6* scalar | Same as the sibling's identity item 1. |
| degree bound and quotient cap (C6) | NQ_MAX = 116, N_MIN = 44 (asserted) | re-derived by `protocol.mjs` with degree-9 tail lines and asserted at build; ε recomputed | Mechanical. A larger cap only enlarges the Schwartz–Zippel degree, which stays ≈ 2⁻²⁴⁷·⁹. |

**Multi-input binding:**
- The input count, the order (role = OP_INPUTINDEX), the sibling code (equal lockings) and the program (H_blob) are all
  checked in every input, as today. Only the location of the check moves (C1), or the hash is replaced by identity (C5).
- The state hand-off is unchanged:
  - T̃_i and R̃_i are fixed by exact byte equality in the pinned producer;
  - each successor reads the predecessor's last state from the bytes the head hashed;
  - δ starts come from the K blocks.
- ρ and z are now handed off as raw digests (C2), still fixed by exact equality.

**Not changed:** the transcript order and arity, every range check at every decode (rule 1), the reduced guards
(rule 5), the GT-GLS integer binding, G1 cofactor malleability (statement-preserving), and ε.

## 4. Structural alternatives evaluated and rejected (numbers from the measured build)

| alternative | what it buys | what it costs | net |
|---|---|---|---|
| **3 inputs** | −1 setup (0.785M), −1 loader (0.1M), −hand-off (≈ 0.2M), −R/locking/tx (≈ 0.25 kB) | Needs worst op ≤ 3 × 10,041 × 800 × 0.938 ≈ 22.6M and N ≤ 30.3 kB (unlocking cap). Today 25.5 − 1.1 = 24.4M; with angle A's 1.5M it is still 22.9M, with N ≈ 32.9 kB. Closing 2.6 kB of bytes with the projective converter adds ≈ 2.5M op. | **infeasible** |
| **5 inputs** | room under the 10 kB caps | +0.785M setup + 0.1M loader + ≈ 0.25M hand-off ≈ +1.1M op ≈ +1.5 kB, plus ≈ 0.25 kB of R, hand-off, locking and tx | **+1.7 kB** |
| **head-only in0** (no Miller events, so no setup in in0) | −0.785M op | in0's natural 3.3 kB buys 2.7M op but the head needs ≈ 1.3M. Either 1.4M of budget is wasted (≈ 1.9 kB), or in1–in3 must take events 0–6 and run 23.5M within 30 kB, a 2.5% margin. | **loss / infeasible at 6%** |
| **one program carrier** (in3) | −25k op per input in R (one introspection, no CAT) ≈ −0.1M | in3 becomes budget-rich and data-poor: with the 6.3 kB program it has room for ≈ 6 chunks but budget for ≈ 12, so ≈ 1.9M of budget goes unused. in1 and in2 lose 2.25 kB of budget bytes, which come back as fillers. | **≈ +2 kB** |
| **per-role program loading** (shared library pinned by R; role bodies pinned by H_ROLE[i] in it) | each input hashes and introspects only library + own role: ≈ −0.1 to −0.2M | +4 × 33 B of H_ROLE + glue ≈ +140 B. The 1,521 B head body cannot live in in0 (195 B of cap headroom at n_q = 116), so in0 needs a second introspection. Saving op at +1 B per 1k op is the wrong direction once N binds. | **≈ 0** |
| **GLS tables shared** (head publishes the 64 entries, consumers byte-check) | −0.52M per Miller input, −1.5M in all | +3,072 B (64 words) | **+1.1 to +3 kB** (N binds) |
| **shared base values only** (16 words) / **products only** (44 words) | −0.56M / −0.87M | +768 B / +2,112 B | at or below break-even (a word costs 36k op of budget; computing it costs 8–28k) |
| **z, ρ recomputed in every input** (no ZR) | −64 B | +0.175M per consumer (sibling reads and hashing of ≈ 33 kB) | **+0.6 kB** |
| **δ constants folded into the program** (no K_HASH layer) | −380 B of K gather/hash code | The program grows to ≈ 13.6 kB, above the 10,000 B stack-element limit, so it needs two-level loading. Every input hashes 7.1 kB more and introspects 3 carriers: ≈ +0.15–0.2M. | marginal at best, and adds a loading level. Not taken: C3 gets most of the code saving without it. |
| **GLS bits concentrated in a few inputs** (extra factor sets m^{2^{16j}·\|x\|^i}) | no tables in the other inputs | Table and lookup cost is the same in total (set count × inputs with tables is invariant), plus 1,152 B of constants per extra set | **loss** |
| **3-event chunks** (BREAKDOWN §4) | −2.6 kB of states | N_MIN 121: +3.7 kB of WQ | **+1.1 kB** |
| **fixture-dependent filler** (filler length a function of the hashed nibble count) | fixture budget is 1.37M below worst: ≈ −0.3 kB at the fixture | Typical proofs gain nothing, so the gain is only on the benchmark fixture. Adds a variable layout. | **not proposed** (owner call; listed for completeness) |

## 5. Why not much more, and what would be needed

Score ≈ max(N, S_op) with N ≈ 33.6 kB after stage 1 and S_op set by Σ worst op/750.

Op tax of the multi-input structure:
- **3.14M of setup:** z powers, S_c(±z), and 64 GLS entries at ±z, of which 627k are the GLS tables.
- **≈ 1.35M** of loader, pins and hand-off.

The setup is irreducible structurally: every Miller input meets all 16 nibble values at both signs in the worst case.
A word handed off costs more budget than it costs to compute. The arithmetic per event (AFFDBL 145k, DSTEP 83k,
GLS 24k, BND 46k per boundary) is near its floor (BREAKDOWN §5).

Every remaining lever trades op and bytes at 750–950 op per byte, which is what the budget rule itself charges. So the
total falls only by the sum of two-sided improvements.

A drop below ≈ 32.5 kB would need, at the same time:
- about −3M op;
- about −1.5 kB of natural bytes.

That can come only from a cheaper per-event identity (for example fewer than 2 evaluations per event, which is a
change to the reviewed mathematics), not from structure.

**Owner levers outside this design:**
- **Tuning margin:**
  - 6.2% → 6.0% gives ≈ −70 B while op binds, and nothing once N binds.
  - A rigorous static op bound (the trace is fixed; only operand lengths vary, about 0.03% sd) could justify a smaller
    margin. That is a policy change, and it is not assumed here.

## 6. Estimates (all from `design2/model.mjs`)

| scenario | N | S_op | score | vs 34,229 |
|---|---|---|---|---|
| stage 1 only (A = 0) | 33,624 | 34,176 | **34,176** | −53 |
| stage 1, A = 0.5M | 33,624 | 33,509 | **33,624** | −605 |
| stage 1 + C5, A = 1.0M | 33,480 | 32,963 | **33,480** | −749 |
| stage 1 + C5 + C6 (k = 8), A = 1.5M | 33,265 | 33,259 | **33,265** | −964 |
| stage 1 + C5 + C6 (k = 11), A = 2.0M | 32,977 | 32,948 | **32,977** | −1,252 |

Error bars:
- Stage 1: dN −200 to −340 and dW −0.03 to −0.08M give a standalone score of 34,122–34,189.
- C6 per-event costs come from the sibling's measured kernel (±10%).
- C3's byte saving is the least certain item (±70 B).

Worst-case op in the 1.0M scenario: ≈ 24.48M standard in total. At that point S_op is 517 B below N, but C6 needs
k ≥ 6 to repay its 553 B fixed cost, so it is not switched on.

## 7. Risks

1. **Small standalone gain.** Stage 1 alone is −53 B because op binds. Its value depends on angle A's op savings
   landing; the plan should be built and judged together with A.
2. **C3 code saving** (−200 B) is estimated from the section sizes in `build.json`, not built. A computed-depth ROLL
   adds op per push.
3. **C5 (P2S)** changes the packaging type the bench reports (`p2s`). The owner should confirm this is wanted for a
   flagship entry. It costs 211k op of budget, so it is used only when N binds by ≥ 264 B.
4. **C6** brings the projective segment of the reviewed BLS bch-spec SI-GLS into the native build. The review must check:
   - the (x : y : 1) entry in the middle of in3;
   - the projective endpoint;
   - the re-derived NQ_MAX / N_MIN.

   It also costs in0's cap headroom (195 B at n_q = 116) if NQ_MAX rises.
5. **Liveness evidence must be redone:** the forced witnesses, the ALL15 sweep and the 3,600 review-family re-run,
   because every change moves the per-input op.

## 8. Build plan (if chosen)

1. Branch `wip/native-bls-v2` from main. Copy `bls-native-sound` to `chunked/bls12-381/bls-native-sound-v2`.
2. Apply C1, C2, C4, then C3, one commit each. After each one, run `test-protocol.mjs`, `build.mjs`, `redteam.mjs`,
   and measure the deltas against this model.
3. Merge angle A's op changes. Run `measure.mjs`, `layout.mjs` and `tune.mjs`. Read the remaining slack. Switch on C5
   at ≥ 264 B of slack and C6 (choose k) at ≥ 1.2M op.
4. **Rejection suite additions:**
   - ZR raw changed by one byte;
   - ZR given as the old 48-B NUM2BIN form;
   - the descriptor-driven pins, with each push resized;
   - a foreign 5th input under the moved binding;
   - P2S: a sibling with P2SH32(R) in place of R;
   - C6: honest-prover proofs with malformed B (off the twist, on the twist outside G2) run through the projective
     tail.
5. Sweep (≥ 667 proofs plus the review families) in both modes. Then the bench entry
   `bch-groth16-bls12381-sound-native-v2` (unreviewed until the 3-lens review). The current entry stays.

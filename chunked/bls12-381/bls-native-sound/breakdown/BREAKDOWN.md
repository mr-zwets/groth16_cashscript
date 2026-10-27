# native-bls-breakdown: byte and op-cost breakdown of bch-groth16-bls12381-sound-native (34,229 B, 4 inputs)

Read-only measurement of origin/main 17b05a7, `chunked/bls12-381/bls-native-sound` (layout.json fillers 27/124/45/115).
Tools: worktree `work/native-bls/groth16_cashscript` (branch wip/native-bls-breakdown), scripts in
`chunked/bls12-381/bls-native-sound/breakdown/` (`opcat.mjs` per-function op and calls; `opcodes.mjs` per-opcode op;
`cats.cjs` buckets). All op numbers are from the libauth bch-2026 VM, standard mode, which is the tighter one.
Exchange rate at the 6.2% tuning margin: 1 B of unlocking buys 800 op of budget, or 750 op of usable op. So
**1M op ≈ 1,333 B**.

## 0. The headline: the score is set by op-cost, not by data

Every input is op-bound at its own worst witness. Input 0 at forced n_q = 44 with the bits in digit 3 first has
U 6,349 and a 6.23% margin. Inputs 1–3 at ALL15 have margins of 6.23/6.22/6.22%. The natural bytes (data + code) are
311 B below what the op budget needs, and the fillers make up exactly that difference. So for this design:

    score ≈ Σ_i (worst op_i / 750) − 4·41 + 140 (locking) + 192 (tx overhead)

Removing a byte does not lower the score unless op drops with it. Op savings beyond about 0.24M (the fillers) only
show up in the score if natural bytes shrink by the same amount.

## 1. Bytes per input (fixture `committed`, n_q = 45)

Bytes are grouped by what they hold, not by which push they sit in. K pieces are split: the δ start point (192 B per
seam) counts as hand-off and the δ slopes count as core.

| bytes | in0 | in1 | in2 | in3 | total |
|---|---|---|---|---|---|
| core data: statement 864, states (5/10/10/7 × 288), B slopes (10/21/21/16 × 96) | 3,264 | 4,896 | 4,896 | 3,552 | 16,608 |
| core data: WQ (45 words) | 2,160 | – | – | – | 2,160 |
| core constants: δ slopes hosted here (K0 is in0 513 + in3 447; K1 slopes and K3 are in in3; K2 is in in2) | 513 | – | 2,016 | 3,999 | 6,528 |
| **hand-off**: ZR (z̃, ρ̃) 96 + claims CL (R̃‖T̃ 240; in3 R̃₃ 48) | 336 | 240 | 240 | 48 | 864 |
| **hand-off**: δ start points (x_j, y_j), 192 per seam (K1 is split 171 / 21) | – | 171 | 192 | 213 | 576 |
| **shared code**: program parts (6,465 total, carried once) | – | 4,229 | 2,236 | – | 6,465 |
| **repeated code**: R (81 B, in every input) | 81 | 81 | 81 | 81 | 324 |
| **padding** (zero fillers, budget only) | 27 | 124 | 45 | 115 | 311 |
| push headers | 16 | 14 | 14 | 17 | 61 |
| **unlocking** | **6,397** | **9,755** | **9,720** | **8,025** | **33,897** |
| locking (P2SH32 35 B) / tx overhead | | | | | 140 / 192 |

**Where the 6,465 B program goes:**
- Functions: 3,673 B. This includes SETUP 1,606 (1,152 B of GLS factor constants), AFFDBL 288, AFFADD 333,
  DSTEP 186, WORK 279, TBL 175, FINW 118, TM 111, LOOP 103 and BND 92.
- Role bodies: 2,688 B. Role 0 is 1,521: pin+K 192, transcript 177, statement 231, binding 98, quotient+final 186,
  setup 143, start 489. Role 1 is 195, role 2 is 183, role 3 is 789 (terminal 607).
- Define/dispatch: 104 B.

**Multi-input-only code:**
- Role pins + K gather/hash: 584 B, of which 4 × 33 B are K_HASH.
- Role params: 156 B.
- READ0, WSTART, FINW and C48: 193 B.
- WORK glue: 279 B.
- Head sibling reads: roughly half of the 177 B transcript section.
- R: 4 × 81 B. Of R's 81 B, 16 are binding (input count 3 + sibling-locking loop 13), 24 are the two carrier slices,
  1 is CAT, 36 are the H_blob pin and 4 are DEFINE/INVOKE.

That totals about 1.3 kB in the program, plus 324 B of R.

## 2. Op-cost per input vs budget (standard; consensus in parentheses)

| | in0 | in1 | in2 | in3 |
|---|---|---|---|---|
| budget (41 + U) × 800, fixture | 5.150M | 7.837M | 7.809M | 6.453M |
| op fixture | 4.700M (4.646M) | 6.845M (6.828M) | 6.837M (6.819M) | 5.764M (5.747M) |
| margin fixture | 8.74% | 12.65% | 12.44% | 10.67% |
| worst witness | forced:44d3 (U 6,349, budget 5.112M) | ALL15 | ALL15 | ALL15 |
| op worst | 4.793M (4.739M) | 7.349M (7.331M) | 7.323M (7.305M) | 6.052M (6.035M) |
| margin worst | 6.23% | 6.23% | 6.22% | 6.22% |

At ALL15, input 0 has n_q = 116 (U 9,805) and a 31.5% margin, because WQ bytes buy budget that the head barely uses.

**Op buckets at each input's worst witness (k op):**

| bucket | in0 | in1 | in2 | in3 | total |
|---|---|---|---|---|---|
| Miller events (AFFDBL, AFFADD, DSTEP, BND, LOOP incl. GLS lookups, own state/slope decode) | 2,735 | 6,160 | 6,160 | 4,665 | 19,720 |
| per-input setup (SETUP, TBL, 4 × TM, 9 × EV: z powers, S_c(±z), 64 GLS table entries) | 784 | 785 | 785 | 785 | 3,139 |
| head (statement 72, binding 284, quotient+final 332, initial value, curve checks, extra decodes) | 924 | – | – | – | 924 |
| transcript incl. sibling reads (3 × INPUTBYTECODE + 4 region hashes + ZR) | 175 | – | – | – | 175 |
| terminal | – | – | – | 256 | 256 |
| hand-off (READ0, WSTART, claims decode, FINW, C48, WORK glue, params) | 18 | 223 | 220 | 195 | 656 |
| layout pin + K gather/hash | 35 | 60 | 37 | 32 | 164 |
| loader R + program define (2 carrier introspections, SHA256 of 6.5 kB) | 99 | 99 | 99 | 99 | 396 |
| other (P, small anonymous bodies) | 22 | 22 | 22 | 19 | 85 |
| total | 4,793 | 7,349 | 7,323 | 6,052 | 25,517 |

**Multi-input op:**
- The 3 extra setup copies cost 2.36M.
- Loader, pins, hand-off and sibling reads cost about 1.35M.
- Together that is **≈ 3.7M op ≈ 4.9 kB of budget**, or 14% of the score.

The ALL15 premium over the fixture is about 0.48M per full Miller input (in3 0.29M). It comes from GLS lookups: about
24k per event with both nibbles nonzero.

**Per opcode** (`opcodes.mjs`, input 1 at ALL15, 7.35M over 14,953 instructions):

| | op | share |
|---|---|---|
| MUL + MOD | 5.12M | 70% |
| stack shuffles (PICK 344k, ROLL 290k, SWAP 89k, ROT 49k, OVER 47k, DUP 46k) | ≈ 0.86M | |
| small pushes (mostly depth indices; 100 op base each) | 0.48M | |
| big data moves (≥ 1k op per step: SPLIT of region/K strings 156k, ROLL 75k, INPUTBYTECODE 48k, SHA256 27k, FROMALT 15k, CAT 12k) | ≈ 0.34M | |

The same data-move figure is 0.33M for in0, 0.31M for in2 and 0.24M for in3. Summed over the 4 inputs at their worst
witnesses it is about 1.2M.

## 3. Comparison with the bch-spec sibling (sound-si-gls, 26,484 B; gap 7,745 B)

| item | native | si-gls | Δ |
|---|---|---|---|
| statement + nibbles + s^c | 864 | 864 | 0 |
| 32 states | 9,216 | 9,216 | 0 |
| witnessed B slopes | 6,528 (68, all affine) | 1,248 (13; events 10–62 projective) | **+5,280** |
| WQ (fixture) | 2,160 (45) | 2,256 (47) | −96 |
| δ slopes | 6,528 (K blocks) | 6,579 (pile in redeem) | −51 |
| δ start points | 576 | 0 | +576 |
| ZR + claims | 864 | 0 | +864 |
| code + constants | 6,465 program | 6,214 redeem minus the δ pile | +251 |
| R copies | 324 | 0 | +324 |
| fillers | 311 | 0 | +311 |
| push headers | 61 | 9 | +52 |
| locking / tx overhead | 140 / 192 | 35 / 63 | +234 |

**Notes on the comparison:**
- **Code:** native has no projective kernels (SI's PROJDBL 445 + PROJADD 614 = 1,059 B). So the true multi-input
  code is about 1.3 kB, not 251 B.
- **The gap is mostly not multi-input overhead.**
  - 5,280 B (68%) is the B slopes that native witnesses instead of computing.
  - In bch-2026 every op must be bought with bytes. An affine doubling with a witnessed slope costs 96 B and saves
    about 89k op against projective (AFFDBL 145k vs SI PROJDBL 234k). 89k op is about 119 B of budget, so the slopes
    are the cheapest way to buy the op (927 op per byte against the 750 needed).
  - SI gets 10,000 × 800 = 8M op free per input. Its 26.1–27.5M op would need about 36 kB of native bytes.
- **Actual multi-input byte overhead:** about 2.5 kB (hand-off 1,440, R 324, fillers 311, locking/tx 234, headers 52,
  code about +250 net).
- **Actual multi-input op overhead:** about 3.7M (§2).

## 4. Structural limits (measured, not assumed)

- **Input count is forced to 4.** The worst total is Ω ≈ 25.5M op ≈ 34 kB. Three inputs top out at 30 kB under the
  10,000 B cap. A fifth input adds about 1.2M (setup + loader + hand-off) ≈ 1.5 kB.
- **Chunking is already at the optimum.** Re-running `protocol.mjs` degree bookkeeping on 3-event tail chunks gives
  23 states but N_MIN 121 / NQ_MAX 289, against 32 states and 44 / 116 today. That costs +3.7 kB of WQ at the floor
  to save 2.6 kB of states, so it is worse.
- **Sharing the GLS tables by a byte-checked claim is a loss.** It would save about 0.5M op per Miller input
  (≈ −2.0 kB of budget overall) but adds 3,072 B of natural bytes, at a point where natural bytes already bind.
- **Swapping B slopes for projective doublings is a loss now.** It costs +23 B per doubling while op binds. Once bytes
  bind it realizes only about 45% of the slack, and adds about 450 B of PROJDBL code.

## 5. Largest reducible items (estimates)

Score savings are capped by min(Δ op-budget, Δ natural bytes + 311).

| # | item | now | est. reduction | how |
|---|---|---|---|---|
| 1 | Big data moves (string SPLIT/ROLL of 2–5 kB regions per event and state, K/region re-slicing, R's two ~10 kB carrier introspections) | ≈ 1.2M op (≈ 1.6 kB budget) | 0.4–0.6M → **−0.5 to −0.8 kB budget** | Pushes ≤ ~500 B, or consume from the short end; read K and own G as several pushes. PROGRESS already estimated −0.3M op. |
| 2 | Kernel instruction overhead in AFFDBL/DSTEP/LOOP/BND (shuffles + depth pushes at 100 op each, about 1.2–1.3M per full Miller input) | ≈ 4M op total | about 10% → 0.4M → **−0.5 kB budget** | Rescheduling. Arithmetic (70%) is near its floor: about 145k per doubling, 83k per δ step, 46k per boundary. |
| 3 | Per-input setup repeated 4× (2.36M extra over the single-input case) | 3.14M op (≈ 4.2 kB budget) | 5–15% via setup kernels → **−0.2 to −0.6 kB budget** | Largest multi-input item but structural: every input needs all 64 table entries at ±z and S_c(±z). |
| 4 | Zero fillers | 311 B (+6 headers; bench padBytes 317) | **−70 B** from margin 6.2 → 6.0% alone; **all 311** once worst op drops ≥ 0.24M | Comes free with items 1–3. Moving the tuning target needs the owner's sign-off. |
| 5 | Multi-input code + R | ≈ 1.3 kB program + 324 B R | **−0.15 to −0.3 kB natural** | Lighter layout pins, WORK/FINW glue, shorter R. Needed so op savings beyond 311 B can reach the score. |

**Realistic outcome:**
- Items 1–3 together save about 1.0–1.5M op (−1.3 to −2.0 kB of budget).
- The natural floor is about 33.6 kB minus item 5.
- So the realized score is **≈ 33.6–33.8 kB (−0.45 to −0.65 kB, −1.5 to −2%)**.
- None of the measured items supports a larger cut, for example under 30 kB. That would need about 3M less worst-case
  op *and* about 3.5 kB fewer natural bytes. No candidate measured here, the rejected ones included, shrinks both
  together. It would take a design change to the per-event data/op ratio.

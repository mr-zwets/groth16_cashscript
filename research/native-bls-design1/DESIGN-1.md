# native-bls-design1: angle A (state and binding) for bch-groth16-bls12381-sound-native-v2

Design only. Base: `chunked/bls12-381/bls-native-sound` at origin/main 17b05a7 (34,229 B, 4 inputs, 25.52M op at the
worst witnesses, standard). Proposed id: `bch-groth16-bls12381-sound-native-v2`. The current entry stays.

Evidence used (all on branch `wip/native-bls-design1`, folder `chunked/bls12-381/bls-native-sound/design1/`):
- `glue.mjs` → `glue.json`: per-input op split by (function or role section, opcode) at ALL15 and forced:44d3, plus every
  step that costs ≥ 1k op. This calibrates the glue cost model below.
- `binding-proto.mjs`: a working VM prototype of item A9. It checks the gather trick exhaustively, checks equality
  against the current binding definition on 24 nibble strings (a wrong n fails), and measures op.
- `breakdown/opcat.json` and `BREAKDOWN.md` (task native-bls-breakdown) for everything else.

## 0. Result in one paragraph

Nine changes to state, hand-off and binding together save about **0.37M worst-case op** (range 0.30–0.45M) and about
**290 B of natural bytes** (range 250–340 B), with no new kind of trust. Because the build stays op-bound, the score
follows op: **≈ 33.7 kB (range 33.64–33.81 kB), −0.4 to −0.6 kB, −1.2 to −1.7%**.

The single biggest item is not multi-input glue. It is the head's public-input binding loop (A9, −150k op in input 0).
The glue items add about −0.2M.

Angle A cannot reach a large cut on its own. The breakdown showed the score sits on a natural-byte floor, and angle A
lowers that floor by about 0.28 kB to **≈ 33.64 kB** (≈ 33.54 kB with the optional 20-byte pins, O1). Op savings from
other angles can only reach the score down to that floor.

## 1. Cost model (measured, `glue.json`)

| quantity | value |
|---|---|
| exchange rate at the 6.2% tuning margin | 1 B of unlocking = 750.4 usable op; score ≈ Σ worst op_i / 750.4 − 4·41 + 48 (fixture WQ over n_q 44) + 332 |
| OP_INPUTBYTECODE | 100 + size of the introspected unlocking (9,905 for input 0 at ALL15) |
| OP_SPLIT | 100 + size of the string split (both halves are pushed) |
| OP_ROLL / FROMALT of a string | about the string's size (pin section: 5 big ROLLs = 10.2k in input 1) |
| SHA256, standard | about 3 op/B (19.7k for the 6,465 B program) |
| one canonical 48-byte word decode | about 1.1k, plus about 0.4k for its range check (RD6 117k / 78 words, RD2 75k / 50 words) |
| per-tx introspections | 8 in R (2 per input), 11 in role code: head 3 + remote K 1; in1 READ0, pred, remote K; in2 and in3 READ0, pred |

The score falls only when worst op falls, until natural bytes bind, so: Δscore = −min(Δneed, Δnatural + 311).

## 2. The changes

Each item lists bytes (natural, fixture), worst-case op per input (in0 at forced:44d3; in1–3 at ALL15) and the binding
argument it changes. Op numbers are derived from the measured pieces named in brackets.

### A1. Hub binding: count and sibling code checked through input 0

- **R today (81 B):**
  `TXINPUTCOUNT 4 NUMEQUALVERIFY  0 BEGIN DUP UTXOBYTECODE INPUTINDEX UTXOBYTECODE EQUALVERIFY 1ADD DUP 4 NUMEQUAL UNTIL DROP  <loader> <pin> 0 DEFINE 0 INVOKE`
- **New R** begins with `0 UTXOBYTECODE INPUTINDEX UTXOBYTECODE EQUALVERIFY` (5 B in place of 16).
- **Role 0** (once, in the program) runs `TXINPUTCOUNT 4 NUMEQUALVERIFY` and `h UTXOBYTECODE 0 UTXOBYTECODE EQUALVERIFY`
  for h = 1, 2, 3 (18 B).
- **Bytes:** R −11 B × 4, program +18, **net −26 B**.
- **Op:** each input saves the 4-turn loop, about 4.5k [R: UTXOBYTECODE 1,080/8, BEGIN/1ADD/NUMEQUAL/INPUTINDEX
  about 1.6k, DUPs and pushes about 1.4k]; the new prefix costs about 0.6k. Head +2k. **Total −14k.**
- **Binding argument.** Take any valid input j that spends P2SH32(R).
  1. R in input j forces UTXOBYTECODE(0) = P2SH32(R), so input 0 runs R. R loads the hash-pinned program, and its role
     is INPUTINDEX = 0.
  2. Role 0 forces the input count to be 4 and every UTXOBYTECODE(h) to equal P2SH32(R).
  3. So all 4 inputs run R, and input h runs role h.

  The facts this proves are the same as today (count = 4, identical sibling code, role = index); only the place each
  check runs changes. Dispatch stays safe: INPUTINDEX + 1 ≤ 4 because the count is 4.

### A2. Read discipline: one introspection per (reader, source), R's carrier prefixes reused, far end cut first

Three mechanical changes, all extracting the same byte ranges as today.

- **(a) Carrier prefixes stay on the stack.**
  - R today cuts `INPUTBYTECODE(c) <off_c> SPLIT NIP <len_c> SPLIT DROP` and throws the prefix [0, off_c) away.
  - New R reads carrier 2 first and keeps both prefixes (bytes are the same or one fewer):
    `2 INPUTBYTECODE <off2> SPLIT <len2> SPLIT DROP  1 INPUTBYTECODE <off1> SPLIT <len1> SPLIT DROP  ROT CAT`.
    The role then starts with prefix₂ and prefix₁ on top.
  - Those prefixes hold every field of inputs 1 and 2 except the program parts: G, CL and the constant pieces.
- **(b) Far end first.** For a field near the front of an introspected unlocking, cut at the field's end first, so the
  second SPLIT works on the short piece. Today READ0 cuts at the ZR offset first and splits about 9.8 kB twice (READ0
  SPLIT 21.9k / 5 calls).
- **(c) Merged reads.** A reader takes one span covering everything it needs from a source. The head takes G₃ together
  with input 3's last state and claims (A5 makes input 3 its predecessor). No reader introspects the same input twice.
- **Placement rule for tune.** A remote constant piece may live only in a carrier prefix or in a span its reader
  already fetches. This removes the in0 → in3 and in1 → in3 constant reads (today 8.1k + 12.6k and 8.1k + 15.4k).
- **Introspections per tx:** from 11 role + 8 R to 4 role + 8 R. The head takes G₁ and G₂ from prefixes and fetches
  in3. Each input fetches in0 (READ0). in2 takes its predecessor from prefix₁ and in3 from prefix₂.

| input | today (measured) | new (derived) | Δ |
|---|---|---|---|
| in0 | G₁ and G₂: 2 × (IB 9.8k + 2 SPLIT about 19.5k); in3: G₃ + R̃₃ about 30k; remote K0 piece 20.7k | G₁, G₂ from prefixes 2 × 10.4k; in3 span (G₃‖CL₃) about 24k; constants from a prefix about 6k | **−59k** |
| in1 | READ0 34k; pred = in0 about 30k; remote K1 piece about 20k | READ0 about 21k; no pred (A5); constants from a prefix about 6k | **−54k** |
| in2 | READ0 34k; pred = in1 IB 9.9k + about 24k SPLIT | READ0 about 21k; pred from prefix₁ about 11k | **−32k** |
| in3 | as in2 | as in2 | **−32k** |

- **Totals:** op **−177k**, bytes −1 B per R (−4 B); a few bytes of read code are saved in the program.
- **Binding argument.**
  - The prefix is literally INPUTBYTECODE(c)[0, off_c), cut by R. R is fixed by P2SH32.
  - Every field sliced from it sits at the same pinned offset as before.
  - Reordering SPLITs, or reading one span instead of two, extracts identical bytes.
  - The layout pins of the owning input (A6/A8) are what make those offsets meaningful, and they are unchanged.

### A3. (not adopted) Drop range checks on handed-off values

- The idea: the consumer's range checks on values whose owner already checks the same bytes (the statement, the
  predecessor's last state, the claims) are redundant.
- Saving: about −12k per Miller input (−36k). Cost: a non-checking decoder, +40–80 B of code.
- That is neutral at 750 op/B, and it adds a cross-input clause to rule 1. Not adopted. The redundancy is noted for the
  reviewer.

### A4. Raw challenges hand-off (ZR = z_raw ‖ ρ_raw, 64 B)

- **Today:** ZR is NUM2BIN(z, 48) ‖ NUM2BIN(ρ, 48), 96 B. Consumers decode both with range checks.
- **New:** ZR is the two SHA256 outputs. The head checks `z_raw ρ_raw CAT ZR EQUALVERIFY` before decoding. Every user,
  head included, decodes with the same U (BIN2NUM(raw ‖ 0x00) ∈ [0, 2²⁵⁶)) and needs no range check.
- **Cost:** **−32 B**, about **−1k op** per input (−3k plus the head's two NUM2BINs).
- **Binding:** ZR equals the hash outputs byte for byte, and every user applies the same decoder, so every input has
  the head's exact z and ρ. The head still checks z ≠ 0.

### A5. The head input runs the last Miller segment and the terminal

- **New role order:** segment s0 = input 1, s1 = input 2, s2 = input 3, s3 = input 0 (with the terminal).
  - Input 1 starts at B and δ with the initial value S_c(−X)·Rconst′·G₀ (the nibble-0 lookups move with it).
  - Input 0 continues from input 3's T̃₃, R̃₃ and last state.
  - Input 0 closes against W = Frob(S_c) and checks the endpoint.
  - The final identity uses input 0's **own** accumulated R. The R̃₃ claim disappears.
- **Bytes:** claims drop from 240 × 3 + 48 to 240 × 3 (**−48 B**). The head's R̃₃ read and the terminal's C48 compare
  go (about −22 B of code). **Total −70 B.**
- **Op:** about −5k (R̃₃ slice and decode, C48 and compare).
- **Binding:** one claim fewer. The chain is the same induction over 4 segments, starting at R = 0. The head's
  transcript order (G₀..G₃ by input index) is unchanged, and so is every seam rule (producer byte equality with its
  computed end, consumer decodes the same bytes).
- **Side effect:** input 1 no longer reads a predecessor (counted in A2).
- **Layout:** the cuts are re-fitted by `layout.mjs` and `tune.mjs`; §3 gives an illustrative cut.

### A6. Fewer pushes

- **Per input:** one push [G ‖ CL] (input 0: [ZR ‖ G₀]), one push [constant pieces ‖ zero filler], then the program part
  (carriers) or WQ (input 0, still last), then R. Today there are 22 data pushes; after this there are 10.
- **Bytes:** about −28 B of headers and 12 fewer SIZE pins (about −70 B of code). **Total about −95 B.**
- **Op:** about +10k overall. The merged pushes are split once on use (about 5k per input), which is offset by
  12 fewer big ROLL+SIZE pins.
- **Binding:**
  - The layout is DEPTH plus the exact SIZE of each push, under consensus push-only and minimal encoding. Every field
    is still at a fixed offset, now inside a push.
  - The head still hashes exactly G_i (a fixed sub-range).
  - The zero filler is checked on its slice, and each constant piece is hashed from its slice. Nothing else changes.

### A7. Drop redundant end-of-string checks

- **Which checks:** FINW and the terminal check that ST, N0, N1, SL and D are empty; READ0 checks that its tail is empty.
- **Why redundant:** every string has a pinned length, and the loop consumes a fixed amount per event, set by the role
  constants SCH and the flags. So emptiness already follows.
- **Change:** replace the checks with a build-time assertion that consumed bytes equal pinned bytes, per string and per
  role.
- **Saving:** **−45 B**, about −3k op per input (**−12k**) [FINW: SIZE/NOT/VERIFY/DROP 2.0k + ROLL 1.5k].
- **Soundness:** no change, because the checks were implied. Lowest-priority item; drop it if the reviewer prefers
  belt and braces.

### A8. Check each push's size at first use

- **Today:** the pin section ROLLs each big push to the top only to read its SIZE, then the body ROLLs it again (big
  ROLLs in the pin sections: in1 10.2k, in2 10.1k, in3 8.6k, in0 4.7k).
- **Change:** check SIZE at the point where the push is first rolled for use.
- **Saving:** **−24k op**, 0 B.
- **Binding:** the same checks, all unconditional, so their order is irrelevant.

### A9. Bit-plane GT-GLS binding (the head's public-input binding)

- **Today:** acc_k = Σ_g 2^(63−g)·TB[N_k[g]] is computed byte by byte. That is 128 iterations of
  SPLIT/BIN2NUM/PICK-lookup/DUP-ADD-ADD, **284k + TA 9k at forced:44d3**, and the cost depends on the data (TB entries
  are 1–25 B, so digit 3 is the expensive one).
- **New, the same integer computed by bit planes.**
  - TB[m] = Σ_{i∈m} |x|^i, so acc_k = Σ_i |x|^i·a_{k,i} with a_{k,i} = Σ_g 2^(63−g)·bit_i(N_k[g]).
  - For an 8-byte chunk v (bytes g = 8c..8c+7), masked to bit i: w = (v·M) >> (56+i) mod 256 =
    Σ_j [bit set]·2^(7−j), with M = 0x8040201008040201 = Σ_k 2^(9k).
  - Proof of the window: the terms land at bit 9(j+k) − j + i. The j+k = 7 terms fill bits 56+i..63+i exactly once.
    The terms with j+k ≤ 6 sum to less than 2^(56+i), and the terms with j+k ≥ 8 sit at bit 65+i or higher.
  - a_{k,i} = Horner over the chunks (·256 + w), then n_k = ((a₃|x| + a₂)|x| + a₁)|x| + a₀, followed by NUMEQUALVERIFY.
- **Prototype** (`binding-proto.mjs`, run on the VM):
  - The gather is checked exhaustively (256 patterns × 4 planes).
  - Results match the reference on all-zero, all-15, ALL15-shaped, alternating-bit and 20 random strings, and a wrong
    n is rejected.
  - Cost is **69.6k per group (139k for both), independent of the data**. The code is 200 B against today's binding
    plus TA, about 176 B.
- **Saving:** **−150k op in input 0**, about +25–35 B (≈ +10 B after hoisting M and the masks).
- **Side effect:** input 0's worst-case witness loses its digit-3-first premium.
- **Binding:**
  - The exact equation acc_k = n_k with n_k < r is the same, over the same hashed nibble bytes.
  - The nibble ≤ 0x0f check stays, and it matters: the 4 planes read only bits 0–3, and the Miller lookups index tables
    of 16.
  - Only the evaluation order of an integer sum changes.
  - Build-time test: the exhaustive gather check plus the VM equality on random and extreme strings.

### A10. (tuning knob, conditional) Turn the remaining filler into the best op-per-byte hand-off

- **When it helps:** only if the build is still op-bound after merging with the other angles.
- **What:** the remaining filler (about 80 B after A1–A9) can instead carry input 0's GLS-base evaluations (EV outputs
  at ±z, 96 B per EV). The consumers then read them instead of recomputing.
- **Rate, derived:** 27.8k per EV, minus about 2.2k of decode, times 3 consumers, minus about 3k of producer compare,
  gives about 760 op/B. That recovers about r/(750 + r) ≈ 50% of the slack, so about 40 B at the estimate below.
- **Binding:** the same owner pattern as z̃ (computed by input 0, canonical C48 bytes, exact equality).
- **Not counted in the estimate.**

### Optional O1. 20-byte pins (owner's call)

- Pin the program in R and the four constant blocks with HASH160 instead of SHA256: −12 B × 4 in R and −12 B × 4 in
  the program, so **−96 B**. Op is about +0.
- These pins guard fixed, builder-chosen constants, so what is needed is second-preimage resistance, which is 2¹⁶⁰.
  Collision resistance, 2⁸⁰, matters only against the builder.
- The bytes count only once natural bytes bind (in the combined plan). Not in the baseline, because the policy text
  says "pinned by a hash" and the reviewed builds all use 32 B.

### Small free items (counted)

- **TAG:** TAG = SHA256("SIGLS-BLS-NATIVE/2" ‖ VK encoding), 32 B instead of 50 B. **−18 B.** It keeps domain
  separation and the VK digest, and is still fixed-width.
- **Prologue rework:** with A6 and A8 the role prologues and WORK glue line up with the push order, so FRAME needs fewer
  ROLLs. Estimated −40 B of code (uncertain, range 0–80 B). Op is inside A8.

## 3. Per-input layout of v2 (illustrative cut; tune re-fits it)

Chunks are unchanged ([1,2,1,2,1,2×28], 33 identities, 32 states). Segment order is in1 → in2 → in3 → in0. Cuts:
in1 [0,9), in2 [9,20), in3 [20,30), in0 [30,33). That gives events 0–14, 15–36, 37–56 and 57–62, with the adds at
0, 2, 5 and 14 in in1 and 46 in in3.

| input | role | push 1 | push 2 | push 3 | δ block (home) | est. worst op |
|---|---|---|---|---|---|---|
| 0 | head + s3 + terminal | ZR 64 ‖ statement 864 ‖ 2 states ‖ 6 slopes = 2,080 | constant pieces + filler | WQ (last; 2,112–5,568) | K0: start 192 + 6 λ = 768 | ≈ 4.5M (budget at n_q 44 ≈ 6.0 kB) |
| 1 | s0 (starts at B, δ; initial value) | 9 states ‖ 19 slopes ‖ CL₁ 240 = 4,656 | constant pieces + filler | program part A | K1: 19 λ = 1,824 | ≈ 6.0–7.3M |
| 2 | s1 | 11 states ‖ 22 slopes ‖ CL₂ = 5,520 | constant pieces + filler | program part B | K2: 192 + 22 λ = 2,304 | ≤ 7.5M (cap) |
| 3 | s2 | 10 states ‖ 21 slopes ‖ CL₃ = 5,136 | constant pieces + filler | – | K3: 192 + 21 λ = 2,208 | ≈ 7.0M |

- Totals: states 32, slopes 68, events 63, K bytes 7,104 (6,528 λ + 576 starts), claims 720.
- R (69 B) is the last push of every input.
- Tune places the program parts (≈ 6,333 B in total) and the remote constant pieces under the A2 placement rule:
  remote pieces live in carrier prefixes or in input 0's READ0 span.
- **Cap check:**
  - Input 0 at n_q = 116 is ≈ 6.0 kB + 3,456 B ≈ 9.5 kB (today 9,805).
  - Carriers stay below 10 kB because their need is lower than today.

**Byte budget (fixture, natural):**

| | today | v2 | Δ |
|---|---|---|---|
| core data (statement, states, B slopes) | 16,608 | 16,608 | 0 |
| WQ (45 words) | 2,160 | 2,160 | 0 |
| δ λ + starts | 7,104 | 7,104 | 0 |
| ZR + claims | 864 | 64 + 720 = 784 | −80 |
| program | 6,465 | ≈ 6,333 | ≈ −132 (A1 +18, A5 −22, A6 −70, A7 −45, TAG −18, A9 +35, prologue −40, A2 ±10) |
| R × 4 | 324 | 276 | −48 |
| push headers | 61 | ≈ 33 | −28 |
| **natural unlocking** | **33,586** | **≈ 33,298** | **≈ −288** |

**Op (worst, standard), derived:**

| | in0 | in1 | in2 | in3 | total |
|---|---|---|---|---|---|
| today | 4.793M | 7.349M | 7.323M | 6.052M | 25.517M |
| A1 | −2k | −4k | −4k | −4k | −14k |
| A2 | −59k | −54k | −32k | −32k | −177k |
| A4 | −1k | −1k | −1k | −0k | −3k |
| A5 | −5k | – | – | – | −5k |
| A6 | +3k | +2k | +2k | +3k | +10k |
| A7 | −3k | −3k | −3k | −3k | −12k |
| A8 | −5k | −7k | −6k | −6k | −24k |
| A9 | −150k | – | – | – | −150k |
| **v2 (before re-cut)** | **≈ 4.571M** | **≈ 7.282M** | **≈ 7.279M** | **≈ 6.007M** | **≈ 25.14M** |

A5 and the re-cut move whole events between inputs. The totals hold; the per-input split is set by tune.

**Score:**
- Need ≈ 25.14M / 750.4 − 164 + 48 ≈ 33,386 B of unlocking; natural ≈ 33,298 B. Op still binds, with ≈ 90 B of filler.
- **Score ≈ 33,386 + 140 + 192 ≈ 33,718 B**, against 34,229 (−511 B, −1.5%).
- If op falls only 0.30M: ≈ 33,811. If it falls 0.45M, natural binds: ≈ 33,630.
- Fixture op ≈ 24.15M − 0.36M ≈ 23.8M standard (≈ 23.7M consensus).
- **Floor for the combined plan:** ≈ 33,298 + 332 ≈ 33,630 B, or ≈ 33,534 B with O1. Another angle's op savings stop
  helping once need reaches this. The −70 B from a 6.0% margin is the owner's call and is not counted.

## 4. Soundness sketch (owner check for every new or changed binding)

Unchanged:
- the protocol (the 33 identities, the batching ε ≤ 275/2²⁵⁶, the GT-GLS relation, curve and twist checks)
- rules 1, 3, 4, 5, 7, 8
- every owner in the README table except the rows below.

Changed rows:

| value | owner in v2 | what changed |
|---|---|---|
| input count | `TXINPUTCOUNT = 4` in role 0 (A1) | moved from R into role 0; reached through the hub argument |
| sibling code | role 0: UTXOBYTECODE(h) = UTXOBYTECODE(0) for h = 1..3; every R: UTXOBYTECODE(INPUTINDEX) = UTXOBYTECODE(0) (A1) | the 4×4 comparisons become 3 + 4 through input 0 |
| input order / role | OP_INPUTINDEX + 1 dispatch | unchanged; the segment order is a program constant (A5) |
| program | SHA256 (O1: HASH160) = H_blob in R, over part₁ ‖ part₂ cut by R | R also keeps the two carrier prefixes; the hashed bytes are unchanged |
| carrier-prefix fields (G₁, G₂, CL₁, CL₂, constant pieces) | INPUTBYTECODE(c)[0, off_c), cut by R; offsets fixed by the owner's layout pins | the same bytes as a fresh introspection (A2) |
| z, ρ | head: ZR = z_raw ‖ ρ_raw byte for byte; every user uses decoder U | the hand-off is the hash outputs, not NUM2BIN (A4) |
| final R | computed in input 0 by its own segment | the R̃₃ claim is gone (A5) |
| seam claims R̃_i ‖ T̃_i (i = s0, s1, s2) and the δ start points | as today: producer byte equality with C48 canonical values, consumer decodes the same bytes; δ starts pinned by K_HASH | the producer→consumer pairs are now in1→in2, in2→in3, in3→in0 |
| layout | DEPTH + the SIZE of each of the 10 pushes; fields at fixed sub-offsets; filler slice = zeros | fewer pushes (A6); checks at first use (A8); end-of-string checks replaced by a build assertion (A7) |
| public-input binding | Σ_i \|x\|^i·a_{k,i} = n_k exactly, a_{k,i} gathered from the hashed nibbles; nibbles ≤ 0x0f; n_k < r | the same integer, evaluated by bit planes (A9) |

**Multi-input binding, end to end:**
1. **Code.** Any valid R-input forces input 0 to be R (A1). Input 0 forces count = 4 and all four lockings equal. So all
   four inputs run R, the program (hash-pinned), and role = index.
2. **Layout.** Each input pins its own push count and sizes. Every slice any input reads from it, through a fresh
   introspection or a carrier prefix, is therefore the intended field.
3. **Data before the challenges.** The head hashes G₀..G₃ (fixed sizes, fixed arity) into h₀ before ρ and z. Each
   input computes with exactly its own G_i. A consumer reads its predecessor's last state from the predecessor's G.
4. **Values after the challenges.**
   - z and ρ reach every input as identical hash bytes.
   - Each seam carries (R̃, T̃), checked byte for byte by the producer against canonical encodings of computed values,
     and decoded by the consumer.
   - The δ start points are VK constants pinned by K_HASH.
5. **The chain.** By induction over s0 → s1 → s2 → s3, the four inputs together compute
   R = Σ_k ρ^(32−k) D_k(z), which is exactly the single-input check. Input 0 then checks R ≡ Q(z)·M(z) with its own R.
6. **Public inputs.** A9 computes the same integer as today from the same hashed bytes, so the GT-GLS relation is
   unchanged.

No new trust assumption is introduced. A3, which would have added one, is deliberately left out.

**New rejection cases for `redteam.mjs` (all ordinary rejections):**
- input 0 under a foreign locking with inputs 1–3 under R (inputs 1–3 must fail at the hub check)
- input h ≠ 0 under a foreign locking (input 0 fails)
- a 5th input and a 3-input tx (input 0 fails)
- inputs swapped (role and layout fail)
- a ZR byte flipped
- a carrier prefix field changed (the head's transcript or the consumer's pin fails)
- n_k ± 1 and n_k + r
- a nibble byte 0x10 and 0x1f (the mask check fails)
- the old R̃₃-style claim tests replaced by seam tests on in3→in0

## 5. Considered and rejected (with numbers)

| idea | result |
|---|---|
| Hash-committed hand-off (producer pins H(claims), consumer carries the claims) | +32 B per seam, no op saved: the values must exist as bytes somewhere and still need one introspection |
| Each Miller input hashes its own region; the head reads H̃_i from input 0 | +96 B; op is zero-sum (the head saves ≈ 50k of SHA, the siblings pay it); dominated by A2's prefix reuse |
| Drop consumer range checks (A3) | −36k op for +40–80 B of code: neutral, and adds a cross-input clause |
| Derive R_{k,1} = Frob(R_{k,0}) on chain (−576 B of GLS constants) | +≈ 190k op per input (Frobenius coefficients plus 10 mulmods) ≈ +1.0 kB of need |
| Head-only input 0 plus 3 Miller inputs | needs ≈ 23.6M on three inputs, cap 3 × 7.53M = 22.6M; and input 0's WQ budget would be wasted (≈ 1.3–1.9 kB) |
| Single program carrier, or input 0 as a carrier | the most room any input has for program bytes is ≈ 4.7 kB at the cap (input 0 ≈ 0.9 kB), less than the 6.3 kB program; a third carrier costs +1 introspection per input (≈ +80k) |
| Move GLS positions 0–7 out of input 0's chunks | the factors would enter at exponent 2^(7−g), so polynomial degrees blow up and so would n_q |
| Statement digits as 4 × 8-byte integers (−64 B; binding becomes 3 MULs) | per-event bit extraction costs +2.5k × 63 events ≈ +160k on the Miller inputs; dominated by A9 |
| Skip the input-count check | the policy requires a count bound; kept, now in role 0 (A1) |

## 6. How this combines with other angles

- **A2, A6 and A8 touch the data-move code** (breakdown item 1). A2 only changes how fields are fetched across inputs,
  and A6/A8 change the prologue. Item 1's per-event re-split fix (≤ 500 B pieces) composes with them.
- **A9 is in the head, which no other breakdown item covers.**
- **Kernel and setup savings** (breakdown items 2 and 3, about 0.6–1.0M) are capped by the natural floor. With angle A
  that floor is ≈ 33.63 kB (≈ 33.53 kB with O1); without it, ≈ 33.92 kB. So angle A's ≈ 290 B of byte cuts are exactly
  what lets about 290 B more of the other angles' op savings reach the score.
- A10 applies only if the merged build is still op-bound.

## 7. Implementation order and checks

Each step ends with `node build.mjs`, `test-protocol.mjs`, `redteam.mjs` and the sweep subset (forced 44, 44d3, ALL15,
random B and C).

1. A4, TAG, A7: local; no layout change.
2. A9: head only. Port `binding-proto.mjs` into `head()` as a shared function called twice, and add the exhaustive
   gather check to `build.mjs`.
3. A1 and A2(a): R and role 0, plus the carrier-prefix stack contract; A2(b) and (c) in READ0 and WORK.
4. A6 and A8: the push model in `protocol.mjs` (`pushesOf`, `offsetOf`, transcript slices) and the role prologues.
5. A5: role order, initial value in role 1, terminal in role 0.
6. Then `measure.mjs` → `layout.mjs` → `tune.mjs` (MARGIN 0.062, the A2 placement rule as a constraint), the full sweep
   (≥ 667 proofs, both modes), and the 3,600-proof review families.
7. Ship as a new directory `chunked/bls12-381/bls-native-sound-v2` and bench id
   `bch-groth16-bls12381-sound-native-v2`; the current entry stays.

**Risks:**
- **Gains are modest** (−1.2 to −1.7%). The A2 numbers depend on tune honouring the placement rule. If a remote piece
  must be fetched by a fresh introspection, the cost is ≈ +20k per such piece.
- **A5 changes which input is tight at which witness.** Input 0's worst becomes forced n_q 44 with the nibbles in
  positions 57–63, while ALL15 stays the worst for in1–3. The margins must be re-measured.
- **A7 relies on a build-time assertion** instead of a runtime check. Reviewers may want the runtime check back
  (+45 B, +12k).
- **A2's prefix contract adds two stack items to every role.** An off-by-one in DEPTH pins would show up as a
  rejection, not as unsoundness, because the pins are exact.
- **The estimates are derived, not built.** Only A9 is prototyped on the VM. Expect ±30% on A2, A6 and A8.

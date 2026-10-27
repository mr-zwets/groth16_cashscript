# DESIGN-2 (angle B, structure): bch-groth16-bn254-sound-native-v2, "SI-MX3-H1"

Task native-bn-design2, design only. The base is the reviewed entry `bch-groth16-bn254-sound-native` (27,624 B, 3 inputs,
20.67M op, code sha256 75c780ae…78d7, `chunked/bn254/bn-native-sound`). The numbers come from `work/native-bn/BREAKDOWN.md`
and two new measurements:
- `rdetail.mjs` gives the op cost of every instruction of R and the body prologue in each input;
- `model.mjs` is a score model calibrated on the measured build. It reproduces 27,622 for the current entry, against
  27,624 measured.

Both scripts are on branch `wip/native-bn-design2`, in `research/native-bn-design2/`.

## 0. Summary

The mathematics, kernels, loop, transcript and terminal stay exactly as in the reviewed build. Only the structure
around them changes:

| id | change | content Δ | op Δ (Σ over roles) |
|---|---|---|---|
| B1 | **One code host, single-range R** (52 B instead of 65): input 0 = `[DS_0][C][FILL_0][R]` | −39 (R) | −99k |
| B2 | **Re-home S_0 and HAND_1** (S_0 → input 1, HAND_1 → input 2); `DG = d1 ‖ d2` with `d1 = SHA256(S_0 ‖ S_1)`; remote reads split prefix-first | −32 (DG) | −66k (remote −73k, transcript +7k) |
| B3 | **One SI-GLS program for all roles**: the role programs become a per-role constant record plus shared prologue and epilogue functions, dispatched by function id | −600 (−450…−750) | +15k |
| B4 | **Re-cut** at `[0, 24, 46, 65]`, which moves chunk 23 to role 2. Possible because input 0 now holds only VK data | 0 (moves bytes) | 0 (moves op) |
| B5 | (margin ≤ 4% only) **HAND_1 without F±**: role 1 sets `F± = S'(±z)` from the last state of S_0, which it hosts | −64 | +20k |
| B6 | (option, owner) **P2S locking = R** | −159 unlocking, +51 locking | 0 (budget −42k per input) |

Estimated results (fixture 0, standard mode; filler sized per input to the margin):

| margin | current entry | B1–B4 | B1–B5 | B1–B5 + P2S |
|---|---|---|---|---|
| 6% (today's rule) | 27,624 | **27,422** (−202) | 27,449 | 27,499 |
| 4% | 27,419 | 26,951 | 26,890 | 26,930 |
| **3%** | 27,419 | 26,858 | **26,791** (−833) | 26,736 |
| 2% | 27,419 | 26,766 | 26,700 | 26,645 |

- **Op cost:** about 20.52M in total. Per role: 6.96 / 6.38 / 7.18M, or 6.96 / 6.40 / 7.18M with B5.
- **Inputs:** 3. Every unlocking is ≤ 9,515 B, ≤ 9,961 B at the worst quotient length (n_q = 132).
- **Cap rule:** every role's worst case is ≤ 7.34M, against the rule's limit of 0.94 × 8,032,800 = 7.55M.
- **Content floor:** B1–B5 bring the content down to 26,426 B, so the score floor is 26,680. That floor binds once
  the margin is ≤ 3% and angle-A op cuts of ≥ 0.3M land (§5).

What the angle can and cannot do: every input is op-bound. A structural change is only worth something if it cuts op
and bytes together, or if the margin is lowered. At the 6% rule the structure alone gives about −200 B. At 3% it
gives about −560 B beyond what the margin change alone gives (27,419), and it sets the content floor that angle-A op
work can then reach.

## 1. Constraints and model

- Per input: `unlocking_i = max(content_i, ⌈op_i / (800·(1−m))⌉ − 41)`, and every unlocking ≤ 10,000 B.
- Score = Σ unlocking + 3 × 35 (P2SH32 locking) + 149 (tx overhead).
- Standard tx ≤ 100 kB. Op cost is in standard mode; consensus mode is about 0.5% lower.
- Cap rule (kept): every input's worst-case op ≤ 0.94 × 8,032,800 = 7,550,832.
- No read-only inputs. OP_DEFINE/OP_INVOKE and nested definitions are used as today (libauth BCH_2026).

**The model (`model.mjs`):**
- Op outside the loop per role is the measured value: 886,431 / 839,632 / 2,377,322, with role 2 including the
  quotient at n_q = 114 (6.6k op per quotient word).
- Loop op per chunk is `1.037 × (183k · events + 152k · additions + 27k)`. The factor 1.037 is calibrated on the three
  measured loops; it fits all three within 0.2%.
- Chunk content is `192 + 96 · B-steps`: the state, one `t` (32 B) per step and one δ slope (64 B) per step.
- Own unlocking pushes cost 1 op per byte.
- The structural op deltas (§3) are per role.

**Op costs measured on the current R** (`rdetail.mjs`, per instruction):
- `INPUTBYTECODE` = 100 + length.
- `SPLIT` = 100 + length of the item that is split.
- `CAT` and `DUP` = 100 + length.
- `SHA256` of the 7,310 B code = 22,212, about 3 op per byte.
- Each body definition = 100 + length (push) + 100 (DEFINE).
- Today's R costs 82.4k per input before the body runs: two bytecode reads of 9.4k each, four SPLITs totalling 26.6k,
  CAT 7.4k, DUP 7.4k and SHA 22.2k.

## 2. Per-input layout (B1–B4; cuts [0, 24, 46, 65]; fixture 0, n_q = 114)

Every push is minimal and R is last. Offsets are into the unlocking bytecode.

```
input 0  [DS_0 2,048 @3] [C 6,710 @2,054]                                                     [FILL_0] [R 52]
input 1  [S_0 3,328 @3] [S_1 3,040 @3,334] [DS_1 1,856 @6,377]                                [FILL_1] [R 52]
input 2  [DG 64 @1] [STMT 642 @68] [HAND_1 224 @712] [HAND_2 224 @938] [S_2 2,784 @1,165] [DS_2 1,728 @3,952]
                                                                                       [FILL_2 @5,680] [WQ] [R 52]
```

| | input 0 | input 1 | input 2 |
|---|---|---|---|
| role events / chunks | [0,24) / 0–11 | [24,46) / 12–22 | [46,65) / 23–32 + terminal |
| content (filler 0) | 8,818 | 8,287 | 9,385 (9,961 at n_q 132) |
| op, standard (model) | 6,962,514 | 6,377,017 | 7,181,865 (≈ 7.33M worst) |
| unlocking at 6% / 3% | 9,218 / 8,932 | 8,440 / 8,287 | 9,510 / 9,385 |

- Fixed-size items come before every variable push, so every range another input reads has a fixed offset: C in
  input 0; S_0 in input 1; DG, STMT, HAND_1 and HAND_2 in input 2.
- The z-tail `ZT` is unchanged: `push(FILL_2) ‖ push(WQ)`, from offset 5,680 up to the R push.

**Who reads what:**

| role | reads (besides its own stack) | bytecode reads |
|---|---|---|
| 0 | input 1: `S_0`; input 2: `DG, STMT, HAND_1, ZT` | 3 (R: in 0; in 1; in 2) |
| 1 | input 2: `DG, STMT, HAND_1, HAND_2, ZT` | 2 (R: in 0; in 2) |
| 2 | — | 2 (R: in 0; own, for `ZT` and the raw-size pin) |

Today the three roles make 5 / 4 / 3 bytecode reads, 12 in total; the new layout makes 7.

## 3. The changes in detail

### B1: one code host, single-range R

```
R (52 B) = <0> OP_INPUTBYTECODE <2054> OP_SPLIT OP_NIP <|C|> OP_SPLIT OP_DROP
           OP_DUP OP_SHA256 <K_code> OP_EQUALVERIFY <1> OP_DEFINE <1> OP_INVOKE
```

- The code (≈ 6.7 kB after B3) is one push in input 0, behind the δ slice `DS_0`. That item is the only other content
  of input 0.
- **Why it fits only after the re-homing:** `C + S_0` (10.0 kB) does not fit in one input, `C + DS_0` (8.8 kB) does.
  That is the "single code host" item of the breakdown (§3.5), done without moving `S_0` into a role that has no room.
- **Op, per role:**
  - R goes from 82.4k to about 53k: one bytecode read (≈ 8.9k), a 8.9k and a 6.9k split, DUP 6.7k, SHA 20.5k.
  - The body definitions are about 0.6k cheaper (smaller code).
  - Net −33k per role, −99k in total.
- **Content:** −13 B of R × 3.

### B2: re-home S_0 and HAND_1; DG = d1 ‖ d2; reads split prefix-first

- **What moves where:**
  - `S_0` moves into input 1, so input 0 holds only VK data.
  - `HAND_1` moves into input 2. Roles 0 and 1 read input 2 anyway, so the 0→1 handover needs no extra bytecode read.
- **Digests:**
  - `d1 = SHA256(S_0 ‖ S_1)`, checked by role 1 on its own stack items (input 1).
  - `d2 = SHA256(STMT ‖ S_2)`, checked by role 2.
  - `d0` is gone: input 0 hosts no prover data.
  - `DG` is 64 B, and `h0 = SHA256(TAG ‖ DG)` is unchanged in form.
- **Reading another input, cheaper:** today `remote()` splits the whole 9 kB bytecode once per header and per item,
  about 9 splits of ≈ 8k each (80k for role 1). The new order is:
  1. one split at the end of the fixed head region (1,162 B in input 2; 3,331 B for S_0 in input 1);
  2. one split at the `ZT` start and one at the R push, both on the tail;
  3. every header check and item split on the small head.

  Estimate: in2 ≈ 40k (today 80k for role 1); in1 for S_0 ≈ 21k. Role 0 goes from 94k to about 61k (−33k), role 1
  from 80k to about 40k (−40k).
- **Transcript:** role 0 no longer hashes S_0 (−13k: pick plus SHA of 3.3k). Role 1 hashes `S_0 ‖ S_1` (+20k: two
  picks, CAT, SHA of 6.4k).
- **Content:** −32 B (DG).

### B3: one SI-GLS program, split across inputs

The three role programs (804 / 720 / 2,373 B) repeat role 2's prologue twice. Following SI-GLS, there is one program
and the role only supplies a range:

```
body:  define shared functions (as today) + PRO, EPI_H, EPI_T, START_0, START_H, ROLE_0..2
       OP_INPUTINDEX <ROLE_0> OP_ADD OP_INVOKE
ROLE_i (≈ 30–60 B + constants): push role i's constant record, <PRO> OP_INVOKE, <START_x> OP_INVOKE, <LOOP> OP_INVOKE,
       <EPI_x> OP_INVOKE
```

- **The constant record:**
  - the event range `a, b` and the nibble-slice offsets;
  - the stream record lengths and the δ-pile piece count;
  - `SCH`, `BND` and `d0`;
  - the δ start state (6 × 33 B);
  - `K_DS[i]`;
  - the item sizes of the own layout and the remote-read offsets.
- **PRO** runs layout, graph, remote reads, transcript, statement decode, slices, δ pile and setup arrangement, with
  the per-role differences coming from the record. It is one generic copy instead of three; role 0's curve and twist
  checks (177 B) and role 2's ψ(B) stay in START_0 and EPI_T respectively.
- **START_0** sets `T = B`, `F± = S_c(∓z)`, `R = 0`. **START_H** runs HDEC (and the F± evaluation under B5).
- **EPI_H** (roles 0 and 1, one copy): consumption checks, HENC, compare with the next HAND, cleanup.
- **EPI_T** (role 2): terminal, binding, quotient, cleanup. It is today's role-2 tail, verbatim.
- **Small items that come with it:**
  - the role-0 δ start `x` is deduplicated with SETUP's `xd` (−66 B);
  - roles 0 and 1 share one cleanup chain (−52 B);
  - one shared head reader for input 2 (−40 B).
- **Estimate:** −615 B, applied as −600 (range −450…−750), consistent with BREAKDOWN §3.2. Op is +5k per role, for
  the extra INVOKEs and the record pushes. Every role pushes its constants already today.
- **Why dispatch by function id and not IF:** on bch-2026 an unexecuted branch costs 100 per skipped instruction.
  The id comes from the authenticated code and is bound to `OP_INPUTINDEX` by GRAPH.
- **Build check:** each record is derived from `CUTS` and asserted against the single-input schedule, as today's
  `SCHEDULE`/`DS`/`DSTATE` asserts are.

### B4: cuts at [0, 24, 46, 65]

- After B1 and B2, input 0's content (8,818) no longer depends on role 0's event range, apart from the 64 B δ slope
  per B step. Input 1 hosts both `S_0` and `S_1`.
- The cuts can therefore balance op against content per input.
- **Search space:** all chunk-boundary cuts, subject to:
  - content ≤ 10,000 B and unlocking ≤ 10,000 B at n_q = 132;
  - the cap rule at the worst case.
- **Result:** cut 2 at 46 is best at every margin. It moves chunk 23 (events 46–47, one addition, 480 B, ≈ 0.57M) from
  role 1 to role 2.
- **Fallback:** if the final code or role-2 op comes out worse, use `[0, 24, 48, 65]`. It costs +147 B at 6% and
  +139 B at 3%. Input 2 at n_q = 132 is 9,961 B with cut 46 (39 B spare) and 9,481 B with cut 48.

### B5 (margins ≤ 4%): HAND_1 = (T, R)

- The 0→1 cut is a chunk boundary. In the single run, role 0's last BNDSTEP sets `F± ← S'(±z)`, where S' is the last
  state of `S_0`, and `S_0` is hosted in role 1's own input.
- Role 1 splits S' off its own `S_0` item, decodes it (6 words, each `< p`) and runs one EV. HAND_1 shrinks to 5 words
  (160 B).
- **Cost:** −64 B content; op is +22k in role 1 (EV, decode, split) and −2k in role 0 (two fewer HENC words).
- It only pays when inputs are content-bound (margin ≤ 4%): at 6% it is +27 B. HAND_2 keeps F±, because doing the same
  there needs a remote state read in role 2 (≈ +35k op), which is about net zero.

### B6 (option, owner decision): P2S

- The 52 B R is under the 201 B P2S standard locking cap: libauth BCH_2026 has `maximumStandardLockingBytecodeLength
  = 201`. So R can be the locking itself.
- **Bytes:** each unlocking drops the 53 B R push and each locking grows from 35 to 52 B.
- **Op:** the budget drops 42.4k per input, so it only pays when content-bound: −55 B at 3% and at 2%; it is worse by
  40 B at 4% and by 50 B at 6%.
- **What changes:**
  - GRAPH still compares `UTXOBYTECODE(j)` with the own one, which is now R itself;
  - the raw-size pin and `ZT` end at the bytecode length, since there is no R push;
  - the score's locking is 52 B per input.
- **Open:** whether the bench counts P2S locking bytes like P2SH32's 35, and the owner's OK to leave P2SH32. It is
  listed and not counted in the headline.

### Not counted (optional knobs)

- **B7: drop the raw-size pin in roles 0 and 1.** DEPTH, the exact sizes and consensus MINIMALDATA/push-only already
  fix the raw length. Saves about 10k op per role and about 30 B. It removes a redundant belt, so it is a reviewer
  call.
- **B8: R leaves the host's tail on the stack** (`… <|C|> OP_SPLIT OP_SWAP OP_DUP …`, +1 B of R). Data placed after `C`
  in input 0 is then free for every role, which is a fine-balancing knob: moving `HAND_2` into input 0 is about −58 B
  at 3%.
- **Mid-chunk cuts:** finer balance, but they break the "cuts at chunk boundaries" spec rule. Not proposed.

## 4. Soundness sketch (owner check for every new or changed binding)

The claim and the error bound stay exactly as in the README: `ε ≤ q_H · 2^−245` plus a SHA256 collision term. Every
role still derives `(h0, ρ, z)` itself, every value has the same owner as today, and the loop, terminal, binding and
quotient code is byte-identical in function. Only these bindings change:

1. **Code identity (B1, B3).**
   - The spent output forces R (P2SH32: hash of R; B6: R itself).
   - R hashes exactly the bytes it defines: `C` = the range `[2054, 2054+|C|)` of input 0. That range lies before the
     variable `FILL_0`. Nothing is re-pushed between the hash and the define.
   - Whatever bytes sit at that range, they are accepted only if they hash to `K_code`. So the code is authenticated
     even if input 0's layout were wrong. Input 0's own layout pin is needed only for liveness.
   - All role constants (cut ranges, schedules, slice offsets, δ start states, `K_DS[i]`, item sizes, remote offsets,
     START/EPI function ids) are inside `C`. They are VK constants under `K_code`.
   - Function ids are asserted distinct at build. A redefinition fails in the VM, and an index without a ROLE id fails
     as an undefined function.
2. **Multi-input binding (unchanged rule, new hosts).**
   - GRAPH: `TXINPUTCOUNT == 3` and `UTXOBYTECODE(j) == own` for j = 0..2. So every input runs the same authenticated
     code, the role equals the index, and the transaction is valid iff all three roles accept.
   - This pins the input count, the order, every sibling's code, and therefore the host of `C` (input 0, which must
     spend the same R).
3. **Committed data now hosted away from its user (B2).**
   - `S_0` lives in input 1. Its owner is **role 1**: `d1 = SHA256(S_0 ‖ S_1)` is computed from role 1's own stack
     items and compared with `DG[0,32)`. Role 1's layout pin (DEPTH, exact sizes, raw size) fixes those items at
     `[3,3331)` and `[3334,6374)`.
   - Role 0 reads `[3,3331)` of input 1 after checking the 3-byte push header in front of it. Under consensus
     push-only and MINIMALDATA, that is the same consensus byte string role 1 hashed.
   - So the stream role 0 consumes is fixed by `h0`, before ρ and z. Role 0 does not need to re-hash it: if role 1
     rejects, the transaction is invalid.
   - `d2` is unchanged. `DG` has a fixed width (64 B) and is read at a fixed, header-checked offset by every role, so
     `h0` determines `(S_0, S_1, STMT, S_2)` up to a SHA256 collision, as today.
   - Input 0 hosts no prover data: `DS_0` is a VK constant (`K_DS[0]`) and `C` is under `K_code`. `FILL_0` is all zero
     and read by nothing (txid-only malleability, as today).
4. **Handover HAND_1 hosted in input 2 (B2).**
   - **Ownership:** HAND_1 is fixed by byte equality with role 0's canonical encoding of its computed end state, with
     the top byte checked. Role 0 reads HAND_1 at `[712, 936)` of input 2 with its header check, and role 1 reads the
     same range. Input 2's layout is pinned by role 2 (DEPTH, sizes, raw size).
   - **Induction:** the same bytes, compared by role 0 and decoded `< p` by role 1, mean role 1 starts from exactly
     the single-run state after event 23. The handover induction (README §4) goes through verbatim.
   - HAND_2 is unchanged in content. It simply stays hosted in input 2, which is now role 2's own input, and the
     argument is the same.
5. **B5: F± at the 0→1 cut.**
   - Role 1 computes `F± = S'(±z)` on-chain. S' is the last 6 words of `S_0` (owned via d1 as in item 3; each word is
     decoded `< p`), and z is its own challenge.
   - This is by definition the value role 0's final BNDSTEP assigns, so the single-run state is preserved. Role 0's
     last R update reads the same S' bytes.
   - HAND_1 then covers `(T, R)` only. Both are still fixed by role 0's equality.
6. **Cuts (B4).**
   - 46 is a chunk boundary, as the spec requires. Role 1's last chunk record ends with S_23, role 2 starts at event
     46, and the δ start state for role 2 is `DSTATE[46]`, baked and asserted.
   - Per-role `SCH`/`BND` are asserted against `DIGITS`/`isBoundary`. The build re-runs the role-split value mirror
     against one uninterrupted run, and the states against SI-GLS (fixtures 0 and 4).
7. **Remote-read restructuring (B2).** The ranges read and the header bytes checked are the same as before; only the
   order of SPLITs changes. This is a pure framing change.
8. **What is deliberately not changed:**
   - no value is handed over without an equality owner;
   - no challenge is handed over;
   - no new prover-chosen item enters the transcript (DG shrinks; ZT is unchanged);
   - every decoded word is still `< p` (or `< r`) where it is decoded.

**Gates to add or extend (rejection tests only):**
- tamper `S_0` in input 1 (with `DG`, the challenges and the handovers recomputed);
- tamper `HAND_1` at its new host (+1, +p alias, a word from another proof);
- swap `S_0`/`S_1` order;
- shift `C` by a non-minimal push in input 0;
- put a foreign P2SH32 input at index 0 that carries input 0's honest pushes (GRAPH must fire in inputs 1 and 2);
- with B5: tamper the last state of `S_0`;
- staple whole inputs from a second proof at each seam.

The existing 24 invalid vectors and the red team carry over, with offsets regenerated.

## 5. Interaction with angle A, and the floor

The content of B1–B5 is 8,818 + 8,287 + 9,321 = 26,426 B, so the score floor is 26,680. With the margin at 3% and
B1–B5 alone, input 0 is still op-bound (8,929 against 8,818 of content): score 26,791. Angle-A op cuts compose
directly (modelled as a flat cut spread over the roles):

| angle-A op cut | 6% | 4% | 3% | 2% |
|---|---|---|---|---|
| 0 | 27,449 (B1–B4: 27,422) | 26,890 | 26,791 | 26,700 |
| −0.3M | 27,050 | 26,754 | 26,680 | 26,680 |
| −0.6M | 26,812 | 26,680 | 26,680 | 26,680 |

Below the floor, only content cuts help:
- the DEPTH-loop cleanup, about −100 B;
- B6 (P2S), −55 B net;
- code compaction from angle A.

## 6. Structural alternatives examined and rejected (with numbers)

| alternative | estimate | verdict |
|---|---|---|
| 2 inputs | the loops alone are about 16.6M, which exceeds 2 × 7.55M (cap rule) and even 2 × 8.03M at 0% margin | impossible |
| 4 inputs | +1 input tax ≈ 0.8M op (setup 0.47, R, transcript, slices, statement) ≈ +1,060 B, plus +35 locking, +43 tx, +53 R; there is no cap pressure to relieve | +≈1.2 kB |
| Setup tables computed once, hosted once, read by the other roles (64 words) | +2,048 B content against ≈ −0.5M op (≈ −640 B); recomputing a word on-chain costs ≪ 24k op (its byte price) | +≈1.4 kB |
| Hand over the 16 base evaluations R_{k,i}(±z) | +512 B against ≈ −0.24M op (−320 B) | worse |
| Per-role code loading (two-level hash, load only shared + own role) | ≤ −10k op per role, and +32…99 B of digests | no |
| Commit `ZT` by a digest `dq` in input 2 | −52k op (roles 0 and 1 skip hashing and splitting ZT), +35 B | ≈ 0, no |
| Drop `DG`, every role hashes all streams | +≈40k op per role for −98 B | worse |
| Code and the common data (DG/STMT/HAND) co-hosted in input 0, read via R's tail | about −20k op more, but needs `dq` (+33 B), and `DS_0` must then be read remotely | ≈ 0; B8 keeps the knob |
| Code in input 2 | STMT + WQ (≤ 4.9 kB) + C (6.7 kB) > 10 kB | does not fit |
| The SI-GLS projective program split across 3 inputs | Σop 23.4M + 1.8M of tax ≈ 33.5 kB of budget | worse |
| Chunk size 3 / 1 | the quotient roughly doubles (+4 kB, +0.9M) / +32 states (+6.1 kB) | worse |
| Dropping F± from HAND_2 too | +≈35k op (remote state read in role 2) against −64 B | ≈ 0 |

## 7. Build plan (new id `bch-groth16-bn254-sound-native-v2`; the current entry stays)

1. Copy `chunked/bn254/bn-native-sound` → `chunked/bn254/bn-native-sound-v2`. Change `protocol.mjs`:
   - `CUTS = [0, 24, 46, 65]`;
   - `D_SIZE = 64` with `d1 = SHA256(S_0 ‖ S_1)`;
   - `HAND_1` = 160 B under B5;
   - `TAG = "BNMX3/2" ‖ VK digest`, a new domain tag.
2. `script.mjs`:
   - new `layoutFor`;
   - single-host `redeemFor`;
   - prefix-first `remote()`;
   - role records, PRO/START/EPI functions and ROLE_i dispatch.
3. `transaction.mjs`: the new unlockings. Fillers sized to the agreed margin.
4. Run build, export, redteam (extended per §4), the sweep (424 cases, cap rule) and profile. Compare against §2,
   with these acceptance targets:
   - score ≤ 27,450 at 6%, ≤ 26,900 at 3%;
   - op per role within ±60k of the model.
5. Run the bench exact-id gate driver on the new id. Do not touch the reviewed entry.

## 8. Risks

- **Code-size estimate of B3 (−600 ± 150 B).** It is the main uncertain number. At 6% it does not matter, since input
  0 is op-bound by 400 B. At 3% each byte counts while input 0 stays op-bound: the pessimistic 6,860 B code gives
  26,894 (B1–B4).
- **The model's loop op** is calibrated to 0.2% on the measured roles. Moving a chunk is modelled at
  1.037 × (2 × 183k + 152k + 27k). Expect ±50k per role. Fallback cuts are `[0, 24, 48, 65]`.
- **Input 2 at n_q = 132 is 9,961 B with cut 46** (39 B under the 10,000 B cap). Any growth of the role-2 items, or a
  larger WQ cap, needs cut 48. The sweep must include the n_q = 132 case.
- **Margin.** The headline 26,791 assumes the owner lowers the build margin from 6% to 3%. At 6% the structure gives
  only −202 B (27,422).
- **B6 (P2S)** needs the owner's OK and bench support for P2S scoring. It is not in the headline.
- **Soundness review delta.** These are new bindings that a reviewer must check:
  - cross-input ownership of `S_0` (hashed by role 1, consumed by role 0);
  - HAND_1 hosted in a third input;
  - B5's F± recomputation;
  - the unified dispatch (record tables).

  Each is a direct instance of an existing rule: owner hash plus pinned framing; equality owner; on-chain computation;
  VK constants under `K_code`.

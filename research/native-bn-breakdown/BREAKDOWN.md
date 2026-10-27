# bch-groth16-bn254-sound-native: byte and op-cost breakdown (task native-bn-breakdown)

Read-only measurement of the reviewed entry (groth16_cashscript origin/main 17b05a7, `chunked/bn254/bn-native-sound`,
code sha256 75c780ae…78d7), fixture 0, libauth BCH_2026. Scripts: `research/native-bn-breakdown/{bytes,ops,walk,lazy}.mjs`
on branch `wip/native-bn`. Profile: `node profile.mjs` (standard mode).

## 0. The governing fact: every input is op-bound, and content is only ~205 B below the op need

Per input, the unlocking must satisfy `len >= op/(800·(1-m)) - 41` (m = 6% build margin) and `len >= content`.

| input | content (filler 0) | op std | op need at 6% | fill | unlocking | budget | margin std / cons |
|---|---|---|---|---|---|---|---|
| 0 | 9,219 | 7,036,431 | 9,313 | 96 | 9,316 | 7,485,600 | 6.00% / 6.46% |
| 1 | 9,221 | 6,995,632 | 9,260 | 41 | 9,262 | 7,442,400 | 6.00% / 6.46% |
| 2 | 8,725 | 6,642,322 | 8,790 | 67 | 8,792 | 7,066,400 | 6.00% / 6.47% |
| sum | 27,165 | 20,674,385 | 27,363 | 204 | 27,370 | | |

Cap rule: worst case per input 7.06M vs 8,032,800 at 10,000 B (12.1% headroom).

Consequences:
- Score ≈ max(Σcontent, Σop/752 − 123) + 254 (3×35 locking + 149 tx). Both are within 205 B of each other.
- A byte cut alone turns into filler (worth 0) until ~205 B of content is gone; an op cut alone is worth
  1 B per 752 op only until the op need drops below content. A v2 must cut both, or change the margin.
- Margin sensitivity (content fixed): 6% → 27,617(+7 hdr); 5%..1% → 27,419 (content binds). Content-only headroom
  this opens: 91 B (5%), 374 (4%), 651 (3%), 923 (2%), 1,189 (1%).

## 1. Bytes per input, by category

| category | input 0 | input 1 | input 2 | total | sibling SI-GLS |
|---|---|---|---|---|---|
| core: 33 states (192 B each) | 2,304 | 2,304 | 1,728 | 6,336 | 6,336 |
| core: affine inverse-norm `t` witnesses (32 B each) | 1,024 | 1,024 | 768 | 2,816 | 0 |
| core: STMT (A,B,C,n, nibbles, s^c) | | | 642 | 642 | 642 |
| core: WQ (114 words) | | | 3,648 | 3,648 | 3,648 |
| VK constant: δ slopes DS_i | 2,048 | 2,048 | 1,536 | 5,632 | 5,665 (incl. hdrs) |
| shared code blob (hosted once, split) | 3,767 | 3,543 | | 7,310 | 5,517 (code 4,057 + consts 1,386 + data 74) |
| state hand-off: HAND_i (7 words) | | 224 | 224 | 448 | 0 |
| state hand-off: DG (d0‖d1‖d2) | | | 96 | 96 | 0 |
| redeem R push (65 B, same in all) | 66 | 66 | 66 | 198 | (redeem is the code) |
| padding bought for op: FILL_i | 96 | 41 | 67 | 204 | 0 |
| push headers | 11 | 12 | 17 | 40 | ~6 |
| **unlocking** | **9,316** | **9,262** | **8,792** | **27,370** | **21,817** |
| locking + tx overhead | | | | 105 + 149 | 35 + 63 |
| **score** | | | | **27,624** | **21,915** |

Repeated shared code: none in bytes. The code blob is hosted once (pieces in inputs 0 and 1) and loaded by every input
through the 65-byte R, so the repetition costs 2 extra R pushes (132 B) plus op (§2).

### The code blob (7,310 B)

- Shared functions 3,311 B, of which SETUP 1,481 (891 B = 27 field constants), BDBL 319, BADD 296, DSTEP 195, LOOP 159,
  STMT 136, HENC 123, TM 111, ADDSTEP 100, TA 78, TRANS 76, BNDSTEP 68, EV 46, small ones ≤ 33. Define overhead ~75,
  dispatch 5.
- Role programs: role 0 804, role 1 720, role 2 2,373 B. By section:
  - role 0: layout 71, graph 2, remote 54, transcript 14, statement 177 (curve/twist checks), slices 125, setup 260,
    post (handover) 47, cleanup 52;
  - role 1: layout 78, graph 2, remote 51, transcript 19, statement 13, slices 134, setup 322, post 47, cleanup 52;
  - role 2: layout 128, transcript 15, statement 207 (incl. ψ(B)), slices 108, setup 318, terminal 1,218 (badd 89,
    dstep 101, badd 107, dstep 51, endpoint 141, Rconst 277, c_j 256, W 196), binding 172, quotient 150, cleanup 53.
- Constants in role code: 231 B in roles 0 and 1 each (δ start state 6×33 + K_DS 33), 858 in role 2.
- Versus the sibling (+1,793 B): constants +892, data +198 (3 schedules, TAG), opcodes/defines +696.
  Attributable to the role split: about 1.6–1.9 kB:
  - role 1's 720 B is entirely a second copy of the prologue, and role 0's 627 B (without its unique curve checks)
    is a third;
  - 2 extra δ start states (396) and 3 K_DS (99);
  - HENC/HDEC/GRAPH/FILL/PLEN (193).
  The affine kernels are smaller than the projective ones, which offsets part of this.

### Multi-input overhead in bytes (score)

| item | bytes |
|---|---|
| role-split code (above) | ~1,600–1,900 |
| HAND_1, HAND_2 (+hdrs) | 452 |
| DG (+hdr) | 98 |
| 2 extra R pushes + 2 lockings + 2 inputs' tx overhead | 132 + 70 + 86 = 288 |
| filler (bought op) | 204 (+1 hdr) |
| **total** | **~2.6–2.9 kB** |

The other ~2.8 kB of the 5.7 kB gap to SI-GLS is the affine `t` stream. It is not overhead: on bch-2026 it is net
positive. A `t` costs 32 B and saves 35k op per doubling (46 B of budget) and 85k per addition (113 B).

## 2. Op cost per input (standard, fixture 0)

| section | in 0 | in 1 | in 2 | single-input analog |
|---|---|---|---|---|
| event loop | 6.150M | 6.156M | 4.265M | (core) |
| - BDBL (108k/doubling) | 2.585 | 2.584 | 1.831 | |
| - DSTEP (49k/step) | 1.570 | 1.570 | 1.177 | |
| - BADD (100k/add) | 0.796 | 0.795 | 0.684 | |
| - LOOP glue (26k/event: digits, GT-GLS lookups/muls, flags) | 0.623 | 0.629 | 0.436 | |
| - boundaries (BNDSTEP + EV) | ~0.33 | ~0.33 | ~0.25 | |
| setup (z powers, S_c(±z), 4 GT-GLS tables, env) | 0.471 | 0.471 | 0.468 | once |
| R: code loading (2×INPUTBYTECODE, 4 SPLIT, CAT, SHA256 7.3 kB, 24 DEFINE) + unlocking pushes | 0.109 | 0.109 | 0.109 | ~0.01 |
| remote reads | 0.094 | 0.080 | 0 | 0 |
| statement decode / checks | 0.088 | 0.039 | 0.064 | once |
| transcript (d_i, h0, ρ, z) | 0.037 | 0.038 | 0.040 | once |
| slices (nibbles, record pre-split, schedules, HDEC) | 0.030 | 0.044 | 0.035 | once |
| layout pin | 0.023 | 0.027 | 0.056 | once |
| post (HENC + compare) | 0.025 | 0.025 | | 0 |
| terminal (2 BADD, 2 DSTEP, endpoint, Rconst, c_j, W) | | | ~0.53 | same |
| binding (65-iteration acc loop) | | | 0.320 | in-loop |
| quotient (114 words) | | | 0.753 | same |
| cleanup | 0.005 | 0.005 | 0.005 | |
| **total** | **7.036** | **6.996** | **6.642** | |

Multi-input op tax, about 1.8M (≈2.4 kB of budget at 752 op/B):
- setup ×2 extra: 0.94M;
- R code loading: 0.31M;
- remote reads: 0.17M;
- statement re-decode: 0.08M;
- transcript, slices and layout pins ×3 instead of once: 0.25M;
- handover: 0.05M.

Even so, the native verifier uses less op in total (20.67M) than the sibling (23.38M std), thanks to the affine walk.

By opcode (role 0), arithmetic dominates:
- MOD costs ≈ a_len·b_len (~2.4k each for 64/32 B) and MUL ~1.3k.
- BDBL: MUL 0.96M + MOD 0.92M of 2.58M; stack shuffling (PICK/ROLL/depth pushes) 0.35M.
- DSTEP: MOD 0.49 + MUL 0.44 of 1.57M; shuffling 0.31M.
- LOOP glue: MUL 0.16 + MOD 0.15 of 0.62M; ~125 instructions/event (26 ROLL, 13 PICK, 33 depth pushes).
- TM: 44 MOD + 44 MUL = 0.15 of 0.19M.
- Roughly 29% of all op is MOD and 28% is MUL.
- The existing greedy lazy-reduction pass (`LAZY=1`) is worse: code −38 B, op +74k (20,743,208 vs 20,669,047, fixture 0, filler 0).

## 3. Largest reducible items (estimates; "op-side" B = op/752)

1. **Build margin 6% → 2–3% (owner decision; no code change).**
   - Op is measured exactly, not modelled: roles 0 and 1 vary by under 0.5% across the 424-case sweep, and role 2 is
     prover-sized per proof. The cap rule (worst case ≤ 94% of the 10 kB budget) is separate and still holds.
   - Immediate saving: −205 B (the fillers; content then binds at 27,419).
   - It also opens 651 B (3%) or 923 B (2%) of headroom, in which items 2 and 5 count byte for byte.
   - Without it, content cuts are worth 0 until the op cuts match them.
2. **Role-program duplication: −400 to −700 B content, op ≈ 0.**
   - Roles 0 and 1 (804 + 720 B) re-implement role 2's prologue: layout, graph, remote, transcript, slices,
     setup arrangement, post and cleanup.
   - Fix: one shared prologue function driven by a small per-role constant table (sizes, offsets, schedule,
     record lengths).
   - Smaller pieces:
     - 2DROP cleanup chains 3×52 B → one DEPTH loop: −~100 B, +~15k op per role;
     - dedupe the role-0 δ start x with SETUP's xd: −66 B;
     - optionally move DS_i into the code blob, so K_code authenticates it: −~90 B net (3 K_DS and their checks,
       but +13 B of R per extra piece and +17k op per input for hashing).
   - The δ start states (198 B per role) are irreducible VK data.
3. **65-event loop and kernel glue, core but paid only because native is op-bound: −0.3 to −0.6M op ⇒ −400 to −800 B op-side.**
   - LOOP glue is 1.69M in total (26k/event), and stack shuffling is 14–19% of BDBL and DSTEP.
   - Every 10k op/event saved = 0.65M = 860 B.
   - Needs exact-VM-cost scheduling, since the static-model lazy pass loses. Least certain of the five.
4. **Setup run in every input: −130 to −270 B op-side.**
   - 3 × 0.47M (0.94M of it duplicated ≈ 1,250 B) is structural: handing the 64 table words over costs ≈ 2 kB per role,
     which is worse.
   - Only cheaper SETUP helps (×3 leverage): TM is 0.19M (44 MOD) and the 9 EV calls 0.14M. A 10–20% cut is
     0.14–0.28M.
5. **Glue: −0.25 to −0.45M op ⇒ −330 to −600 B op-side, plus up to −39 B of R.** The pieces:
   - R code loading: 0.33M. One code host avoids 1 INPUTBYTECODE, 2 SPLITs and the CAT (−30k per input). The 10 kB
     cap forces rehosting: input 0 = [DS_0][C], with S_0 moved to input 1 and read remotely by role 0.
   - Remote reads: 0.17M.
   - Stream pre-split: ~35k per role (11 SPLITs of the whole 3.3 kB stream); a split tree would save ~24k per role.
   - Binding loop in role 2: 0.32M, instruction-bound; −0.1 to −0.2M.

Not reducible, or not worth it:
- the `t` stream (net op winner, see §1);
- dropping F± from HAND, since F± = S'(±z) at a chunk-boundary cut: −128 B content but +~0.09M op for the remote
  state read and EV, ≈ net 0;
- fewer inputs (Σop 20.7M needs ≥ 3 inputs at the 8.03M cap);
- larger chunks (fewer states, but the quotient degree roughly doubles).

**Realistic v2 target:** about 26.6–26.9 kB (−2.5 to −3.7%), for example margin 3% plus items 2 and 5. With items 3
and 4 also landing, about 26.4 kB. The ~22 kB of the bch-spec sibling is not reachable: its 5.7 kB advantage is
2.8 kB of `t` witnesses (which save op here), ~2.6–2.9 kB of multi-input bytes, and the fact that bch-spec inputs are
byte-bound rather than op-bound.

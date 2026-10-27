# bch-groth16-bn254-sound-native-v2, design 1 (angle A: state and binding)

Task native-bn-design1. Design only, but every number below is **measured** on a working prototype
(`groth16_cashscript` branch `wip/native-bn-design1` @ f7d9f13, `chunked/bn254/bn-native-v2a-proto/`, fixture 0,
libauth BCH_2026, standard mode) unless it is marked as an estimate. The baseline is today's reviewed entry
`bch-groth16-bn254-sound-native` (code sha256 75c780ae…78d7).

## 0. Result in one table

| build | margin | unlocking per input | Σ unlocking | score | vs today |
|---|---|---|---|---|---|
| today (cuts 0/24/48/65) | 6% | 9,316 / 9,262 / 8,792 | 27,370 | **27,624** | |
| today | ≤ 5% | 9,219 / 9,221 / 8,725 (content-bound) | 27,165 | 27,419 | −205 |
| **v2-A** (cuts 0/26/48/65) | 6% | 9,775 / 8,670 / 8,839 | 27,284 | **27,538** | **−86** |
| v2-A | 5% | 9,671 / 8,605 / 8,839 | 27,115 | 27,369 | −255 |
| **v2-A** | ≤ 4% | 9,618 / 8,605 / 8,839 (content-bound) | 27,062 | **27,316** | **−308** |
| v2-A with today's cuts 0/24/48/65 | 6% | 9,479 / 9,223 / 8,839 | 27,541 | 27,795 | +171 (rebalancing is required) |

**What it costs and buys.**
- **Op cost.** Σop falls from 20,674,385 to 20,569,603 (−104.8k): 7,381,091 / 6,550,259 / 6,638,253 at 5%.
- **Content.** Content falls by 103 B in the same cut and 112 B at equal cuts.
- **Honest verdict.**
  - On its own, angle A is small: −86 B at the current 6% rule, and −103 B on top of a margin cut.
  - Its main value is structural. At a ≤ 4% margin it leaves every input **content-bound with op slack**: 147 / 204 / 325 B
    of budget at 3% (≈ 0.52M op). In that regime, angle-B content cuts (role-program dedup, −400 to −700 B) count byte
    for byte up to roughly 0.68 kB.
  - The single code host also turns any shrinking of the code blob directly into a smaller input 0.
- **Prototype checks.** Fixtures 0–4 and the forced cases are accepted in both modes. Every changed binding has an
  ordinary rejection check that fires (§4).

## 1. Changes (A1–A4 core; all prototyped)

### A1. One code host; a 50-byte redeem
- Input 0 hosts the whole code blob `C` (7,384 B) as its **first** push. `S_0` moves out of input 0 (see A3).
- The new redeem (`R'`, 50 B, identical in every input; today's is 65 B):
  ```
  <0> OP_INPUTBYTECODE <3+Lc> OP_SPLIT OP_DROP <3> OP_SPLIT OP_NIP
  OP_DUP OP_SHA256 <K_code> OP_EQUALVERIFY <1> OP_DEFINE <1> OP_INVOKE
  ```
- Prefix-first cut: split off the code prefix first, then strip the 3-byte header.
- Measured: R plus code loading costs 83.0k op per input instead of 109.2k (−26.1k × 3 = **−78.4k**). R is −15 B per
  input (−45 B).
- Cap: input 0 = C + DS_0 + R' ≈ 9.6 kB ≤ 10,000. This leaves about 380 B for code growth at cut 26, or 520 B at cut 24.

### A2. Front-loaded remote ranges and prefix-first reads
- Every range that another input reads (`X1`, `DG`, `STMT`, `X2`) sits at the **front** of its host. `ZT` stays at the
  tail.
- A remote read is: `INPUTBYTECODE`, then for the z-tail `<zt> SPLIT` and a trim of the R push from the tail, then
  `<end of needed prefix> SPLIT DROP`. Only after that come the header checks and slices, which now run on items of
  ≤ 3.7 kB instead of ~9 kB.
- The header check in front of every remote range is kept.
- Role 2 reads its own ZT the same way.
- Measured remote sections: role 0 94.4k → 57.8k, role 1 79.9k → 41.7k (**−74.8k**). Role 2 layout −4.9k.

### A3. Five-word handover; the cut state is hosted by the receiver
- `HAND_i` becomes `(x_T.c0, x_T.c1, y_T.c0, y_T.c1, R)`: 160 B instead of 224. `F±` is no longer handed over.
- The receiver derives `F± = S_cut(±z)` itself, with the shared `EV`, from the **cut state** `S_cut`. That is the last
  chunk state of the sender's range, which is exactly the value the sender's last boundary assigns to `F±`.
- `S_cut` is not duplicated. It moves from the sender's stream into the receiver's input:
  - **0→1:** S_0 now lives in input 1 anyway (A1), so S_cut is the last 192 B of `S_0`, inside `X1 = S_0 ‖ HAND_1`.
  - **1→2:** `X2 = S_cut ‖ HAND_2` in input 2. Role 1 rebuilds its stream as `S_1 = S_1' ‖ S_cut`, with S_cut read
    remotely, so `d1 = SHA256(S_1)` is unchanged.
- Digest definitions are unchanged: `d0 = SHA256(S_0)`, `d1 = SHA256(S_1)`, `d2 = SHA256(STMT ‖ S_2)`.
- Measured:
  - content −128 B (2 × 64);
  - op: HENC −6.6k × 2; EV start +19.2k × 2 (in setup); SDEC + X splits +18.1k (role 1) and +8.2k (role 2); CAT +3.4k.
    Net about **+55k**.
  - Code +63 B in total (SDEC +16, HENC −36, roles 1/2 +47 each, role 0 −8). Folding "SDEC, EV, HDEC" into one shared
    start function should recover about 30 B (estimate, angle-B tuning).

### A4. Rebalanced cuts: `CUTS = [0, 26, 48, 65]`
- Chunk [24,26) (2 doublings, no addition; 418k op measured, 256 B stream, 2 δ slopes) moves from role 1 to role 0.
  Under A1 the stream bytes stay in input 1, and only 128 B of DS move to input 0.
- This turns input 0 (code-heavy, light on op after A1) and input 1 (light on content, heavy on op) into a balanced pair.
- Without A4, A1–A3 are worse than today at 6%: 27,795, because input 1 buys 488 B of filler while input 0 has 257 B
  of unused content.
- The δ slices become 34 / 30 / 24 slopes. The δ pile takes an uneven last piece (`nP = ceil(len/512)`, every piece a
  nonzero multiple of 64). The baked δ start states and schedules are regenerated, and `protocol.mjs` asserts them
  against the single chain at load. The build must keep its role-split value-level equality and state-equality
  asserts, parameterised by CUTS. The prototype's `measure.mjs` uses the same mirror (`handovers()` asserts the final
  identity).
- **Builder rule (new).** Choose CUTS (chunk bounds near 24/48) and the hosting of movable items with a small search:
  minimise `Σ_i max(content_i, ⌈op_i/(800(1−m))⌉ − 41)` subject to the cap rule.
  - The best layout depends on the margin m and on the final code size. If angle B shrinks C by more than ~350 B,
    input 0 becomes op-bound at cut 26, and the search moves the cut back to 24 or moves `DS_1` into input 0.
  - Measured alternatives at ≤ 4%: 0/26/50/65 → 27,314 (−2) and 0/24/50/65 → 27,557.

## 2. Per-input layout (v2-A, cuts 0/26/48/65)

```
input 0 (role 0, events [0,26), 13 chunks):  [C 7,384] [DS_0 2,176]                                   [FILL_0] [R' 50]
input 1 (role 1, events [26,48), 11 chunks): [X1 = S_0 3,584 ‖ HAND_1 160] [S_1' 2,880] [DS_1 1,920]  [FILL_1] [R' 50]
input 2 (role 2, [48,65) + terminal):        [DG 96] [STMT 642] [X2 = S_cut 192 ‖ HAND_2 160] [S_2 2,496] [DS_2 1,536] [FILL_2] [WQ] [R' 50]
```

| input | content (B) | op std at fixture 0 | need at 6% / 4% / 3% | binding at ≤ 4% | worst op at the cap (sweep subset) | headroom to the cap budget |
|---|---|---|---|---|---|---|
| 0 | 9,618 | 7,381,091 | 9,775 / 9,570 / 9,471 | content (slack 48 / 147 B) | 7,413,771 (every nibble 1) | 7.71% (rule ≥ 6%) |
| 1 | 8,605 | 6,550,259 | 8,670 / 8,488 / 8,401 | content (117 / 204 B) | 6,578,766 | 18.10% |
| 2 | 8,839 | 6,638,253 | 8,787 / 8,602 / 8,514 | content (237 / 325 B) | 6,798,371 (n_q 132) | 15.37% |

Locking 3 × 35 (P2SH32), tx overhead 149. Each unlocking ≤ 10,000 B and the tx is ≈ 27.3 kB, both standard. No
read-only inputs and no non-2026 feature.

**Who reads what.**
- Role 0: R' reads C from input 0. Role 0 reads `X1` from input 1, and `DG`, `STMT` and `ZT` from input 2.
- Role 1: `DG`, `STMT`, `X2` and `ZT` from input 2.
- Role 2: only its own bytecode (ZT).

### Op by section (fixture 0, standard; today → v2-A)

| section | in 0 | in 1 | in 2 |
|---|---|---|---|
| R and code loading, unlocking pushes | 109.2k → 84.0k | 109.2k → 83.0k | 109.0k → 83.4k |
| layout pin | 23.2k → 23.8k | 26.9k → 25.8k | 56.0k → 51.1k |
| remote | 94.4k → 57.2k | 79.9k → 41.2k | — |
| transcript | 37.3k → 38.1k | 37.8k → 40.3k | 39.8k → 39.5k |
| slices | 30.5k → 34.6k | 43.6k → 58.8k | 35.2k → 43.4k |
| setup (incl. EV start for roles 1, 2) | 471k → 474k | 471k → 490k | 468k → 487k |
| loop | 6,150k → 6,555k (+chunk) | 6,156k → 5,746k (−chunk) | 4,265k |
| post (HENC 5 words) | 25.4k → 18.8k | 25.4k → 18.8k | — |

## 3. Soundness sketch (owner check, every new or changed binding)

The mathematics (states, identities, ρ/z, GT-GLS, endpoint, binding, quotient) is today's, unchanged. Only the
hosting, the handover width, the code host and the cut position change.

**Pinning and multi-input binding.**
- A spent output forces `R'`. `R'` defines and runs only bytes whose SHA256 is `K_code`, read from input 0 at
  `[3, 3+Lc)`.
- That code runs `GRAPH` unchanged: `TXINPUTCOUNT == 3` and every `UTXOBYTECODE(j)` equals the own one. So all three
  inputs run the same authenticated code, the role equals the index, and the sibling code and lockings are bound.
- Input 0 is not trusted for anything else. If its bytes do not contain the code, every input fails `EQUALVERIFY`.
- Role 0 pins input 0's layout (DEPTH 3, `|C| = Lc`, `|DS_0|`, filler, raw size), so `C` is exactly the first push.
- No hash cycle: `R'` contains `K_code`, and the code contains no digest of `R'`.

**One transcript.**
- `DG`, `STMT` and `ZT` are read from the same consensus bytes by every role. The offsets are exact because of:
  - the owner's DEPTH, size and raw-size pin;
  - a header check before every remote range;
  - push-only, minimal-push unlockings.
- A2 only reorders `SPLIT`s. The ranges and checks are unchanged. ZT is still `[zt, len − |push(R')|)`.
- Each `d_i` is checked by the role that hashes its preimage, and `h0 = SHA256(TAG ‖ DG)`. ρ and z are derived
  locally (`z ≠ 0`).

**Value owners (changed rows in bold).**

| value | owner |
|---|---|
| code, field constants, δ slopes/start states/schedules | VK constants: `P2SH32(R') → K_code`. The δ slices are `SHA256(DS_i) == K_DS[i]` (in code). **New slices for cut 26 are regenerated and asserted against the single δ chain.** |
| **S_0 (hosted in input 1, inside X1)** | hash-committed: role 0 reads it at a fixed, header-checked offset and requires `SHA256(S_0) == DG[0:32]` before ρ. Each word is `< p` when used. |
| **S_cut = last state of S_1 (hosted in input 2, inside X2)** | hash-committed: role 1 reads it at a fixed, header-checked offset, rebuilds `S_1 = S_1' ‖ S_cut`, and requires `SHA256(S_1) == DG[32:64]` before ρ. |
| **F± at the start of roles 1 and 2** | computed on-chain by the receiver: `EV(S_cut, ±z)`, from the same committed bytes the sender used at its last boundary (role 1 uses the tail of S_0 in its own X1; role 2 uses S_cut in its own X2). Every word is decoded `< p` on both sides. |
| **HAND_i = (x_T, y_T, R)** | exact byte equality: the sender requires `HAND_{i+1} == HENC(x_T, y_T, R)` (canonical, top byte checked), read at a fixed, header-checked offset of input i+1. The receiver decodes each word `< p`. |
| t, STMT, WQ, the other states, FILL | unchanged (exact equation `t·N(den) ≡ 1`; hash-committed; length rules; all-zero filler) |

**Handover induction (A3).**
- Role i's run is deterministic from the constants, the committed bytes, (ρ, z), and its start `(T, F±, R)`.
  - The sender ends with `F± = S_cut(±z)`; that is the boundary rule `F± ← S'(±z)` at its last event.
  - It also ends with `(x_T, y_T, R)`.
- The receiver starts from `(x_T, y_T, R)`, byte-equal to the sender's canonical encoding, and from `F± = EV(S_cut, ±z)`.
  Both sides evaluate `EV` on the same bytes with the same z, so the two values are equal as residues. No encoding
  question arises for F±: it is never serialised.
- So role i+1 starts from exactly the single-run state after event `cut_{i+1} − 1`, as before.
- Staples:
  - Splicing in an input from another proof changes some `d_i` (S_0, S_cut and S_1' are all inside `d0` or `d1`) or a
    `HAND`, and fails.
  - S_cut is in d1, not d2, so swapping input 2 from another proof also changes the S_cut that role 1 hashes.

**Cut 26 (A4).**
- It is a chunk boundary, so the identities, degrees, `NQ_MAX` and the soundness error are unchanged.
- The per-range schedules are asserted against the single schedule. The role-split mirror equals the single run
  (prototype `handovers()` asserts the final identity on every proved fixture).

**Error.** Unchanged: `≤ q_H·2^−245` plus SHA256 collisions (same digest layer). The FILL_2 length is still one z
query each.

**Not changed, still required.**
- Local canonical decoding in every role.
- The nibble mask.
- `z ≠ 0`.
- Filler all-zero, byte-exact.
- Every guard on reduced values.
- The nonzero line factors (curve checks in role 0).

## 4. Tests (ordinary rejection tests; prototype results)

`measure.mjs` (consensus): every case below is rejected, and the inputs that reject are listed.

| tampered | rejected by |
|---|---|
| X1: an x_T byte of HAND_1 | inputs 0, 1 |
| X1: an R byte of HAND_1 | inputs 0, 1 |
| X1: S_12 (cut state 0→1) | inputs 0, 1 |
| X1: the first t of S_0 | input 0 |
| S_1' byte | input 1 |
| X2: S_cut | inputs 1, 2 |
| X2: a y_T byte of HAND_2 | inputs 1, 2 |
| code byte (input 0) | inputs 0, 1, 2 |
| DG d1 | inputs 0, 1, 2 |
| 2-input tx | rejected |

**Liveness** (`caprule.mjs`, unlockings padded to 10,000 B, both modes): fixtures 0–4, every nibble 15/0/1, and 4
random proofs are all accepted, and the cap rule holds (§2).

**Before shipping**, port today's full gates to the new layout:
- `build.mjs` asserts;
- the `redteam.mjs` list, plus: a `+p` alias in S_cut and S_12; S_cut swapped between proofs; HAND with 7 words
  (wrong size); a header changed at the X1 and X2 offsets; C not first in input 0;
- the 424-case `sweep.mjs`;
- the bench gates under the new id `bch-groth16-bn254-sound-native-v2`, with the current entry kept.

## 5. Considered and rejected (angle A)

| idea | result |
|---|---|
| B1: `DG = d01 ‖ d2` with `d01 = SHA256(S_0‖S_1)` (both roles see both streams under A1/A3) | **measured**: DG −32 B, code +33 B, op +60k, so net ≥ 0. Rejected. |
| B4: no DG, every role hashes the whole transcript | estimate: −99 B DG, +40–60 B code, +~0.14M op. B1 shows that the code cost eats the gain. Rejected. |
| ZT digest `dq = SHA256(ZT)` hosted in input 2 | −37k op (roles 0/1), +35 B content: −15 B at 6%, +35 B at ≤ 4%. Rejected. |
| hand over the setup tables (64 words) or defer GT-GLS to role 2 | +2 kB per role, or +768 B per role, against ≤ 0.6M op saved. Worse. |
| hand over the δ state instead of baking it | same bytes, plus HENC/HDEC op. No gain. |
| drop x_T/y_T (recompute) | needs an Fp2 sqrt or a scalar multiplication. Infeasible. |
| per-role code hashing (only the shared code plus the own role) | R' grows by 2 × 33 B digests or more, ×3 inputs. Worse. |
| R uses input 0's stack copy of C (IF on index) | −18k op on input 0 only, +4 B R' × 3. Not worth it. |
| hash C ‖ DS_0 under K_code (drop K_DS[0]) | about −20 to −44 B, +16–33k op. Marginal; left to angle B. |
| P2S locking (R' in the locking) | excluded by the P2SH32 packaging requirement. When op-bound it is also worse: −52 B unlocking per input loses 41.6k of budget, plus 15 B more locking. |
| dropping the raw-size pins (redundant under consensus push-only and minimal push) | estimate −21k op, −30 to −40 B code. **Optional, reviewer call.** It removes a defence-in-depth check, so it is not in the core. |

## 6. Risks and owner decisions

- **Margin (owner).** v2-A gives −86 B at 6%. Most of its value (−308 B) and the room for angle B's content cuts need
  a margin of ≤ 4%. The roles are op-exact (fixed schedule), so this stays a policy call.
- **Thinner cap headroom on input 0.** It is 7.7% at cut 26, against 12.1% today; the rule needs ≥ 6%.
  - Any later op added to role 0 must stay below ~+137k.
  - The cut search (A4) must re-check the cap rule.
  - The fallback is cut 24, with `DS_1` or other items hosted in input 0 to rebalance.
- **Code-host cap.** C + DS_0 + R' must fit in 10,000 B. That leaves ~380 B for code growth at cut 26 (~520 B at
  cut 24).
- **Small structural change.** Not a new mechanism. Only "S_cut hosted by the receiver and committed by the
  sender's digest" is new reasoning, and it is one line in the owner table.
- **Prototype, not a reviewed build.** export, redteam and sweep are not yet ported. Code (+63 B) is untuned.
- **Interaction with the other angles.**
  - A1/A3/A4 are orthogonal to kernel and loop work (angle C) and to role-program dedup (angle B).
  - With angle B the cut search may move the cut back to 24.
  - Combined estimate at 3%: ≈ 27,316 − (400…680) ≈ **26.6–26.9 kB**, limited by the ~0.52M op slack unless angle C
    lands.

## 7. Files

- **Branch `wip/native-bn-design1` (pushed), commit f7d9f13:**
  - `chunked/bn254/bn-native-v2a-proto/`, containing `measure.mjs`, `caprule.mjs`, `trace.mjs` and the patched
    `script.mjs`, `protocol.mjs` and `transaction.mjs`;
  - `research/native-bn-design1/trace.mjs`;
  - a copy of this doc.
- **Reproduce** (in `chunked/bn254/bn-native-v2a-proto/`):
  ```
  CUTS=0,26,48,65 MARGIN=0.06 node measure.mjs
  VERIFIER_DIR=<zk-verifier-bench> CUTS=0,26,48,65 node caprule.mjs
  ```

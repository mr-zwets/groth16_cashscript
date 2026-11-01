# Track 9 S2: the pool's R and the re-proved M1 statements

Research only (wip/pool). This folder holds the pool version of Track 8's layout a′ verifier R (DESIGN-T9 §3, §6 S2)
and its tests. Track 8's files on main are untouched. The changed ones were copied here, and the unchanged modules are
imported read-only from `../../pq-stark-batch/`. The W-state covenant is S1's (`../w/`), and it is used unchanged.

## What changed in R (`gena.mjs`, `genn.mjs`, `ctx.mjs`, `layouta.mjs`)

1. **ROOT is a HEAD push.** HEAD's items are now `ROOTS OOD BPOW FROOTS CPOW QPOW ROOT NF CTXW`. ROOT is 32 B (4 lanes,
   u64 LE) and sits just before NF, so HEAD's unlocking ends with ROOT NF CTXW. That is S1's tail contract, which W
   reads.
   - HEAD checks ROOT's size.
   - Every input that runs the transcript (HEAD, CODE, FIN) checks that each ROOT lane is < p.
   - The transcript observes ROOT in place of Track 8's constant.
   - The CODE inputs pass the lanes to the constraint DAG (the last-row constraints I_j read ROOT).
   - **R no longer depends on the statement.** One R serves every withdrawal, so one W (which holds SHA-256(R))
     serves every withdrawal. `grade-a` checks this: one (R, W) pair over all 24 statements.
2. **CTX is computed over outputs[1..]** with a count of n − 1. Output 0, the next W state, is excluded and is pinned
   by W alone.
   - The serialization is Track 8's (FORMAT.md "CTX serialization") applied to outputs 1..n−1.
   - The script loop runs at least once, so a final transaction with output 0 only is rejected (a withdrawal needs a
     payout).
3. **Graph slot for W.** In the final transaction (tx1 of the 2-transaction plan), the last input (wIdx = 5 of 6) is
   the W state.
   - R requires inputs 0..4 to be R, the input count to be 6, and input 5's locking to differ from R.
   - R does **not** pin W's locking or category. This keeps the design's "R never references W" rule, so there is no
     hash cycle.
   - The final HEAD's thread rules (Track 8: no other input carries a token, and no output carries one) now skip input
     5 and output 0. Output 0 may carry a token, but it must not carry the thread category.

The AIR, the prover's circuit and the wire format are unchanged.

## Re-proved statements (`gen-statements.mjs`, `../prover`)

`../prover` is the Track 8 prover with one change, a witness change. The case `m1@LEAF@0@CTXHASH@WIT` takes an explicit
nk, r and 30 siblings (128 lanes in hex) in place of the seeded ones (`src/airs.rs` `stmt_case`).

Statement i (i = 0..23) uses genesis note i from `../w/results/genesis.json`:
- notes 0–15 are in epoch 0 (ring slot 0), and notes 16–23 are in epoch 1 (slot 1);
- CTX = SHA-256 of outputs[1..] = one P2PKH payout of D − φ = 950,000 sat.

Proved under Z128 with Merkle cap 5, as in Track 8 S7.

**Every vector's public values match** genesis note i: ROOT is its epoch root, NF is the note's NF, and CTX matches the
payout (`results/gen-vec.txt`). This also confirms that S1's JS Poseidon2 genesis tree equals the Rust prover's.
- Proving takes 0.7–3.5 s per statement.
- Proofs are 74,160–77,360 B (p3b-v1).
- Three vectors are committed in `../prover/vectors/S2` (notes 0 and 1 from epoch 0, note 16 from epoch 1).
- Two more proofs serve the mix and other_vk families: second-seed proofs of statements 0 and 1, and cap-0 proofs of
  statements 0 and 1.

## Results

Reproduce with `gen-s2.sh` (about 10 minutes). Result files: `results/grade-a.{txt,json}`,
`results/test-a-2tx-pool.json`, `results/test-a-harness.json` and `results/test-a.txt`.

### Grading: 24 statements, libauth BCH 2026, today's rules

The W input spends the genesis state (empty nullifier set). Op-cost is BCHN-adjusted: libauth plus 37,790 B of
OP_DEFINE bodies on every R input. W has no OP_DEFINE.

| plan | accepted | transactions (inputs) | bytes | max input |
|---|--:|---|---|--:|
| **2-tx a′ + W (baseline)** | **24/24** | 2 (11 + 6) | 91,183 + 41,457 = **132,640** | 91.1% (QRY) |
| 1-tx a′ + W (measured only) | 24/24 | 1 (13) | **99,594** (406 B left under 100,000) | 91.0% (QRY) |

- **The same transaction sizes for every statement.** Full Merkle paths have a fixed size.
- **One (R, W) pair for all 24 statements** in each plan:
  - R is 118 B (P2S);
  - SHA-256(R) in the 2-tx plan is `6cde4a7e…830a`;
  - W's redeem script is 499 B (P2SH32).
- **Compared with Track 8 S7** (91,059 + 40,497 = 131,556 B), the total grows by **1,084 B**:
  - tx0 grows by 124 B: the 33 B ROOT push plus larger code blobs (the ROOT lane checks, the W-slot rule and the
    thread rule);
  - tx1 grows by 960 B: the same two changes, plus the W input (645 B unlocking plus its outpoint) and the W output.
  - The OP_DEFINE bytes each R input is charged on BCHN grow from 36,844 to 37,790 B.
  - The design estimated 1.5–1.9 KB for W in tx1.
- **Per role (2-tx):**

  | role | unlocking | op-cost (BCHN-adjusted) | share of its budget |
  |---|--:|--:|--:|
  | HEAD | 6,487 B | 1.33M | 25.4% |
  | CODE1 (tx0) | 9,572 B | 5.50M | 71.5% |
  | CODE2 (tx0) | 9,569 B | 5.01M | 65.2% |
  | FIN | 6,462 B | 3.76–3.79M | 72.8% |
  | QRY | 8,322 B | 6.07–6.09M | **90.7–91.1%** (Track 8: 90.7–91.0%) |
  | W | 645 B | 0.234M | 42.7% |

  In tx1, the CODE inputs are 0.24M and HEAD is 0.53M.
- **The 1-tx plan with W fits, but only at small nullifier sets.** DESIGN-T9 §5 expected it not to fit (it assumed
  1.5–1.9 KB for W). The W unlocking grows with the set (S1: about 1.0 KB at 1,000 spends, about 1.13 KB at 2^16). So the
  1-tx plan exceeds 100,000 B once the compressed SMT path adds about 400 B, at roughly a few thousand spends.
  - Maintainer decision 3 dropped the 1-tx stretch for the pool. This is recorded as a measurement only, and S3 uses the
    2-tx plan.

### Sweeps: 0 unexpected verdicts

| sweep | files | cases | unexpected |
|---|--:|--:|--:|
| production: 2-tx + W, Track 8 S7 families + DESIGN-T9 S2 families (`--layout --pool`) | 26 (+2 skipped) | **4,977** | **0** |
| harness: S3 M1 cap-5 case files, 1-tx without W, CTX a witness item | 36 (+2 skipped) | **2,387** | **0** |

**Rules every case follows (as in Track 8):**
- Each case's chain verdict must equal the expected one. Where they exist, the a′ model's and the S3 reference's
  verdicts must too.
- Valid cases must pass today's standard and consensus rules on every input of both transactions, plus whole-transaction
  verification.
- Reject cases run on the loose VM, so a rejection is a failed check and not a resource limit.

**Same accounting as Track 8 S7:**
- The skipped files are the two cap-0 vectors. Layout a′ is the cap-5 deployment.
- The 55 encoder-only cases (harness: 69) are malformed-by-length proofs whose on-chain witness is the valid proof's.
- In the harness, 35 cases are not run on chain: 33 CTX lanes ≥ 2^56 and 2 VK variants.
- The harness totals equal Track 8 S7's exactly (2,387 / 69 / 35).

**The S7 families in the production sweep:**
- **Proof-level families from the S3 case files.** All families are present:
  - cap, ood, random, pow, final, row, salt, sibling, count, fri_value;
  - truncate, extend, noncanon, statement (321);
  - other_vk: 6 cases, of which 4 are second-seed proofs that must accept.
- **Constants (702).** The Track 8 cases plus new ones: ROOT flipped in HEAD in both transactions, and ROOT flipped in
  tx1's HEAD only.
- **Input (624).** Includes a new case: the ROOT push missing.
- **Graph (208)**, **mix (156)**, **control (2)**.
- **Thread (416).** The output change now modifies output 1 (the payout). New case: the thread NFT moved to output 0.
- **Tx (104).** These change the payouts.
- **Root (78).** HEAD ROOT[3] + 1; ROOT[0] + 1; ROOT = the other genesis epoch's root (it is in the ring, but it is not
  this proof's root).

**No-op tampers.** 18 cases were skipped as no-ops and are not counted as verdicts. These are S3's "ROOT of another
tree", where the other vector is a same-epoch note: 16 notes share one root, so the "foreign" ROOT is this proof's own
ROOT. The chain, the model and the reference all accepted the one instance that ran before the guard existed. Real
foreign-root cases are in the root family above and in the ring family below.

**DESIGN-T9 S2 families** (`poolCases`, on all 26 production files). A pool case names the input that must reject.
With "others accept", every other tx1 input must accept under today's standard rules, which shows which script enforces
the rule.

| family | cases | what | result |
|---|--:|---|---|
| nf | 86 | **same NF twice**. In sequence: the first withdrawal from genesis is accepted; then, on the next state, the same proof, the same proof with its stale absence witness, and another proof of the same note (seed 2) are each rejected. Conflicting: the other-seed tx1 on the same genesis W outpoint is valid alone; both tx1 spend the same outpoint, so at most one confirms; after it confirms, the loser rebuilt on its state is rejected | 30 accepted as required; every rejection is by **W**, with all R inputs accepting |
| ring | 78 | **ROOT not in the ring**: a valid Track 8 S7 proof (same VK, its own random ROOT, CTX = its payout as output 1); also the wrong ring slot and an empty slot | **W** rejects; every R input accepts |
| windex | 130 | **W at the wrong index or missing**: W swapped with the QRY input or with HEAD; W removed; an extra R input after W; an R input in the W slot | rejected (R) |
| commit | 104 | **an output-0 commitment that does not match**: nfRoot unchanged; nfRoot after another key; histRoot flipped; epoch + 1 | **W** rejects; R accepts |
| out0 | 208 | **output 0 is outside CTX**: output 0's value − 1 or its locking changed is rejected by W only, with every R input accepting. **Race**: tx1 rebuilt on a later W state (another note withdrawn first; same proof, same tx0) is **accepted** (26/26). **Any output ≥ 1 changed** (payout value − 1, payout locking, an extra output 2, the payout removed) is rejected by **HEAD** (CTX), with W accepting. Outputs 0 and 1 swapped are rejected | as required |
| wonly | 52 | **a withdrawal without R at input 0**: W alone; W after a non-R input 0 | **W** rejects (graph and HR) |

**Documented, not a rejection (26 runs, `documented` in the JSON).** This tx1 puts a non-W input (OP_1, 1,000,000 sat) in
the W slot and an OP_RETURN as output 0. **R's five inputs accept.**
- This follows from the design: R never references W, so R cannot tell W from another input in the slot.
- Such a transaction moves no pool funds. Its outputs are paid by that input, and pool funds leave only through W, which
  requires R and inserts NF.
- It does consume the user's thread NFT without inserting NF. The proof stays spendable once, and the user can redo
  tx0.
- Closing this would mean pinning W's category in R. That creates no hash cycle (CAT is a genesis outpoint), but it is a
  change to the design, so it is left open for the maintainer.

### Not covered

- **BCHN (S3).** Conflicting transactions are shown here only as two valid tx1 spending one W outpoint. The mempool
  rejection of the second one is S3's job.
- **The 1-tx + W plan** was graded but not swept, and it is not a deliverable.
- **Track 8's per-phase profile (`profile-a`)** was not re-run. The input costs are in `grade-a`.

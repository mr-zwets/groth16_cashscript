# Track 9 S4: deposits, the queue, the permissionless flush, and the ring

Research only (wip/pool9b). This folder holds the D-state covenant of DESIGN-T9 §2 and §6 S4, its flush coordinator
and the flush workers, and the libauth acceptance test. W's flush branch is in `../w/wcov.mjs`, R's W-slot pin
(review item A3) in `../r/gena.mjs`, and the BCHN end-to-end run in `../node/s4.ts`.

**Result: S4 acceptance passes**, in libauth (`results/s4-d.json`) and on BCHN regtest (`../node/results/t9s4a*`).

| acceptance item (DESIGN §6 S4 and the task) | result |
|---|---|
| flush root = offline Poseidon2 tree over 64 sequential deposits (4 flushes) | **4/4 equal** (libauth); 17/17 over 272 deposits in libauth and again on BCHN |
| ring wraparound expires a stale root (rejected at epoch + 16) | **yes**: root 0 (written at epoch 0) is accepted at epoch 16 and rejected by W after the flush at epoch 16 overwrites slot 0 (libauth with S1's stand-in R; BCHN with real R and real proofs: W rejects, testmempoolaccept `mandatory-script-verify-flag-failed`, block `blk-bad-inputs`) |
| premature flush, wrong frontier, leaf lane ≥ p rejected | **yes** (families `premature` 2, `frontier` 7, `lane` 4, plus 46 more plain rejections, 59 in all; 0 unexpected. The 72 cases are 59 rejections + 13 required accepts) |
| deposit → flush → prove → withdraw on BCHN (POLICY=1), testmempoolaccept at default policy | **yes**: genesis, 272 deposits, 17 flushes and 4 withdrawals (tx0 and tx1) were each allowed by testmempoolaccept and mined; 5 proofs from the Track 8 prover with the explicit witness |
| A3: R pins input 5 to the pool's W | **closed** (R checks category and prefix 0x57; `../r/README.md`) |
| A1: pool-specific nullifiers, or why not needed | **resolved by G (initial ring all Z); no script change** (`../README.md` A1, `../SOUNDNESS-T9.md` §6) |

## Design as built

**One category, two state NFTs.** The genesis transaction spends an outpoint at index 0, whose txid becomes CAT, and
creates exactly two mutable NFTs of CAT and no minting NFT:

- D (P2SH32, prefix 0x44) at output 0;
- W (P2SH32, prefix 0x57) at output 1.

Each covenant pins its successor: its own locking, CAT ‖ 0x01, its prefix, and no fungible amount. Under L1 (an off-chain
check of the genesis), "CAT ‖ 0x01 with prefix 0x44" therefore means the real D, and "CAT ‖ 0x01 with prefix 0x57" the
real W. The categories are fixed before any script is built (CAT is a funding txid), so there is no hash cycle:

- R contains CAT;
- W contains CAT and SHA-256(R);
- D contains CAT and HASH256 of the flush blob.

**D commitment (65 B):** `0x44 ‖ queue ‖ depHash`.
- `queue = SHA-256(len ‖ chain)`, where each deposit sets chain′ = SHA-256(chain ‖ C), and every flush resets chain to Z.
- `depHash = SHA-256(count (u32 LE) ‖ F)`. Here count is the number of leaves in the tree (a multiple of 16), and F is
  the frontier at levels 4..29 (26 × 32 B). F[l] is the left node at level l when bit l of count is 1, and Z otherwise.
  Levels 0..3 are always empty, because flushes append aligned 16-leaf subtrees.

**Deposit** (`buildD`; D at input 0, any other inputs and outputs):
- the unlocking holds `C len chain` and the redeem;
- SHA-256(len ‖ chain) = queue, and 0 ≤ len < 16;
- C is 32 B, and each of its 4 lanes is < p;
- output 0 is D′ with `0x44 ‖ SHA-256(len+1 ‖ SHA-256(chain ‖ C)) ‖ depHash` and value = in + D + f.

Regtest values are D = 1,000,000 sat and f = 10,000 sat.

**Flush** (inputs D, W, worker 1..4; outputs D′, W′ and anything the keeper wants).
- D's redeem checks the flush blob against its HASH256 and runs it (OP_DEFINE / OP_INVOKE). The blob is pool independent.
- D's unlocking holds: `LV` (the 16 leaves), `FR`, `count`, `MID = A8 ‖ B4 ‖ H11 ‖ H23 ‖ ROOT ‖ X`,
  `RING = old slot ‖ 4 siblings`, the blob, and the redeem. The blob then checks:
  1. **Queue.** It folds LV from chain = Z and checks SHA-256(0x10 ‖ chain) = queue. So exactly the 16 deposited leaves
     are flushed, in order, and a flush with len < 16 fails.
  2. **Frontier.** SHA-256(count ‖ FR) = depHash, count % 16 = 0, and count ≤ 2^30 − 16.
  3. **W.** Input 1 has D's category and prefix 0x57.
  4. **Ring.** slot = epoch mod 16. The old slot value and the siblings hash to histRoot. ROOT with the same siblings
     gives histRoot′.
  5. **Workers.** Inputs 2..5 have the worker locking. The first push of each unlocking equals the IO program that the
     blob builds from LV, count, FR, the 26 zero hashes (832 B, in the blob) and MID:

     | worker | compressions | work |
     |---|--:|---|
     | 1 | 10 | the trees of leaves 0–7 (A8) and 8–11 (B4) |
     | 2 | 12 | leaves 12–15, then (B4, C4) and (A8, B8) to the subtree root, then path levels 4–10, exporting H11 |
     | 3 | 12 | levels 11–22, exporting H23 |
     | 4 | 7 | levels 23–29, exporting ROOT |

     At each path level, the IO is `01 F[l] 03 02` (compress(F[l], node)) if bit l of count is 1, and `01 ZH[l] 02`
     (compress(node, ZH[l])) otherwise. At l0, the lowest zero bit, `04 X 01 X` is inserted first, which exports X, the
     node entering level l0. The blob writes the new frontier: F′[l] = Z below l0, X at l0, and F[l] above.
  6. **Outputs.** W′ at output 1 has W's locking, CAT ‖ 0x01, no fungible amount, `0x57 ‖ nfRoot ‖ histRoot′ ‖ epoch+1`
     and value = W + 16 D. D′ at output 0 has `0x44 ‖ SHA-256(0x00 ‖ Z) ‖ SHA-256(count+16 ‖ F′)` and value =
     D − 16 (D + f).
- **The keeper fee is implicit.** The 16 f released from D, plus the worker inputs, go to whatever outputs the keeper
  adds. On BCHN the keeper output got 118,000 sat after a 50,000 sat fee (1.19 sat/B; 4 workers at 2,000 sat each).
- **Worker UTXOs are anyone-can-spend until the flush confirms.** The worker locking checks only DEPTH 3 and
  H(WBLOB), so anyone who sees a funded worker UTXO can spend it with a small IO program in a transaction of their
  own (WBLOB is public). The keeper then loses that worker's value and must rebuild the flush with a new worker.
  Pool funds are not affected: D binds each worker's IO in the flush, so a worker spent elsewhere moves no D or W
  value. Keepers should fund workers at the dust minimum (about 600 sat each for the 52 B output under BCHN's default
  dust rule; computed, not measured) and broadcast the worker-setup transaction and the flush together.
- **The worker** (P2S, 43 B): `DEPTH 3 NUMEQUALVERIFY DUP HASH256 <H(WBLOB)> EQUALVERIFY 1 DEFINE 1 INVOKE`.
  - Its unlocking is `IO PAD WBLOB`. WBLOB defines S0's compression T∘P and interprets IO over a stack of nodes.
  - The ops are: `01 lit` push (every lane < p); `02` compress the top two nodes; `03` swap them; `04 lit` pop, which
    must equal lit.
  - The node stack must be empty at the end.
  - DEPTH 3 makes IO the first push, which is the one D compares.
- **W's flush branch** is taken when W's unlocking is the redeem only. It checks:
  - W is input 1, and input 0 is CAT ‖ 0x01 with prefix 0x44;
  - output 0's value = D's value − 16 (D + f). Only D's flush branch allows that, since D's deposit branch adds D + f;
  - its own output 1: locking, category, no amount, prefix and nfRoot unchanged, value + 16 D.

  D checks histRoot′ and epoch + 1.

## Results

### libauth (`node test-d.mjs` → `results/s4-d.json`, 14 s): PASS, 72 cases, 0 unexpected

The 72 cases are 59 rejections + 13 required accepts (seq 4, deposit 2, flush 1, wrap 3, edge 3). The family table
below sums to 76 because the `seq` row also counts its 4 root/ring equality checks (root = offline tree, histRoot =
ring of the roots), which are checks inside the accepted cases, not separate transactions.

Every valid transaction passes bchStd and bchCons on every input and libauth's whole-transaction verification, and
the BCHN-adjusted op-cost is within budget on every input. A rejection counts only if the input also rejects on the
loose VM, so it is a failed check and not a resource limit (as in S1 and S2). Where a case says "others accept", every
other input accepts, which shows which script enforces the rule.

| family | cases | what |
|---|--:|---|
| seq | 8 | 4 flushes over 64 deposits: root = offline tree (`w/genesis.mjs` `tree()`, a separate computation from the frontier reference) and histRoot = ring of the roots; a note of each flush is withdrawn against its root |
| deposit | 16 | controls (honest; every lane = p − 1). D rejects (others accept): leaf 31 or 33 B; witness len + 1 or chain flipped; value − 1 or without f; queue unchanged; depHash flipped; prefix 0x57; W's locking; immutable NFT; token moved; D at input 1; **a 17th deposit on a full queue** |
| lane | 4 | **leaf lane ≥ p**: lane 0 = p, lane 3 = p, lane 1 = 2^64 − 1, lane 2 = p + 5. D rejects; others accept |
| flush | 1 | control at count 64, epoch 4 |
| frontier | 7 | **wrong frontier**: FR byte flipped; the set-bit entry replaced by Z; two entries swapped; 25 entries; count ± 16; the IO and witness of another frontier (count 48). D rejects |
| premature | 2 | **premature flush**: 15 deposits plus a 16th leaf never deposited; the 15 leaves only. D rejects |
| ring | 4 | old slot value flipped; a sibling flipped; slot 0's value and path at epoch 4; 128 B RING. D rejects |
| mid | 7 | MID items flipped (D rejects). **Consistent wrong claims** (D's IO, the worker IO and D's outputs agree): a wrong ROOT, where only worker 4 rejects; a wrong X, where only worker 2 rejects; a wrong H11 or A8, where the computing worker rejects (and the next) |
| io | 6 | a leaf flipped in worker 1's IO; worker 4's E literal; workers 2 and 3 swapped; worker 4 missing; a worker with another locking; an extra push before IO |
| wout | 5 | W′: ROOT in slot 5; epoch not incremented (D rejects, others accept); nfRoot changed; value − 1; D's locking (D and W reject) |
| dout | 3 | D′: value − 1 (D and W reject); queue not reset; depHash with the old frontier (D rejects) |
| wbranch | 3 | W's flush branch with D running its deposit branch (W rejects, others accept); **a fake D** (another category, prefix 0x44, OP_1 locking) at input 0 (W rejects); **a fake W** at input 1 (D rejects) |
| wrap | 5 | **ring wraparound** at 17 flushes / 272 deposits: a flush-0 note against root 0 at epoch 16 accepted. At epoch 17 another flush-0 note against root 0 is **rejected by W** (with slot 0's or slot 1's path). That note against the newest root (root 16) is accepted, and a flush-0 note against root 1 (still in the ring) is accepted |
| edge | 5 | synthetic D states (the script cannot tell them from real ones): l0 = 29; count = 2^30 − 16 (no zero bit, F′ all Z) accepted; count = 2^30 rejected (D); count = 0. A queued leaf with lane 0 = p (a queue a deposit could never build): **worker 1 rejects** (the literal lane check) |

Withdrawals in this test use S1's stand-in R (three 32 B pushes, no proof). They exercise W's ring and nullifier
rules on a flushed history. The real R with real proofs is the BCHN run below.

**Sizes and op-cost** (libauth, BCHN-adjusted: + the OP_DEFINE body bytes, which BCHN charges per input):

| item | bytes | op-cost | share of its input's budget |
|---|--:|--:|--:|
| D redeem (P2SH32) | 291 | – | – |
| W redeem (P2SH32, S1's 499 B + the flush branch) | 671 | – | – |
| flush blob (+ the 112 B level function it defines) | 2,209 | – | – |
| worker blob (S0's compression 7,567 B + interpreter) / worker locking (P2S) | 7,725 / 43 | – | – |
| **deposit transaction** (2 inputs, 2 outputs) | **645** | D input: 18.6K | 5.8% |
| **flush transaction** (6 inputs, 3 outputs) | **42,127–42,129** | 25.4M in all | max 91.1% |
| – D (unlocking 4,213 B) | | 0.70M | 20.6% |
| – W (674 B) | | 0.048M | 8.3% |
| – worker 1 (8,600 B, 10 compressions) | | 6.07M | 87.9% |
| – worker 2 (10,000 B, 12) | | 7.27–7.32M | 91.1% |
| – worker 3 (10,000 B, 12) | | 7.24M | 90.2% (91.9% when every bit of count is set) |
| – worker 4 (8,036 B, 7) | | 4.25M | 65.9% |

Compared with S0's table (k = 4: 41 compressions, 23.75M, 4 inputs, 40 KB): the flush has 4 worker inputs as planned
plus D and W. It totals 42.1 KB. Worker 1 and worker 4 are sized below 10 KB, because worker 4 needs only the blob
and its IO.

The non-Poseidon2 work S0 left open costs about 0.75M: the D input (queue hashes, frontier, ring update, IO building,
4 reads of 10 KB worker unlockings) plus W. The lane checks and the interpreter add about 2% per worker against S0's
bare loop (7.27M vs 12 × 0.574M + 0.05M).

### BCHN v29.1.0 regtest (`../node/s4.ts`, node `t9s4a`, POLICY=1): PASS

- **Node.** One fresh node under work/pool9b/bchn, started with `node.sh` (identical to bench
  `research/node-check/node.sh`), stopped afterwards.
- **Genesis.** The genesis spends a P2SH32(OP_1) output at vout 0, so the genesis transaction itself is
  **policy-tested**: testmempoolaccept allowed it. BCHN decodes exactly 2 outputs of CAT, both mutable (prefixes 0x44
  and 0x57), and no minting NFT.
- **R.** R is built for this pool (W-slot pin, CAT): 118 B. W holds its hash.
- **Deposits.** 272 deposits (17 × 16), each 645 B. Each was allowed by testmempoolaccept and sent as an unconfirmed
  chain on D, then mined in one block per 16.
- **Flushes.** 17 flushes, 42,127–42,129 B each, all allowed, mined, and **root = offline tree** (17/17). After every
  step, BCHN's `gettxout` of D and W matched the JS state: value, category, capability, commitment and locking.
- **Proofs.** The Track 8 prover with the explicit witness case (`m1@INDEX@0@CTX@WIT`: nk, r and the 30 siblings from
  the offline tree) produced 5 proofs of 73,744–76,208 B in 2.5–5.6 s. Their public values equal (flush root, NF, CTX).
- **Withdrawals.**
  - Note 3 against root 0 and note 20 against root 1, right after the second flush.
  - Note 5 against root 0 at epoch 16.
  - Note 9 against root 16 with a new proof.

  Each tx0 + tx1 was allowed by testmempoolaccept and mined: 91,229 + 41,675–41,739 B, max input 91.1%, W 33–35%.
- **Stale root.** Note 9 against root 0 at epoch 17: tx0 was allowed and mined. tx1 was rejected in libauth at the W
  input (OP_VERIFY), in testmempoolaccept (`16: mandatory-script-verify-flag-failed (Script failed an OP_EQUALVERIFY
  operation)`), by sendrawtransaction, and as a block (`blk-bad-inputs`).
- **testmempoolaccept totals.** 299 valid transactions were allowed: genesis, 272 deposits, 17 flushes, and 9
  withdrawal transactions (4 × tx0 and tx1, plus the stale case's tx0). The one refusal is the expected stale tx1.
- **Not policy-tested.** The funding transactions (the deposit inputs, worker UTXOs, R carriers and the thread NFT)
  were mined through submitblock from the rig's bare-OP_1 coinbases, as in S3 (A4).

## Files

| file | what |
|---|---|
| `dcov.mjs` | scripts: `buildD` (D redeem), `flushBlob` (coordinator), `workerBlob` / `workerLocking`, `codeSet` |
| `dpool.mjs` | JS reference (`DState`, `WState`, `flushPlan`), the pool (`makePool4`), transaction builders (`genesisOutputs`, `depositTx`, `flushTx`) with tamper hooks, `runTx` |
| `test-d.mjs` | the libauth acceptance test → `results/s4-d.json` |
| `../node/s4.ts`, `../node/run-s4.sh`, `../node/summarize-s4.mjs` | the BCHN run → `../node/results/t9s4a{.jsonl,.log,-summary.json}` |

## Reproduce

```
node test-d.mjs                                   # --flushes 17
CARGO_TARGET_DIR=$CACHE/target nice cargo build --release --offline -j4 --manifest-path ../prover/Cargo.toml
cd ../node && S2_VEC=<S2 vectors> PROVER=$CACHE/target/release/pq-pool-prover S4_CACHE=$CACHE/s4 \
  OPCOST_DIR=<datadirs> ./run-s4.sh <fresh NAME> 9 7 --wrap      # about 6 minutes
```

## Limits and open points

- **The flush is in a single transaction of 42 KB under today's rules.** Its 4 workers carry the 7.7 KB compression
  code each. With 100 KB per-input limits it would be one worker (S0: 138 compressions fit).
- **Anyone can flush, and only the full queue can be flushed.**
  - Deposits stall at len = 16 until someone flushes.
  - The 16 f fee pays the keeper. A third-party keeper breaks even only if
    16 f ≥ (flush bytes + worker-setup bytes) × feerate, i.e. f_min ≈ (42,129 + ~400) × feerate / 16 ≈ 2.7k sat at
    1 sat/B (the setup transaction size is an estimate for one input and 4 worker outputs; not measured). The regtest
    f = 10,000 sat covers about 3.7 sat/B. Below f_min only depositors who flush themselves keep the pool moving; that
    weakens the "stall bounded by fee" argument but cannot cause theft.
  - When the tree is full (count = 2^30, after the flush at 2^30 − 16), D's deposit branch, which cannot see count,
    still accepts up to 16 more deposits. They can never be flushed or refunded, so up to 16 (D + f) is locked for
    good. Not reachable in practice (2^30 deposits first); a final flush that writes a full sentinel queue would close
    it and is not implemented.
  - No timeout or partial flush exists. A partial flush would need a different subtree shape.
- **Notes become withdrawable only after a flush, and a proof's root expires 16 flushes later.**
  - A note can always be re-proved against a newer root (BCHN: note 9).
  - Wallets must track the frontier and the leaves (from the deposit transactions) to build paths.
- **L1 (A2) now protects funds.** With a minting NFT of CAT, a forged W could receive a flush's 16 D. The genesis check
  (exactly two mutable NFTs of CAT, no minting NFT) is now required for fund safety, not only for state uniqueness.
  It is an off-chain check, as before.
- **Not measured: BCHN timing.** This is an acceptance and policy run.

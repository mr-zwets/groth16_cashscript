# Track 9 S1: SHA-256 SMT library and the W-state covenant (static genesis history)

Research only (wip/pool). This folder holds the nullifier set and the W-state covenant of DESIGN-T9 §1–§3, with no
deposits yet. The genesis history is built offline, `histRoot` is seeded, and W is funded at genesis.

The withdrawal's input 0 is a **stand-in R** (`stubR`): a P2S script that only checks the sizes of its three pushes
(ROOT, NF, CTXW). It verifies no proof. The real R (ROOT as a HEAD push, CTX over outputs[1..], a graph slot for W) is
S2. So these tests cover W's own rules, not the proof.

## What W checks (withdraw branch, `wcov.mjs` `buildW`)

W is P2SH32. Its redeem script is 499 B. Its unlocking is, bottom first: S, B, L, HS (128 B), slot, redeem.

1. **Graph.** TXINPUTCOUNT = nIn, INPUTINDEX = wIdx, and SHA-256(input 0's locking) = HR (the hash of R).
2. **Own token.** The category is CAT ‖ 0x01 (mutable), and the commitment is `0x57 ‖ nfRoot ‖ histRoot ‖ epoch` (69 B).
3. **HEAD's pushes.** W reads HEAD's unlocking (input 0) with OP_INPUTBYTECODE. Its last 99 B must be
   `0x20 ROOT 0x20 NF 0x20 CTXW`, and every push header is checked.
   - Minimal pushes are consensus, and R checks every HEAD item's size, so this suffix is exactly those items.
   - **S2 must keep that tail:** HEAD's items end with ROOT, NF, CTXW, each 32 B and size-checked by R.
4. **Ring.** ROOT ≠ Z, 0 ≤ slot < 16, and ROOT with the 4 siblings in HS (exactly 128 B) hashes to histRoot.
5. **Nullifier set.** K = SHA-256("t9NF" ‖ NF)[0..8). The SMT code returns the old root O and the new root N, and
   O must equal nfRoot (so NF is absent).
6. **Output 0.**
   - Its locking equals W's own locking.
   - Its category is CAT ‖ 0x01, and it carries no fungible amount.
   - Its commitment is `0x57 ‖ N ‖` (histRoot ‖ epoch, the bytes copied from the input).
   - Its value is W's input value − D, with D = 1,000,000 sat.

**No second W.** CAT is pinned in the redeem script. A mutable NFT input allows at most one NFT of its category in the
outputs, and output 0 must hold it, so no other output can carry the category.

## The SMT (`smt.mjs` reference, `wcov.mjs` `smtCode`)

**Definition (as in the design):**
- Depth 64.
- An absent leaf is Z (32 zero bytes); a present leaf is ONE = 0x01 ‖ 0³¹.
- H(Z, Z) = Z; otherwise H(l, r) = SHA-256(l ‖ r).
- Level 0 is the leaf level. At level l, the node is the right child iff bit l of K is 1.

**Compressed path:**
- An 8 B bitmap: bit l is set ⇔ the level-l sibling is not Z.
- The non-Z siblings, level 0 first.
- **One addition to the design:** L, the lowest set bit of the bitmap (64 if none). It is derived from the bitmap,
  costs 1–2 B, and the script checks it with shifts: (B + 2⁶⁴) >> L is odd, and shifting it back by L gives B + 2⁶⁴.
  A sent sibling must not be Z, so every path has exactly one encoding.

**Script:**
- **Loop A** (levels 0..L−1): every sibling is Z, so O stays Z and only N is hashed. It costs about 22 instructions per level.
- **Loop B** (levels L..63): the sibling comes from S when its bitmap bit is set, otherwise it is Z. O and N are both
  hashed. It costs about 63 instructions per level. From level L on, O ≠ Z, so H is plain SHA-256 there.
- After both loops, every bitmap bit and every byte of S must have been used, and exactly 64 levels must have run.

**Why two loops.** The first version used one loop with the H(Z, Z) rule inside: about 81 instructions per level,
0.575M op-cost. It **did not fit** the W input's budget (about 0.52M at a 650 B unlocking). The design's 0.2M estimate
missed the 100-per-instruction base cost. The two-loop version costs 0.19–0.23M on natural trees.

## Genesis (`genesis.mjs` → `results/genesis.json`)

- **Notes.** 2 epochs × 16 notes (k = 4), 32 notes in all, so that S2's 24 re-proved statements can each use a different
  note. Note i: nk and r are 4 lanes < p each, derived from SHA-256.
  - NF = T(P(nk ‖ 0,0,0,TAG_NF)), leaf = T(P(NF ‖ r)) (the M1 relation of prover/src/stmt.rs).
- **Tree.** Poseidon2-Gl-8, depth 30, leaf i at index i, with zero-hashes on the right. Epoch e's root is the tree of the
  first 16(e+1) leaves.
- **Ring.** Slots 0 and 1 hold the two epoch roots (4 lanes u64 LE, the HEAD push format), and the other 14 slots are Z.
- **W genesis commitment.** nfRoot = Z, histRoot, epoch = 2.
- **For S2.** The file lists every note's nk, r, NF, leaf, index, slot, root and 30 siblings.
  - Track 8's prover derives its siblings from a seed, so S2 needs a witness input for given (nk, r, index, siblings).
    That is a witness change, not a circuit change.
  - The Poseidon2 here is S0's `permRef`, which matches p3-goldilocks on 1,005 inputs. The epoch roots will be checked
    for real when S2's proofs carry them as public values.

## Results

`node test-w.mjs` (seed 1, 210 s) → `results/s1-w.json`. Result: **PASS**.

**1. SMT library vs the JS reference.** 10,000 cases, 0 disagreements. The script must accept exactly when the
reference says the key is absent, and then O and N must equal the reference's roots before and after the insert.
- 6,449 inserts and 3,551 present keys.
- Key kinds:

  | kind | cases |
  |---|---|
  | random | 2,192 |
  | shared top prefix of 1–63 bits | 2,243 |
  | present | 2,157 |
  | one bit flipped | 1,120 |
  | leaf neighbour K xor 1 | 1,166 |
  | extremes (0, 2⁶⁴−1, …) | 1,122 |

- Trees were pre-seeded with 0 to 4,096 keys.
- All 65 values of L (0..64) occur, with up to 25 siblings.

**2. W covenant vs the reference, on whole transactions.** 10,000 transactions, 0 disagreements.
- libauth BCH 2026 standard, checking every input and the transaction.
- 7,460 withdrawals were accepted. 2,540 attempts with an already-spent NF were all rejected.
- The ROOT was taken from slot 0 or 1 at random.

**3. Rejection families.** 199 cases plus 4 honest controls, over 4 states: empty set, 1 spent, 40 spent, 7,460 spent.
- Every case is rejected by W's input, and input 0 (the stand-in R) still accepts, except in the families that change
  input 0 itself.
- A guard fails any tamper that leaves the transaction unchanged. 7 tampers that cannot apply in a state (for example,
  swapping siblings when there is only one) are listed as skipped.

| family | cases | what |
|---|---|---|
| nf | 12 | NF + 1 (lane 0 or 3) in HEAD with W's witness for NF; NF + 1 with its own honest witness but the output for NF |
| present | 6 | an already-spent NF (its membership path); the same NF with its stale pre-spend witness |
| bitmap | 37 | a set bit cleared; an unset bit set above or below L; an unset bit set and Z sent as its sibling; L ± 1; L = 64; bitmap 7 or 9 B |
| sibling | 24 | one bit flipped in the first or last sibling; the first two swapped; the last dropped; an extra 32 B or 1 B; the path of another absent key |
| ring | 32 | ROOT not in the ring; the other epoch's ROOT; the wrong slot, slot 16 or −1; a flipped ring sibling; 96 B of ring siblings; ROOT = Z with an empty slot's path |
| carry | 32 | output nfRoot unchanged, or the root after another key; histRoot changed or replaced; epoch + 1; prefix 0x44; one byte added or dropped |
| output | 20 | output 0 immutable; the token burned; the token moved to output 1; another locking; outputs 0 and 1 swapped |
| value | 16 | in − D ± 1; in; in − 2D |
| graph | 16 | input 0 not R; W at input 0; a third input; W alone |
| head | 4 | an extra push after CTXW (the stand-in R also rejects) |

**Double spend in sequence.** A withdrawal is accepted. The same NF is then rejected from the new state, and replaying
the first witness against the new state is also rejected.

**4. Cost of the W input** (libauth standard; there is no OP_DEFINE, so the BCHN-adjusted figure is the same):

| state | siblings | L | W unlocking | op-cost | budget | share | tx bytes |
|---|--:|--:|--:|--:|--:|--:|--:|
| empty set | 0 | 64 | 645 B | 221,167 | 548,800 | 40.3% | 1,020 |
| 10 spent | 3 | 60 | 742 B | 234,600 | 626,400 | 37.5% | 1,117 |
| 1,000 spent | 11 | 51 | 999 B | 283,254 | 832,000 | 34.0% | 1,374 |
| 2¹² random keys | 12 | 52 | 1,031 B | 278,176 | 857,600 | 32.4% | 1,406 |
| 2¹⁶ random keys | 15 | 49 | 1,127 B | 295,466 | 934,400 | 31.6% | 1,502 |
| constructed: one key, K xor 1 | 1 | 0 | 676 B | 519,621 | 573,600 | **90.6%** | 1,051 |
| constructed: 64 siblings | 64 | 0 | 2,694 B | 663,072 | 2,188,000 | 30.3% | 3,069 |

- Over the 10,000-transaction run, the W input cost 0.220–0.354M op-cost, at most 41.3% of its budget. The largest
  transaction was 1,566 B.
- **The tight case is a small L with few siblings.** Each loop-B level with a Z sibling costs about 6.6K op-cost and
  brings no bytes. The 90.6% case needs a stored key that shares the top 63 bits with K. Since K is a hash of a hidden
  NF, nobody can aim for it, and it does not occur by chance.
- W has no padding item. If R's changes in S2 ever push this close to the limit, a pad push can be added to W's unlocking.

**Compared with the design's estimate.** The W input needs 0.65–1.1 KB, against the design's 1.5–1.9 KB for the W
input, the SMT path and the W output in tx1. Its op-cost is 0.22–0.30M, against the design's estimate of about 0.2M
for the SMT alone.

**BCHN v29.1.0 regtest** (`s1-bchn-export.mjs` → `results/s1-bchn-policy.jsonl`):
- One fresh POLICY=1 node under work/pool/bchn (bchn-t9s1q), with listen=0 and connect=0. It is stopped.
- W was rebuilt for the node-check faucet category.
- Four withdrawals were each allowed by `testmempoolaccept` at the default policy and mined: genesis, 1,000 spent, the
  90.6% worst case, and 64 siblings.
- This confirms on BCHN: 2026 loops, OP_LSHIFTNUM/RSHIFTNUM, a P2SH32 token covenant, and OP_INPUTBYTECODE reads.
- The faucet's minting baton is not burned in this setup, so this run says nothing about state uniqueness (L1). The
  real genesis, which burns the baton, is S3.
- A first attempt on datadir bchn-t9s1p failed before sending anything (nc.ts also needs `OPCOST_DIR`). That node was
  stopped.

## Files

| file | what |
|---|---|
| `smt.mjs` | the JS reference: an SMT node store, compressed paths, ring root and path, W commitment encoding |
| `wcov.mjs` | the script: `smtCode` (the two-loop SMT), `buildW` (the W redeem), `stubR` (the S1 stand-in R), `smtHarness` |
| `wtx.mjs` | the withdrawal transaction builder (with tamper hooks), `runTx`, `honest` (reference witness) |
| `genesis.mjs` | the genesis notes, the Poseidon2 deposit tree, the ring, and the W genesis commitment → `results/genesis.json` |
| `test-w.mjs` | the acceptance test → `results/s1-w.json` |
| `s1-bchn-export.mjs` | node-check workloads → `results/s1-bchn-policy.jsonl` |

## Reproduce

```
node genesis.mjs
node test-w.mjs                      # --lib 10000 --w 10000 --seed 1
node s1-bchn-export.mjs $(npx tsx <bench>/research/node-check/nc.ts category) $CACHE/s1-bchn/t9-s1.json
# bench: export OPCOST_DIR=<dir>; POLICY=1 research/node-check/node.sh start NAME 9
#   (cd research/node-check && npx tsx nc.ts policy --node NAME --src json:$CACHE/s1-bchn/t9-s1.json --out policy.jsonl)
#   research/node-check/node.sh stop NAME
```

## Parameters S2/S3 must set

These are the `makePool` / `buildW` parameters.
- HR = SHA-256 of R's P2S locking.
- nIn = the input count of the final transaction.
- wIdx = W's fixed input index, which must not be 0.
- CAT = the real genesis category (internal byte order).
- The HEAD tail: ROOT, NF, CTXW, in that order, at the end of HEAD's unlocking.

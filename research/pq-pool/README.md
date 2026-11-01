# Track 9: post-quantum shielded pool (S0–S4, research)

DESIGN-T9 with the maintainer's 1-day cut (S0–S3, merged), then S4 (wip/pool9b). Stage folders:

- `p2/`: S0, Poseidon2-Goldilocks-8 in CashVM.
- `w/`: S1, the SHA-256 nullifier SMT and the W-state covenant (S4 adds W's flush branch).
- `r/` (with `prover/`): S2, the pool R and the 24 re-proved genesis statements (S4 adds R's W-slot pin, A3).
- `node/`: S3, BCHN regtest runs of the 2-transaction withdrawal; S4's end-to-end run (`s4.ts`).
- `d/`: S4, the D-state covenant (deposits into a SHA-256 queue), the permissionless flush (Poseidon2 subtree and path in
  4 worker inputs) and the 16-slot ring. Results and limits in `d/README.md`.

Each folder has its own README with results and limits. `summary-t9.json` (from `node summary-t9.mjs`) is the S0–S3
snapshot. `summary-s4.json` (from `node summary-s4.mjs`) holds S4 and the S1–S3 re-runs that S4's changes required
(`rerun-s4.sh`; results in `r/results/s4rerun/`, `w/results/s4rerun/`, `node/results/t9s3b*`).

**S4 headline.**
- **Sizes.** A deposit is 645 B. A flush is 42.1 KB (D, W and 4 workers, max input 91.1%, 41 compressions). R gains 46 B
  (the pin), and W's redeem grows from 499 to 671 B (the flush branch). The 2-tx withdrawal at the genesis state is
  91,229 + 41,675 = 132,904 B (S2: 132,640).
- **libauth.** 72 cases, 0 unexpected. The flush roots equal the offline tree over 64 deposits in 4 flushes, and again
  over 272 deposits in 17. Root 0 expires at the flush with epoch counter 16.
- **BCHN regtest (POLICY=1).** genesis, then 272 deposits, then 17 flushes (each root = the offline tree), then 5
  proofs, then 4 withdrawals. Each valid transaction was allowed by testmempoolaccept. The stale-root withdrawal was
  rejected by W.
- **S1–S3 re-runs.**
  - test-w: PASS.
  - S2 production sweep: 5,055 cases (the 4,977 plus 78 `wpin`), 0 unexpected.
  - S2 harness: 2,387 cases, 0 unexpected.
  - S3 on BCHN: 24/24, and replay, chain10, race and conflict all as before, with 76/76 allowed.

SOUNDNESS-T9 (S7a) is in `SOUNDNESS-T9.md`: lemmas L1–L7, the owner table, and the status of A1–A5 below (plus a new
A6, the thread category's minting NFTs). The section below is the input it was written from.

## Assumptions and known properties (input to SOUNDNESS-T9)

**A1. Ring roots are unique to one pool (needed for L6, withdrawals ≤ deposits). S4: documented, not changed.**
- A proof binds only ROOT, NF and CTX. Neither the proof nor the statement names a pool, and each pool (each category)
  has its own nullifier set.
- So a note whose root is in two pools' rings can be withdrawn once from each. S3's pool B shows this with the static
  genesis ring: it withdrew statements 0–12 again after pool A had paid 0–23 (`node/README.md`). The S4 re-run
  (`t9s3b`) repeats this with a separate R for each pool. **R's W-slot pin (A3) does not change it**: R_A only works
  with W_A, but the same proof also verifies under R_B with W_B.
- **Why no change is needed with S4.**
  - A pool's genesis ring is empty (16 × Z, and W rejects ROOT = Z).
  - Every later ring entry is written by that pool's flush. The flush computes the root of the pool's own tree from the
    leaves queued by its own deposits, and each deposit paid D + f into D. D moves 16 D to W per flush.
  - So a ROOT in pool X's ring is the root of X's tree. A note withdrawable from X has its leaf in X's tree, and
    therefore paid D into X.
  - Withdrawals from X ≤ distinct NFs over X's leaves ≤ deposits into X. This is L6 per pool, given Poseidon2 collision
    resistance (two different leaf sequences with one root) and L1.
  - A note can be withdrawn from two pools only if its leaf was deposited (and paid for) in both.
  - Copying another user's leaf into pool B costs the copier D and lets only the note's owner, who knows nk and r,
    withdraw it.
- **Making NF or the leaf pool-specific** would need an AIR change: NF = T(P(nk ‖ 0,0,0,TAG_NF)) is fixed by M1. That
  means re-proved vectors and a soundness re-check, which is out of S4's scope (the circuit is unchanged).
  - Putting CAT into the SMT key changes nothing, because each pool's set is already separate.
- **What remains is a deployment rule.** Never seed a funded pool's ring with roots it did not flush. S1–S3's static
  genesis tree breaks this rule on purpose, as a test fixture (pool B), and is not a deployment pattern.

**A2. W's state uniqueness (L1) rests on an off-chain check of the genesis transaction.**
- W checks its own category CAT ‖ 0x01 and that output 0 carries it. A mutable NFT has one successor, so the chain of
  W states is unique **if no minting NFT of CAT ever existed**. W cannot check this itself.
- Wallets and relayers must check the genesis transaction: exactly one NFT of CAT, mutable, and no minting capability.
  S3 checked this on BCHN for both geneses (`noMintingNft: true` in `node/results/s3-summary.json`).
- In S0–S3 this is a trust-anchor note, not a fund risk: W allows exactly one W input (nIn = 6, W at index 5), so a
  forged W UTXO made with a minting NFT could pay out only its own value.
- **S4 re-check: L1 now protects deposits.**
  - D and W are the two mutable NFTs of one category (prefixes 0x44 and 0x57). The flush identifies W by category and
    prefix.
  - With a minting NFT of CAT, someone could forge a W and receive a flush's 16 D, or forge a D.
  - The genesis check is therefore required for fund safety: exactly two NFTs of CAT, both mutable, one at D's locking
    with prefix 0x44 and one at W's with prefix 0x57, and no minting NFT.
  - S4's BCHN genesis was checked this way (`d/README.md`).

**A3. R pins W. Closed in S4.**
- S0–S3: in the final transaction, R checked that input 5's locking is not R and that output 0 does not carry the thread
  category. It did not check that input 5 is W. A non-W input in the slot passed R (griefing only: no pool funds move,
  but the user's thread NFT is consumed and NF is not inserted).
- **S4:** the final HEAD also checks input `TXINPUTCOUNT − 1` (input 5): category = CAT ‖ 0x01 (mutable) and commitment
  prefix 0x57. The prefix check is needed because the pool's D state has the same category.
  - There is no hash cycle. CAT is the txid of the genesis input's outpoint and is fixed before R, W and D are built.
- **Cost: R is pool specific.**
  - Each pool has its own R (one more 46 B check in a code blob; R stays 118 B), its own HR in W, and its own R carrier
    UTXOs for relayers.
  - tx0 and tx1 each grow by 46 B, and BCHN's per-input OP_DEFINE charge by 92 B (37,790 to 37,882: the 46 B count in the
    function body and again in the code blob that defines it).
  - Proofs are not pool specific.
- **Tests.** S2's `documented` case is now the `wpin` family (78 cases, 0 unexpected; HEAD rejects, others accept):
  - a non-W input;
  - **another pool's W whose HR names this R** (its own script accepts);
  - the pool's category with prefix 0x44.

**A4. Scope of the BCHN policy checks.**
- **S3.** The testmempoolaccept result (76/76 allowed) covers **each withdrawal transaction** (tx0 and tx1). The W
  genesis and funding transactions spend bare-OP_1 coinbases, were mined through submitblock, and were not
  policy-tested.
- **S4.** The pool genesis spends a P2SH32(OP_1) output and **was** policy-tested, as were every deposit, flush and
  withdrawal transaction (299 allowed). The funding transactions (deposit inputs, worker UTXOs, R carriers, thread NFT)
  are still mined through submitblock.

**A5. How to read the sweep totals.** The S2 production sweep's "4,977 cases, 0 unexpected" is not 4,977 on-chain
rejections. It is 4,834 rejections, 88 required accepts and 55 encoder-only relabels (a malformed-by-length proof whose
on-chain witness is the valid one, so the script accepts it). Per-family counts are in `r/README.md` and in the JSON's
`families`. The S4 re-run has 5,055 cases: 4,912 chain rejections (the 4,834 plus 78 `wpin`), 88 required accepts and
55 encoder-only relabels.

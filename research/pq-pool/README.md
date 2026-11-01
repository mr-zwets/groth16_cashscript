# Track 9: post-quantum shielded pool (S0–S3, research, wip/pool)

DESIGN-T9 with the maintainer's 1-day cut: S0–S3 only. Stage folders:

- `p2/`: S0, Poseidon2-Goldilocks-8 in CashVM.
- `w/`: S1, the SHA-256 nullifier SMT and the W-state covenant.
- `r/` (with `prover/`): S2, the pool R and the 24 re-proved genesis statements.
- `node/`: S3, BCHN regtest runs of the 2-transaction withdrawal.

Each folder has its own README with results and limits. `summary-t9.json` (from `node summary-t9.mjs`) collects the
headline numbers of all four stages. There are no deposits and no flush (S4), and SOUNDNESS-T9
(S7) is not written. The section below collects what SOUNDNESS-T9 must state, as found in the S0–S3 work and its
review.

## Assumptions and known properties (input to SOUNDNESS-T9)

**A1. Ring roots are unique to one pool (needed for L6, withdrawals ≤ deposits).**
- A proof binds only ROOT, NF and CTX. Neither R nor the statement names a pool, and each pool (each W category) has
  its own nullifier set.
- So a note whose root is in two pools' rings can be withdrawn once from each. S3's pool B shows this as valid
  behaviour: it is a second W genesis with the same genesis ring and the same R, and it withdrew statements 0–12
  again after pool A had paid statements 0–23 (`node/README.md`).
- L6 therefore holds per pool only when each pool's ring roots are its own.
  - With S4 deposits, a pool's ring roots are built from its own funded deposits, so this holds.
  - A static genesis tree (S1–S3) must never seed more than one funded pool. S3's pool B is a test of this case, not a
    deployment pattern.
- A possible later change: put the pool category into the leaf or the NF domain. This is not done.

**A2. W's state uniqueness (L1) rests on an off-chain check of the genesis transaction.**
- W checks its own category CAT ‖ 0x01 and that output 0 carries it. A mutable NFT has one successor, so the chain of
  W states is unique **if no minting NFT of CAT ever existed**. W cannot check this itself.
- Wallets and relayers must check the genesis transaction: exactly one NFT of CAT, mutable, and no minting capability.
  S3 checked this on BCHN for both geneses (`noMintingNft: true` in `node/results/s3-summary.json`).
- In S0–S3 this is a trust-anchor note, not a fund risk: W allows exactly one W input (nIn = 6, W at index 5), so a
  forged W UTXO made with a minting NFT could pay out only its own value.
- Re-check when S4 adds D-state deposits that move funds into W.

**A3. R does not pin W (griefing only).**
- In the final transaction, R checks that input 5's locking is not R and that output 0 does not carry the thread
  category. It does not check that input 5 is W. Any non-W input in the W slot passes R (S2 sweep: 26 runs recorded as
  `documented` in `r/results/test-a-2tx-pool.json`).
- No pool funds move: outputs[1..] are still bound by CTX, so whoever supplies the slot input pays the payout. Pool
  funds leave only through W, which requires R and inserts NF.
- The cost is the user's: the thread NFT and the R carriers are consumed and NF is not inserted. The user can redo
  tx0 with the same proof.
- To close it, R can pin CAT ‖ 0x01 at input wIdx. There is no hash cycle (CAT is the txid of the genesis prevout,
  not derived from R), but R then becomes specific to one pool. Left open for the maintainer.

**A4. Scope of the BCHN policy checks.** S3's testmempoolaccept result (76/76 allowed) covers **each withdrawal
transaction** (tx0 and tx1). The W genesis and funding transactions spend bare-OP_1 coinbases, were mined through
submitblock, and were not policy-tested.

**A5. How to read the sweep totals.** The S2 production sweep's "4,977 cases, 0 unexpected" is not 4,977 on-chain
rejections. It is 4,834 rejections, 88 required accepts and 55 encoder-only relabels (a malformed-by-length proof whose
on-chain witness is the valid one, so the script accepts it). Per-family counts are in `r/README.md` and in the JSON's
`families`.

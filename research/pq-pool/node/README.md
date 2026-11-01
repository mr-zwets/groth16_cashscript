# Track 9 S3: the pool withdrawal on BCHN regtest (2-tx a′ + W)

Date 2026-11-01, branch `wip/pool`. One fresh stock BCHN v29.1.0 regtest node, `t9s3a`, configured with `POLICY=1`:
acceptnonstdtxn=0 and otherwise the default relay policy, listen=0, connect=0, rpcbind 127.0.0.1. Its datadir is
`work/pool/bchn/bchn-t9s3a`. The node is stopped. The node ran on CPU 9 and the driver on CPU 7, under nice. The
24 statements are S2's vectors (`work/pool/cache/s2/vec`); none was re-proved.

**Result: S3 acceptance passes.** Every item in DESIGN-T9 §6 S3 holds on BCHN, and libauth agrees on every transaction.

| check (DESIGN §6 S3) | result |
|---|---|
| 24/24 withdrawals accepted (2-tx) | **24/24**, each confirmed: tx0 and tx1 sent (tx1 with tx0 unconfirmed) and mined in one block. tx0 is 91,183 B and tx1 is 41,457–41,650 B (tx1 grows with the SMT path). Max input 91.1% of budget (QRY, BCHN-adjusted). The W input uses 36.8–44.0% of its budget, with a 645–838 B unlocking. |
| NF double spend rejected by libauth and BCHN | **Rejected.** Pool A, after the 24, replays statement 0. The fresh tx0 is valid and is mined. Its tx1 is rejected in libauth at the W input (OP_VERIFY), in testmempoolaccept (`mandatory-script-verify-flag-failed (… OP_EQUALVERIFY)`), by sendrawtransaction, and as a block (`blk-bad-inputs`). This holds with the honest present-key witness and with a stale witness (an absence path from the genesis state). The W UTXO is unchanged afterwards. |
| 10-withdrawal unconfirmed chain on W, one block | **Mined in one block.** Pool B, statements 0–9: all 20 transactions were sent unconfirmed, and tx1_k spends the output 0 of tx1_{k−1}. Every testmempoolaccept allowed them. BCHN's own assembler (generatetoaddress) put all 20 in block 275 (21 txs, 1,327,416 B), and the mempool was empty afterwards. |
| race: loser's tx1 rebuilt, not re-proved, accepted | **Accepted.** Statements 10 (X) and 11 (Y) both built tx1 on the same W outpoint, and X was sent first. Y's tx1 was rejected with `txn-mempool-conflict`. Y then rebuilt only tx1 on X's unconfirmed output 0. It reused the same tx0 (byte-identical) and the same R inputs 0–4 (byte-identical unlockings and outpoints), with the same payout. Only the W input and output 0 changed. The rebuilt tx1 was allowed and sent, and one block held X0, Y0, X1 and Y1′ but not the loser. |
| testmempoolaccept at the default policy for each withdrawal transaction | **76/76 valid withdrawal transactions (tx0 and tx1) allowed.** That is 48 seq, 20 chain, 4 race, 3 conflict and the replay's tx0. The only refusals were the 5 expected ones (below). tx0 pays 2.30 sat/B and tx1 1.51–1.52 sat/B, as built by S2. |

Extra (pool B, statement 12 relayed twice from two tx0 threads with the same NF): the second tx1 on the same W
outpoint is a `txn-mempool-conflict`. Rebuilt on the first one's unconfirmed output 0, it is rejected by W in
libauth, in testmempoolaccept (script error) and in a block (`blk-bad-inputs`). This is the "same NF in conflicting
transactions" case from S2, now on BCHN, including a sequence through the mempool.

The 5 testmempoolaccept refusals, all expected:
- replay present-path tx1, replay stale-witness tx1 and conflict rebuilt tx1: `16: mandatory-script-verify-flag-failed (Script failed an OP_EQUALVERIFY operation)`;
- race loser tx1 and conflict second tx1: `18: txn-mempool-conflict`.

## Setup (what is real on chain)

- **Thread category.** This is R's code constant. It is the node faucet's category (nc.ts: a minting baton from a genesis on coinbase(1):0), as in Track 8's node check. R is therefore rebuilt with this category: 118 B, SHA-256 `199fcb9a…3481`. S2's `6cde4a7e…830a` used the test constant. Only the 32 category bytes in the code differ; sizes, the DEFINE bytes (37,790) and the per-input pattern are unchanged, and tx sizes equal S2's grade (91,183 + 41,457 B at the genesis state).
- **W categories are real geneses with no minting NFT.** Each W is created by spending a mature coinbase's output 0 into one mutable NFT whose category is that coinbase's txid. It sits at W's P2SH32 locking (499 B redeem) and carries the genesis commitment. BCHN's decoded genesis tx has exactly one output of that category, and it is `mutable`. No minting NFT of the category ever existed, which is the design's "baton burned". W cannot check this on chain; it is an off-chain check of the genesis transaction that wallets and relayers must make (`../README.md` A2).
  - Pool A: `6d2cc7ea…4dd2`, 30 × D.
  - Pool B: `266a6524…6613`, 20 × D.
  - The genesis transactions were mined by submitblock and not policy-tested. Their input is a bare-OP_1 coinbase, the same as the nc.ts funding transactions.
- **Two pools.** All 32 genesis notes have NFs, but only notes 0–23 have proofs. Pool A spends statements 0–23 once each. Pool B is a second W genesis with the same R and a fresh empty set, and spends statements 0–12 again: the chain, the race and the conflict. Both W instances use the same genesis ring (the S1 static history).
  - This is valid behaviour for this setup, and it shows an assumption: the proof binds only ROOT, NF and CTX, and nullifier sets are per pool, so withdrawals ≤ deposits (L6) holds per pool only when each pool's ring roots are its own. A static genesis tree must never seed more than one funded pool (`../README.md` A1).
- **W state is checked against the node.** After every step, `gettxout` (mempool included) of W's current outpoint must match the JS state: the value, the category, capability mutable, the commitment `0x57‖nfRoot‖histRoot‖epoch`, and the locking.
- **Funding.** The R carriers (2,000 sat), tx0's minting NFT (200,000 sat) and the payouts are S2's fixture values. The R carriers and tx0's minting NFT are funded in a mined block by the nc.ts Funder; funding transactions are not policy-tested, as in nc.ts. tx1's input 0 spends tx0's output 1 (the thread NFT).
- **libauth.** Each transaction is evaluated per input in BCH 2026 standard and consensus mode, and as a whole transaction in standard mode, with the real outpoints and sources. The libauth used is Track 8's unpatched 3.1.0-next.8; for the R inputs, the BCHN-adjusted figure adds the 37,790 B of OP_DEFINE bodies, and every input is within budget.

## Files

- `s3.ts`: the driver. Header comment lists the scenarios.
- `node.sh`: copy of bench `research/node-check/node.sh`.
- `rig.ts`: copy of bench `research/opcost-timing/bchn/rig.ts`.
  - Both copies are unchanged from bench main 1d00508.
  - The Funder in `s3.ts` is nc.ts's, adapted to fund one batch in one transaction.
- `summarize-s3.mjs`: summary of the run.
- `run-s3.sh`: start the node, run the driver, stop the node.
- `results/s3.jsonl`, `results/s3.log`, `results/s3-summary.json`: this run (node t9s3a).

Reproduce: `S2_VEC=work/pool/cache/s2/vec OPCOST_DIR=work/pool/bchn ./run-s3.sh <fresh NAME>`. It takes about
15 minutes. node_modules is the worktree root symlink, which provides tsx and libauth.

## Limits

- **Not timed.** Track 8's node check already timed the a′ plan; this run is about acceptance and policy.
- **No deposits or flush (S4).** The history is S1's static genesis ring.
- **Coinbase-only funding.** The W genesis and the funding transactions spend bare-OP_1 coinbases mined by the rig and were not policy-tested. The S3 acceptance criterion is stated for each withdrawal transaction, not each transaction.
- **S2's open item still holds: R does not pin W.** It was not exercised on BCHN, by design (constructive tests only).

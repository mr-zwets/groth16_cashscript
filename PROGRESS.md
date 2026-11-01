# Track 9 (pool) progress — wip/pool only

Design: zk-verifier-bench research/pq-pool/DESIGN-T9.md (maintainer decisions: scope S0–S3).

## S0 — Poseidon2-Gl-8 in CashVM: DONE (gate not triggered)

- Worktree from origin/main 2d96adc. Code and results: research/pq-pool/p2/ (README.md has the full numbers).
- Correctness: script (libauth cons + std, 8-lane and 4-lane compress) = permRef (air8_ref) = p3-goldilocks
  default_goldilocks_poseidon2_8() on the test vector + 1,000 random + 4 edge inputs (1,005/1,005); 100/100 wrong-output
  rejections. results/s0-p2.json.
- op-cost per permutation: 580,112–582,868 (8 lanes), 571,221–573,974 (compress). Straight-line code, no DEFINE inside,
  so BCHN-adjusted = libauth; as a DEFINE'd body, + 7,567 B once per input. Gate (> 1.2M): NOT triggered; k = 4 stays.
- Flush worker input (10,000 B unlocking, P2S 94 B, whole-tx bchStd): 13 compressions fit (93.6% BCHN-adjusted);
  574,314 per compression in a loop, 50,276 fixed per input. 100 KB input: 138.
- Flush table: k = 4 → 41 compressions, 23.75M, 4 padded 10 KB inputs (design est. 20–41M, 3–5). k = 5 → 5 inputs.
  Not included: queue/frontier/ring SHA-256, lane range checks, covenant checks (S4).
- BCHN v29.1.0 regtest (fresh POLICY=1 node under work/pool/bchn, stopped): fit13 allowed + mined; DEFINE probe
  (budget between libauth and libauth + DEFINE) rejected by policy (VM cost limit exceeded), as node-check predicts.

## S1 — SHA-256 SMT + W-state covenant (static genesis history): DONE (acceptance PASS)

- Code and results: research/pq-pool/w/ (README.md has everything). W tested with a stand-in R (size checks only);
  the real R is S2.
- W redeem 499 B (P2SH32). Checks: graph (nIn, wIdx, SHA-256(input 0 locking) = HR), own category CAT||01, HEAD tail
  read via INPUTBYTECODE (last pushes ROOT NF CTXW, headers checked — S2 must keep this tail), ROOT != Z and in ring
  (slot + 128 B), SMT absence (O = nfRoot) + insert, output 0 (same locking, category, no FT, commitment 0x57||N||
  histRoot||epoch copied, value = in - D, D = 1,000,000).
- SMT: depth 64, H(Z,Z)=Z, compressed path = bitmap + non-Z siblings + L (lowest set bit, 1 B, checked with shifts;
  addition to the design). Two loops (A: levels < L, N only; B: levels >= L). First one-loop version cost 0.575M and
  did NOT fit the W input budget (design's 0.2M estimate missed the per-instruction cost); two-loop: 0.19-0.23M.
- Acceptance (results/s1-w.json, seed 1): library vs JS reference 10,000 cases (6,449 inserts, 3,551 present; long
  shared prefixes, neighbours, extremes; all L 0..64) 0 disagreements; W on whole txs (libauth BCH 2026 std) 10,000
  (7,460 withdrawals, 2,540 spent-NF attempts) 0 disagreements; 199 rejection cases + 4 controls (NF+1, present key, bitmap/L,
  sibling, ring, carry-over, output, value, graph) all rejected by W; double spend in sequence rejected.
- W input cost: 0.22-0.30M op-cost (31-41% of budget) natural; constructed worst (L = 0, one sibling) 90.6%;
  W unlocking 645 B - 1.1 KB; tx 1,020-1,566 B.
- Genesis (results/genesis.json): 2 epochs x 16 notes (32, so S2's 24 statements get distinct notes), Poseidon2
  depth-30 tree, ring slots 0/1, epoch 2. S2 needs a prover witness input for given nk, r, index, siblings.
- BCHN v29.1.0 regtest (fresh POLICY=1 node work/pool/bchn/bchn-t9s1q, stopped): 4 withdrawals (genesis, 1,000 spent,
  90.6% worst, 64 siblings) allowed at default policy and mined (loops, shifts, P2SH32 token covenant).

## S2 — pool R + re-proved M1 statements: DONE (acceptance PASS)

- Code and results: research/pq-pool/r/ (README.md), prover copy research/pq-pool/prover (explicit witness case
  m1@LEAF@0@CTX@WIT; circuit unchanged), vectors/S2 (3 committed; 24 + 4 in work/pool/cache/s2).
- R changes: ROOT a HEAD push before NF (lanes < p in HEAD/CODE/FIN; DAG reads it), CTX over outputs[1..] (count
  n-1; >= 1 payout needed), final tx graph = 5 R inputs + W at index 5 (R checks its locking != R; does not pin W);
  final HEAD thread rules skip input 5 and output 0 (output 0 must not carry the thread category). R is now
  statement-independent: one (R, W) pair for all 24 statements (R 118 B, SHA-256 6cde4a7e..830a; W 499 B).
- 24 statements on genesis notes 0-23: every vector's ROOT/NF/CTX equals the note's (JS Poseidon2 genesis = Rust).
- grade (libauth BCH 2026, today's rules, BCHN-adjusted): 2tx+W 24/24, 91,183 + 41,457 = 132,640 B (+1,084 vs T8),
  QRY max 91.1%, W 645 B / 0.234M / 42.7%. 1tx+W measured: 24/24 at 99,594 B (406 B margin at the empty set;
  overflows once the SMT path grows ~400 B, a few thousand spends) — not a deliverable (decision 3).
- Sweeps: production 2tx+W 4,977 cases 0 unexpected (all T8 S7 families + nf/ring/windex/commit/out0/wonly);
  harness 2,387 cases 0 unexpected (= T8 S7 totals). 18 no-op tampers skipped (S3 'foreign ROOT' from a same-epoch
  vector = same ROOT). Documented: a non-W input at the W slot passes R (no pool funds move; consumes the thread NFT
  without NF insert); pinning W's category in R would close it (no cycle) — maintainer call.
- Not done: BCHN (S3); conflicting txs only shown as two valid tx1 on one W outpoint (mempool test is S3).

## S3 — BCHN regtest (2-tx withdrawal): DONE (acceptance PASS)

- Code and results: research/pq-pool/node/ (README.md; s3.ts driver, node.sh + rig.ts copied from bench main 1d00508,
  Funder from nc.ts). Fresh POLICY=1 node work/pool/bchn/bchn-t9s3a (BCHN 29.1.0, listen=0, connect=0), stopped.
- Real W geneses (pool A 30 D, pool B 20 D): mature coinbase vout 0 -> one mutable NFT, no minting NFT ever exists.
  Thread category = node faucet's, so R rebuilt (118 B, sha256 199fcb9a..; only the 32 category bytes differ from S2).
- 24/24 withdrawals (pool A, statements 0..23) accepted: tma allowed, sent, mined; 91,183 + 41,457..41,650 B; max
  input 91.1% (QRY), W 36.8-44.0%; gettxout of W matches the JS state after every step.
- NF double spend (statement 0 replayed, present-path and stale witness): tx0 valid and mined; tx1 rejected by
  libauth (W input), testmempoolaccept/sendrawtransaction (mandatory-script-verify-flag-failed) and as a block
  (blk-bad-inputs).
- 10-withdrawal unconfirmed chain (pool B, statements 0..9): 20 txs sent unconfirmed, all in block 275, mempool empty.
- Race (statements 10/11): loser txn-mempool-conflict; rebuilt tx1 (same tx0, byte-identical R inputs 0..4, same
  payout; only W input and output 0 change) allowed and mined. Same-NF conflict (statement 12 twice): second tx1
  mempool conflict; rebuilt on the unconfirmed state rejected by W (libauth, tma, block).
- testmempoolaccept: 76/76 valid txs allowed; the 5 refusals are the expected ones.
- Not done: timing (Track 8 node check covers it), deposits/flush (S4). R does not pin W (S2 item) still open.

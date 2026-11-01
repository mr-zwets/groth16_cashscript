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

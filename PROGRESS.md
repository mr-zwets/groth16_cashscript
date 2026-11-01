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

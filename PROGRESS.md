# Track 9 (pool) progress — wip/pool only

Design: zk-verifier-bench research/pq-pool/DESIGN-T9.md (maintainer decisions: scope S0–S3).

## S0 — Poseidon2-Gl-8 in CashVM (in progress)

- Worktree created from origin/main 2d96adc. Code: research/pq-pool/p2/.
- Permutation script (p2gl8.mjs) matches p3-goldilocks on the test vector + 1,000 random + 4 edge inputs
  (results/s0-p2.json). op-cost per permutation about 0.58M (straight-line; no DEFINE inside).

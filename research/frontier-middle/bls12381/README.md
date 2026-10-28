# Track 2 frontier-middle research designs: BLS12-381

Both designs are bench entries: T1 is `bch-groth16-bls12381-sound-si-gls-dproj` (vmTarget bch-spec) and T2 is
`bch-groth16-bls12381-singleton-minop-rolled` (vmTarget bch-2026, P2SH32). Each had two Track 2 reviews (soundness;
measurement reproduction), both pass with minor findings only, handled in the 2026-10-28 fix round (see each design's
README). Both need an op budget looser than any VM that exists or is proposed today, so the bench grades them "not
BCH-compatible: op-cost", like the singletons. They show how much of the empty middle of the BLS12-381 bytes vs
op-cost frontier can be filled by recombining already-reviewed techniques (hint vs compute), with no new cryptography.

| design | dir | inputs | bytes (score) | op-cost libauth / BCHN-adj. (committed) | worst-case proof | k_min | model prediction |
|---|---|--:|--:|--:|--:|--:|--:|
| T1 SI-GLS + on-chain projective δ walk, E_A = 0 | `sigls-dproj/` | 1 | **18,892** | 36.89M / 36.90M | 37.87M (bench worst-case vector) | 1.65 bch-spec base, 2.50 bch-2026 base (max over the sweep) | 18,661 B / 37.3M |
| T2 rolled minop, on-chain γ/δ walks (P2SH32) | `minop-rolled/` | 1 | **8,712** (bare 8,674) | 192.76M / 192.76M | 218.29M | 27.9 (31.2 worst) bch-2026 base | 8,189 B / 189.3M |

E_k = max(bytes, op/(800k) − 41·inputs) in KB, BCHN-adjusted committed op. Today's best reviewed BLS value is in
parentheses; the change is relative to it.

| k | 2 | 5 | 10 | 25 | 50 | 100 |
|---|--:|--:|--:|--:|--:|--:|
| today | 26.5 | 26.5 | 26.5 | 26.5 | 24.8 | 12.4 |
| T1 | **23.0 (−13%)** | **18.9 (−29%)** | **18.9 (−29%)** | 18.9 (−29%) | 18.9 (−24%) | 18.9 (+52%) |
| T2 | 120 | 48.2 | 24.1 (−9%; worst proof +3%) | **9.6 (−64%; worst proof −59%)** | **8.7 (−65%)** | **8.7 (−30%)** |
| best of T1, T2 | 23.0 (−13%) | 18.9 (−29%) | 18.9 (−29%) | 9.6 (−64%) | 8.7 (−65%) | 8.7 (−30%) |

The two designs together beat today's best at every k from 2 to 100, and in the policy-relevant zone k = 5–10 by 29%
(T1).

Each design's README has its soundness argument (built on the reviewed design it forks), the differences, and how to
reproduce. Measurement used the bench harness's `benchmark()` on zk-verifier-bench branch
`wip/frontier-middle-build-bls12381` (`research/frontier-middle/bls12381/run.ts`), plus loosened-budget runs on the
real target VM (bch-spec for T1, bch-2026 for T2) with `operationCostBudgetPerByte = 800·k`. BCHN-adjusted op-cost
adds the executed OP_DEFINE body bytes; BCHN charges them, while libauth charges 100 per OP_DEFINE (Track 1 report).

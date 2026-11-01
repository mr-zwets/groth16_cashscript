# wip/pool9b progress (Track 9 S4)

- [x] S4 D-state covenant (deposit, flush coordinator blob, 4 worker inputs) under research/pq-pool/d/
- [x] W flush branch (w/wcov.mjs), W redeem 499 -> 671 B
- [x] A3: R pins input 5 = pool W (category CAT||01 and commitment prefix 0x57); R pool specific (+46 B blob)
- [x] A1: documented (README A1: own-deposit rings bound withdrawals per pool; NF unchanged, AIR fixed)
- [x] libauth acceptance (d/test-d.mjs): 72 cases, 0 unexpected; 64 deposits/4 flushes = offline tree; wraparound; premature, frontier, lane >= p
- [x] re-runs: S1 test-w PASS; S2 grade 24/24 (132,904 B), sweeps 5,055 + 2,387 cases 0 unexpected; S3 BCHN (t9s3b) same verdicts, 76/76
- [x] BCHN e2e (t9s4a, POLICY=1): genesis, 272 deposits, 17 flushes, 5 proofs, 4 withdrawals allowed; stale root rejected at epoch 17
- nodes stopped: bchn-t9s4a, bchn-t9s3b (work/pool9b/bchn)

# wip/pool9b progress (Track 9 S4)

- [x] S4 D-state covenant (deposit, flush coordinator blob, 4 worker inputs) under research/pq-pool/d/
- [x] W flush branch (w/wcov.mjs), W redeem 499 -> 671 B
- [x] A3: R pins input 5 = pool W (category CAT||01 and commitment prefix 0x57); R pool specific (+46 B blob)
- [x] A1: documented (README A1: own-deposit rings bound withdrawals per pool; NF unchanged, AIR fixed)
- [x] libauth acceptance (d/test-d.mjs): 72 cases, 0 unexpected; 64 deposits/4 flushes = offline tree; wraparound; premature, frontier, lane >= p
- [x] re-runs: S1 test-w PASS; S2 grade 24/24 (132,904 B), sweeps 5,055 + 2,387 cases 0 unexpected; S3 BCHN (t9s3b) same verdicts, 76/76
- [x] BCHN e2e (t9s4a, POLICY=1): genesis, 272 deposits, 17 flushes, 5 proofs, 4 withdrawals allowed; stale root rejected at epoch 17
- nodes stopped: bchn-t9s4a, bchn-t9s3b (work/pool9b/bchn)

# S7a SOUNDNESS-T9
- [x] research/pq-pool/SOUNDNESS-T9.md: L1-L7 (DESIGN-T9 §6 outline), owner table (constants, genesis, deposit, flush, withdrawal tx1), A1 resolved (empty-ring rule moved into genesis check G), A2 carried (G, now full list incl. lockings and initial commitments), A3 closed, A4/A5 carried (test scope, reading rule), new A6 (thread-category minting NFTs only under R; rig faucet violates it on purpose)
- open: SE assumed; G/T have no standalone checker (S5); append correctness argued + tested, not machine-checked

# S7a fix round (review: 8 minors, no blocker/major; docs and accounting only, no script change)
- [x] d/README: 59 rejections (46 beyond premature/frontier/lane, not 54); 72 = 59 + 13 accepts; family table 76 = +4 seq equality checks
- [x] harness sweep split everywhere: 2,387 = 2,232 chain rejections + 51 accepts + 69 encoder-only + 35 not run on chain
- [x] full tree: last queue of up to 16 deposits after count = 2^30 permanently locked (documented; sentinel queue not implemented)
- [x] worker UTXOs anyone-can-spend: owner-table wording, keeper griefing in SOUNDNESS §7, dust-funding + broadcast-together advice
- [x] keeper break-even f_min ~ (42,129 + ~400) x feerate / 16 ~ 2.7k sat at 1 sat/B (setup size estimated)
- [x] T reworded for pool-specific R sharing TCAT; A6 updated
- [x] A1 status unified: "resolved by G (initial ring all Z); no script change" (README, d/README, summary-s4)
- [x] L3 step 4 / owner table: IO sizes data-independent, 472..~560 B (sampled), so PUSHDATA2 header always minimal
- re-runs: none needed (no script or test change); summary-s4.mjs regenerated, identical except the A1 string

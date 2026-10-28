# PROGRESS (wip/frontier-middle-build-bls12381) -- work note, must never land on main
(Note: main 6204686 carries a stale PROGRESS.md from wip/leftovers; this branch overwrites it.)

Track 2 build, BLS12-381. Research artifacts under research/frontier-middle/bls12381/ (not leaderboard entries).

- [x] T1 bls12381-t1-sigls-dproj (research/frontier-middle/bls12381/sigls-dproj): 18,892 B / 36.89M (BCHN 36.90M),
  worst 37.87M, k_min 1.64 (spec base). Harness pass; 15/15 invalid; pub-input 9/9; redteam 81/81; sweep 87/87 at k=2.
- [x] T2 bls12381-t2-minop-rolled (research/frontier-middle/bls12381/minop-rolled): P2SH32 8,712 B (bare 8,674) /
  192.76M, worst 218.29M, k_min 27.9 (31.2 worst). Existing minop vectors 5/5 accepted, 10/10 rejected; F
  differential test equal on all 5 vectors.
- [ ] T1 stage 2 (bls-native-sound port): not built.
- [ ] T1 kernel sharing (~-0.8 KB): not built.  [ ] T2 outliner pass: not run.
- bench glue: zk-verifier-bench wip/frontier-middle-build-bls12381 research/frontier-middle/bls12381/ (impls.ts, run.ts).

# wip/frontier-middle-build-bn254 (groth16_cashscript) -- work note, never merge to main
Base: origin/main 6204686. Track 2 build, BN254 targets T1 (bn254-t1-sigls-dproj) and T2 (bn254-t2-rolled-lazy-residue).
Sources: research/frontier-middle/bn254/. Bench worktree ../bench (same branch), glue under research/frontier-middle/.
- [ ] T1: fork sound-si-gls -> research/frontier-middle/bn254/sigls-dproj, projective delta walk
- [ ] T1: build, sweep (fixtures + dense), export, bench measurement, E_k
- [ ] T2: feasibility / build or early stop
- [ ] README

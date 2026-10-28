# wip/frontier-middle-build-bn254 (groth16_cashscript) -- work note, never merge to main
Base: origin/main 6204686. Track 2 build, BN254 targets T1 (bn254-t1-sigls-dproj) and T2 (bn254-t2-rolled-lazy-residue).
Sources: research/frontier-middle/bn254/ (README.md there has results, soundness, reproduce).
Bench worktree ../bench, same branch: research/frontier-middle/bn254/measure.ts (+ vectors, results.json), not registered.
- [x] T1 sigls-dproj: 16,571 B / 33.32M (inline variant 17,203 / 32.02M); 59-case sweep, harness 4/4, 15/15, PI 0/9. ACCEPT.
- [x] T2 rolled-residue: 9,776 B / 130.3M (worst 139.1M), mulc variant 9,116 / 147.4M; harness 4/4, 6/6, PI 0/9; 18-case sweep. ACCEPT.
- [x] README
- Not done: independent review; redteam.mjs (only existing invalid vectors allowed); T2 GLV vk_x; recompiler outlining.

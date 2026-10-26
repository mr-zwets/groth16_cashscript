# review-k34 progress
- worktrees: g34 (pr/34 f8b16b2), b51 (pr/51 157c233). Report only.
- genpow re-export at 8eb2c5d: byte-identical both files
- BN legacy catalog: identical. BN exact-frame 5 vectors: identical ONLY with a cashc emitting DUP SIZE NIP gate (co-8 and upstream 0.14.0 emit SIZE <n> NUMEQUALVERIFY -> cert assert fails). Compiler unpinned: nit.
- BLS-large repair: identical. Finding: input 1 (768B genesis carrier) frozen program also reads its final limb as BIN2NUM(whole remainder); no gate, no owner argument.
- Slim bare-terminal: dropped redeem push unowned; executors read input 4 via reverse offsets (vkx-stages.mjs:46-53). Finding (doc/argument), no credit impact.
- vkx successor catalog: identical. Guards: loader 5901B sha 0c295f.. same construction as native5; bridge field order matches native5 genesis; all 7 programs = guard ++ exact original; new root present in terminal (6 profiles); public slots match original descriptors.
- FINDING b51: bch-bn-exact-frame-corrected.ts EXPECTED_CATALOG_SHA256 abe6e0.. != committed catalog fb6e834c.. -> descriptor throws on import; with seal patched validator gives PASS 52 runs/908 inputs.

# minop-docs (wip/minop-docs) — documentation fixes for our own minop singletons
Base: origin/main 276b74b. CLEANUP-RESULT.md "Our own minop" items 1, 2, 3, 5. Do not merge yet.
- [x] 1 BN gen_singletons.mjs F-limb comment (signedFp, (-p,p)); regenerate; lockingOK sha identical
- [ ] 2 singleton/bn254/README.md Soundness section
- [ ] 3 singleton/bls12-381/README.md minop section rewrite + sizes
- [ ] 5 build_vectors_groth16_minop.mjs:79 layout comment; C:/ paths -> VERIFIER_DIR
  item 1: lockingOK sha256 79835065413a6ba7...a45dd0d9 (50,539 B) identical to bench src/bch/groth16-singleton-minop-vectors.json after regen (cashc dab3f89f, rescheduleStacks)

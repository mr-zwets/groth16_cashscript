# minop-docs (wip/minop-docs) — documentation fixes for our own minop singletons
Base: origin/main 276b74b. CLEANUP-RESULT.md "Our own minop" items 1, 2, 3, 5. Do not merge yet.
- [x] 1 BN gen_singletons.mjs F-limb comment (signedFp, (-p,p)); regenerate; lockingOK sha identical
- [x] 2 singleton/bn254/README.md Soundness section
- [x] 3 singleton/bls12-381/README.md minop section rewrite + sizes
- [ ] 5 build_vectors_groth16_minop.mjs:79 layout comment; C:/ paths -> VERIFIER_DIR
  item 1: lockingOK sha256 79835065413a6ba7...a45dd0d9 (50,539 B) identical to bench src/bch/groth16-singleton-minop-vectors.json after regen (cashc dab3f89f, rescheduleStacks)
  item 2: Soundness section inserted before 'No separate byte-optimized singleton'; also refreshed stale BN minop numbers (64,840,336 op / 72,761,016 worst / 9 inputs / 50,539 B locking / 58,073 B scored, from bench results.json ca18086). Rechecked r|lambda, gcd(N(alpha),h2)=1, r∤h2 in python.
  item 3: minop section rewritten (quotient torus, owner table, verdict, fused psi argument); sizes 58,007/58,841/145,596,803 from bench results.json ca18086. BLS regen byte-identical .cash; lockingOK sha f943ef55...dec52645 identical. BN README op% corrected vs current baseline 771,300,238.

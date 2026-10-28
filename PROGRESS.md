# wip/leftovers (groth16_cashscript)
Base: origin/main be3dc66.
- [x] 1 singleton-fs bound: BLS_QSPLIT_TAIL22_STATUS.md singleton table + bound paragraph, verifiers.md note.
  q_V = 1,104 SHA-256 per spend counted with work/review-bls-fs-singletons-1/tools/trace.mjs on the shipped
  locking (dump redeem == bench lockingOK) and the committed fixture.
- [x] 2 minop psi(B) wording -> psi(B) == [x]B = -[|x|]B (x < 0) in gen_singleton_minop.mjs (header + emitted
  line), groth16_minop.cash (regenerated, byte-identical to the edited file), domain_checks_test.mjs:3,
  groth16.cash:138, groth16_strict.cash:164 (same wrong comment).
  Compiled bytecode sha256 unchanged (cashc dab3f89f): groth16.cash size+resched 788ae845..., size+nosink c3039154...,
  groth16_minop.cash 49b982e4...; groth16_strict.cash does not compile on dab3f89f before or after (pre-existing),
  its comment-stripped source is identical.
  Rebuilt against a scratch copy of bench d01ae89 src/: groth16-bls12381-singleton-minop-vectors.json,
  groth16-bls12381-singleton-vectors.json, -multiproof-vectors.json all byte-identical.
  Left: build_vectors_groth16_minop.mjs:111 description string (it is written into the vector JSON, so changing it
  changes vector bytes); lib/G2Check.cash:4,7 (correct there: it defines x = 0xd201000000010000 = |x|);
  lib/lazy/Bls12381LazyG.cash:33 (library; not in the task list).
  Minop C:/ paths: already fixed on main in 4d49c82 (BN minop scripts use VERIFIER_DIR; BLS minop already did).

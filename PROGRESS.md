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
- [x] 3 C:/ paths in the 13 remaining scripts -> join(VERIFIER_DIR, ...), with
  VERIFIER_DIR = process.env.VERIFIER_DIR ?? <script dir>/../../../zk-verifier-bench/ (sibling checkout;
  ../../../../ for recompiler/outline_spike.mjs). Existing OUT / argv[2] overrides kept. Same env var as the
  minop fix (4d49c82), plus a script-relative default.
  Files: chunked/{rescheduler/census, shamir/build_vectors, twoloop/build_vectors}.mjs,
  singleton/bls12-381/{build_vectors, build_vectors_vkx}.mjs, singleton/bn254/{build_vectors (2 paths),
  build_vectors_vkx, finalexp, finalexp_ref, groth16, miller4, miller_ref, recompiler/outline_spike}.mjs.
  Checks (VERIFIER_DIR = scratch copy of bench d01ae89 src/, cashc dab3f89f): node --check all 13; every
  script run to completion, exit 0 (finalexp/miller4/groth16 PASS, refs true, census/outline print).
  Byte-identical vs bench: pairing-singleton-vectors.json (BN), pairing-bls12381-singleton-vectors.json.
  vkx-singleton, vkx-bls12381-singleton, vkx-chunked, vkx-chunked-shamir differ from bench under this compiler,
  but the HEAD script (path redirected via OUT or sed) writes the same bytes as the new script: the
  difference is pre-existing compiler drift (e.g. vkx BN 879 vs 964 B), not this change.
  Default resolution checked: from the main checkout layout all three depths resolve to
  verifier.cash/zk-verifier-bench/.

## Finalize
- Applied the reviews' non-blocking wording fixes: the sentence split in verifiers.md, "bare as benchmarked" (P2SH32 adds 1 setup and 2 verifier hashes), a clause on the flat affine PIC factors, and fixed-shape loops for q_V.

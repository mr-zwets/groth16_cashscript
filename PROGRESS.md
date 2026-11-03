# PROGRESS — Track 11 (real keys), branch wip/real-keys

- [x] Worktrees (groth16_cashscript, bench) from origin/main; node_modules symlinked to bench main (patched libauth).
- [x] Upstream pins copied to chunked/bn254/real-keys/upstream (SP1 v5 VK, RISC Zero VK + ControlID + test receipts, 3 published SP1 v5 proofs).
- [x] extract.mjs: VKs + fixtures, noble pairing check of every proof against the full upstream statement; RISC Zero constants folded into IC0 (checked both ways).
- [x] math.mjs: BN_VK_FIXTURES env switch (default unchanged: code sha 75c780ae… reproduced).
- [x] build-key.mjs: SP1 v5 (3 proofs) and RISC Zero (1 receipt) accepted, consensus + standard.
- [ ] rejection suite per key
- [ ] covenant binding variant
- [ ] BCHN node check (block + POLICY=1)
- [ ] README / report

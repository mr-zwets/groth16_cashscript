# PROGRESS — Track 11 (real keys), branch wip/real-keys

- [x] Worktrees (groth16_cashscript, bench) from origin/main; node_modules symlinked to bench main (patched libauth).
- [x] Upstream pins copied to chunked/bn254/real-keys/upstream (SP1 v5 VK, RISC Zero VK + ControlID + test receipts, 3 published SP1 v5 proofs).
- [x] extract.mjs: VKs + fixtures, noble pairing check of every proof against the full upstream statement; RISC Zero constants folded into IC0 (checked both ways).
- [x] math.mjs: BN_VK_FIXTURES env switch (default unchanged: code sha 75c780ae… reproduced).
- [x] build-key.mjs: SP1 v5 (3 proofs) and RISC Zero (1 receipt) accepted, consensus + standard.
- [x] rejection suite per key (redteam-key.mjs: 168 / 172 runs, all rejected)
- [x] covenant binding variant (covenant.mjs, covenant-test.mjs; guard r2:covenant)
- [x] BCHN node check (block + POLICY=1): t11a full, t11b timing rerun; 6/6 valid accepted + allowed, 142/142 rejected
- [x] README (chunked/bn254/real-keys/README.md), bench node-check README section

## Fix round (review verdict: pass, 7 minor findings)

- [x] F1 SP1VerifierGroth16.sol re-copied from 512b5e02 (git blob d7f1cf63 matches); fixtures unchanged.
- [x] F2 upstream/SOURCES.md (repo, commit, path, git blob id per file).
- [x] F3 risc0 RiscZeroGroth16Verifier.sol + IRiscZeroVerifier.sol vendored from fe5adc30; extract.mjs text-pins them.
- [x] F4 redteam-core.mjs 10b: false statement with digits/t/states recomputed -> input 2 rejected at r2:cleanup (169 / 173 runs, 0 accepted).
- [x] F5 covenant-test: covenant pinned to another programVKey / image id -> r2:covenant (12/12, 10/10).
- [x] F6 build JSON `deployment` field + README table label (plain builds: verifier core, not deployable).
- [x] F7 bench node-check README: mempool verdicts of rejections attributed to the timing node; BCHN re-run t11c.

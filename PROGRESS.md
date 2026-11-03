# PROGRESS — Track 12 (program-pinned covenant template), branch wip/pinned-template

- [x] Worktrees (groth16_cashscript, zk-verifier-bench) from origin/main; node_modules symlinked to bench main (patched libauth).
- [ ] Real SP1 v5 / RISC Zero proving: BLOCKED. Installing sp1up / rzup (external toolchains) was denied by the
      permission system in this session. Guest + host sources are in chunked/bn254/pinned/guest (NOT compiled).
      Needs a user decision: allow the toolchain installs (and docker for SP1's gnark wrap), then follow the README section "Producing real proofs".
- [x] pv.mjs (PV layout = tx outputs), template.mjs (on-chain PV rebuild + statement via the Track 11 hook), pinned.mjs (library + tx builder), example.mjs (CLI), keys.mjs
- [x] risc0-v3 key: released control root a54dc85a (risc0 3.0.x / risc0-ethereum v3.0.1), fold-risc0.mjs, upstream/SOURCES.md
- [x] pinned-test.mjs: test key 76 runs (6 accept, 70 reject); sp1-v5 10, risc0 4, risc0-v3 4 (real proofs: rejections + plain-core re-randomized controls)
- [x] covenant-cost.mjs: template block SP1 +133 B / +10.1k op, RISC Zero +315 B / +12.7k op (2 outputs)
- [x] BCHN node-check t12a, t12b (fresh nodes, stopped): 92/92 as expected, BCHN = libauth, 9/9 valid allowed (POLICY=1)
- [x] README (chunked/bn254/pinned/README.md), bench node-check README section
- [x] Two internal reviews (A: pass, 4 minors; B: fix, 3 majors + 5 minors). Fix round (a7edd02 + README):
      on-chain self-payment guard; spendability caps (n <= 96, |PV| <= 9,900, n x |PV| <= 300,000, measured);
      example CLI takes program id / INSTANCE from arguments, regtest-only example values, bchtest default prefix;
      pinned.mjs preflight (caps, dust, self-payment, 1 sat/B fee floor) + libauth verify in buildSpend; key opt-ins
      for 'test' / 'risc0'; README fee / replay / change / txid / token-burn corrections; tests assert sections and
      opcodes, add self-payment + mixing runs (test key 92 runs: 6 accept, 86 reject). BCHN t12c: 108/108 as expected.
- [ ] Independent (external) review of the template (not done)

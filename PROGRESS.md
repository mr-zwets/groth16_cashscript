# PROGRESS (wip/plonk-usable-bsb22; stays on this branch, never main)

Track 7, task BSB22 commitments.

- [x] protocol delta from gnark v0.16.4 verify.go written down (prover/PROTOCOL.md section "BSB22")
- [x] prover: range64 + merkle16rc circuits (std/rangecheck, exactly one commitment), vectors v2-bsb22
- [x] verify.mjs: commitments; 351 cases OK, hash-to-field cross-checked against gnark's on every valid proof
- [x] CashVM single input (plonk.mjs, script.mjs): merkle16rc spec + 100 KB, range64 spec, all tests pass
- [x] chain (multi.mjs) ported; logic OK on the relaxed VM; does NOT fit 100,000 B (103.7 KB best, 11 inputs)
- [x] SOUNDNESS.md scope (+ section 8), line refs updated
- [ ] not done: m >= 2 tests, GT folding, a 2-tx chain, summary.json regeneration

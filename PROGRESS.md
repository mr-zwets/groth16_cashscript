# PROGRESS (wip/plonk-usable-bsb22; stays on this branch, never main)

Track 7, task BSB22 commitments.

- [x] protocol delta from gnark v0.16.4 verify.go written down (prover/PROTOCOL.md section "BSB22")
- [x] prover: range64 + merkle16rc circuits (std/rangecheck, exactly one commitment), vectors v2-bsb22
- [x] verify.mjs: commitments; 351 cases OK, hash-to-field cross-checked against gnark's on every valid proof
- [ ] CashVM single input (plonk.mjs, script.mjs)
- [ ] chain (multi.mjs) if feasible
- [ ] SOUNDNESS.md scope

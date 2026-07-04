# Op-cost stack rescheduler for chunk redeems

**Now a compiler pass**: the scheduler is ported into the cashc fork as the opt-in
`rescheduleStacks` compiler option (`packages/cashc/src/stack-rescheduling.ts`, fork
commit 230b2c7 on `compiler-optimizations`), and the `RESCHEDULE=opcost` builder hook in
`_millermath.mjs` routes to it. `opcost.mjs` here is the original standalone
implementation, kept as the reference the port was byte-for-byte validated against
(millerres/g2check/finalexpres redeems compile identically both ways). The in-compiler
version additionally fixes an opcode-table bug the standalone had (`0xa3` is OP_MIN, not
OP_WITHIN), which unlocks rescheduling of the GLV vk_x mains (`min()` users) that the
standalone silently fell back on — worth another ~1.2K bytes / ~2.5M op on the flagship.

An op-cost-objective rescheduling pass over compiled chunk bytecode, built on the
byte-objective singleton recompiler (`singleton/bn254/recompiler/`). It re-derives each
routine's evaluation schedule from its dataflow DAG so operands are on top of the stack
when needed, eliminating `<depth> OP_PICK/OP_ROLL` fetch pairs — but selects candidate
schedules by the BCH2026 op-cost meter (100/instruction + pushed bytes) instead of
serialized bytes. On op-cost-bound chunks, 800 op-cost saved = 1 byte of zero-padding
removed from the unlocking.

## How it works

1. `dissect` the redeem into its `OP_DEFINE` subroutine table + main routine
   (recompiler.mjs, unchanged).
2. Subroutine bodies: candidates `{cashc, topo, greedy, opcost}` are **measured on the
   loosened VM** with fixed pseudo-random inputs (`recompileAllOpcost`); the cheapest
   diff-test-equivalent variant wins. The `opcost` strategy is a greedy DAG scheduler
   whose fetch-cost heuristic uses the real meter weights (schedule.mjs `fetchCostOp`).
3. Main routine: candidates ranked by a static op-cost estimate (`opCostEstimate`) —
   chunk mains are straight-line and execute once, so the static rank tracks the meter
   up to a nominal item-length approximation.
4. Per-body and per-block, the pass keeps `min(cashc, rescheduled)`, so it is never
   worse than the compiler on any block.

Correctness: bodies are differentially tested on random inputs; whole redeems are
validated by the vector builders, which evaluate every chunk in its real transaction
context (accept the valid proof, reject the tampered one) and recompute all
P2SH/link/padding bindings from the final redeem bytes.

## Integration

Opt-in via `RESCHEDULE=opcost` on any builder that compiles through
`chunked/pairing/_millermath.mjs` (`compileBytecode` / `compileFileBytecode`); default
off, so every build stays A/B-able:

    RESCHEDULE=opcost node chunked/grouped/build_vectors_residue.mjs

The four intratx/grouped builders additionally do **per-chunk variant selection**: the
first assembly measures both the rescheduled and the plain-cashc redeem in context and
keeps whichever yields the smaller *tuned* unlocking (op-bound chunks favor the
rescheduled redeem; small arg+redeem-bound chunks favor the byte-smaller cashc one).
The choice is cached on first assembly so all proof instances share identical lockings.

## Measured results (2026-07-04, committed-proof runs)

| family | total op-cost | total bytes |
|---|---|---|
| groth16-grouped-residue | 195,408,679 → 186,657,613 (−4.5%) | 256,199 → 244,525 (−11,674) |
| groth16-intratx-residue | 195,449,911 → 186,699,552 (−4.5%) | 256,257 → 244,587 (−11,670) |
| groth16-grouped | 317,635,048 → 300,371,946 (−5.4%) | 403,213 → 383,150 (−20,063) |
| groth16-intratx | 317,733,399 → 300,464,156 (−5.4%) | 403,372 → 383,302 (−20,070) |
| pairing-intratx | 178,683,572 → 172,568,816 (−3.4%) | 225,600 → 217,993 (−7,607) |
| pairing-chunked (covenant) | 178,818,871 → 172,708,051 (−3.4%) | — |
| groth16-chunked (covenant) | 316,623,099 → 300,532,106 (−5.1%) | — |
| vkx-chunked-covenant | 11,631,314 → 7,984,710 (−31.4%) | — |

All families: `allAccept=true`, `allFit=true`, tampered runs rejected, on the committed
proof, proof#1, and the worst-case proof. The byte-objective singleton recompile is
unaffected (locking still 8,385 B, accept/reject intact).

Benchmark scores (verifier `npm run benchmark:json`, final vectors built through the
in-compiler pass; grouped-residue committed run totalOp 195,408,679 → 184,122,002,
−5.8%):

| entry | before | after | Δ |
|---|---:|---:|---:|
| bch-groth16-grouped-residue | 257,810 | 244,918 | −5.0% |
| bch-groth16-intratx-residue | 257,696 | 244,808 | −5.0% |
| bch-groth16-grouped | 405,813 | 385,547 | −5.0% |
| bch-groth16-intratx | 405,542 | 385,270 | −5.0% |
| bch-groth16-chunked | 407,968 | 388,498 | −4.8% |
| bch-pairing-chunked | 228,811 | 221,181 | −3.3% |
| bch-pairing-intratx | 226,652 | 219,045 | −3.4% |
| bch-vkx-chunked-covenant | 17,695 | 13,967 | −21.1% |

This more than recovers the +1.3–2.3% op-cost regression the BN254 chunked families
took in the cashc-next alignment (see `cashc-next-op-regression.md`).

Out of scope (mechanical follow-ups): BLS12-381 families, the shamir vk_x build (own
compile path, not hooked), porting the scheduler into cashc as a backend.

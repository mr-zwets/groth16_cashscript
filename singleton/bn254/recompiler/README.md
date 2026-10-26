# recompiler/ — opcode-optimizing stack-scheduler for the BN254 singleton

A post-pass over the cashc-compiled `../groth16.cash` that re-emits the bytecode with a
better stack schedule, then outlines repeated instruction sequences into `OP_DEFINE`
bodies. Semantics are unchanged — scheduling only changes *how operands are moved on the
stack*, outlining is byte-exact factoring — and together they cut the locking bytecode
**7,953 → 5,878 B (−26%)** (scheduling 7,953 → 7,539, outlining 7,539 → 5,878), far
under BCH's 10,000-byte standard script-size cap. Numbers are for cashc
compiler-optimizations-8 with the coordinate range checks (2026-10-26); the 7,953 B input
is the `disableDefSinking` compile (the plain `bch-groth16-singleton` entry ships the
`rescheduleStacks` compile, 7,847 B). Against an older cashc the same pass took
14,131 → 6,314 B; cashc has since absorbed much of the scheduling gain. Op-cost
(771.3M plain → 800.2M optimized, committed proof) grows slightly from the outline call
overhead; the win is purely byte size, which is what this entry is scored on.

## Why there's room

cashc keeps each variable at a fixed stack home and, on reassignment inside a loop/branch,
bubbles the new value back to that home with an altstack park/restore (`emitReplace`). In
the Miller loop alone that is ~2,150 `OP_TOALTSTACK`/`OP_FROMALTSTACK`. Across the verifier,
~85% of the bytes in control-flow bodies are stack shuffling. This pass eliminates the
park/restore by consuming values in place and addressing operands directly.

## Pipeline

| file | role |
|------|------|
| `asm.mjs` | byte-level (dis)assembler; `parse`/`serialize` round-trip byte-identically |
| `decompile.mjs` | split a subroutine into straight-line blocks at IF/BEGIN/UNTIL boundaries; recover each block's value-DAG; preserve the main+alt stack layout at every boundary so blocks recompose |
| `schedule.mjs` | re-emit each block with a use-count greedy scheduler (ROLL last-use in place, PICK copies, deepest-occurrence move for repeated operands), altstack-passthrough, 1-byte shallow ops, and a multi-item-op peephole (`OVER OVER`→`2DUP`, `<3>PICK<3>PICK`→`2OVER`, `<3>ROLL<3>ROLL`→`2SWAP`, `<5>ROLL<5>ROLL`→`2ROT`) |
| `recompiler.mjs` | dissect the locking bytecode into the OP_DEFINE table; probe each subroutine's arity; recompile every body keeping the smallest of {cashc, topo, greedy} that is **differential-tested equivalent** to the original on the loosened BCH-2026 VM; reassemble; full-verify |
| `outline.mjs` | byte-exact auto-outlining: factor repeated instruction subsequences (balanced control flow, no BEGIN/UNTIL/OP_DEFINE/OP_ACTIVEBYTECODE) into new `OP_DEFINE` bodies, greedy per pass, iterated to a fixpoint; every rewrite batch is verified accept-valid/reject-tampered, with per-rewrite isolation on failure. Also used by the BLS12-381 opcode-optimized build (`singleton/bls12-381/build_vectors_optimized.mjs`, where the whole recompiler proved curve-agnostic: only the diff-test input range is parameterized via `setTestInputRange`) |
| `outline_spike.mjs` | the roadmap item 6/7 measurement spike the pass grew from: depth-layout census + 16-hot greedy oracle (lever closed) and the original outlining scan |
| `build_vectors_optimized.mjs` | the runnable: compile groth16.cash → recompile → outline → write the verifier benchmark vectors |

## Reproduce

```
node singleton/bn254/recompiler/build_vectors_optimized.mjs
```

Compiles `../groth16.cash`, recompiles it, re-validates against the committed proof
witnesses (the runtime interface is identical, so the same unlocking witnesses apply), and
writes:

- `zk-verifier-bench/src/bch/groth16-singleton-opcode-optimized-vectors.json`
- `zk-verifier-bench/src/bch/groth16-singleton-opcode-optimized-multiproof-vectors.json`

(`zk-verifier-bench` is the sibling checkout by default; override with `BENCH_DIR`.) Run
`../build_vectors_groth16.mjs` and the bench's `pnpm gen:multiproof` first: this build reads
the plain entry's unlocking witnesses and `rangeInvalid` cases from
`groth16-singleton-vectors.json`.

Benchmark entry: `bch-groth16-singleton-opcode-optimized`
(`zk-verifier-bench/src/implementations/bch-groth16-singleton-opcode-optimized.ts`).

## Correctness

Every rewritten subroutine is differential-tested against the cashc original on random
inputs (`recompiler.mjs` `bodyEquiv`), and the full contract is checked accept-valid /
reject-tampered plus all distinct multiproofs and zero-input proofs before any vectors are
written. The `asm.mjs` parser/serializer round-trips the original bytecode byte-for-byte.

Random in-range inputs never make a `require()` fail, so the differential test cannot see
a dropped check, and the main routine (which holds the input-validation requires) is only
validated end to end. Two guards cover that:

- `decompile.mjs` records calls to zero-output bodies (functions that only `require()`)
  as block roots (`block.effects`), so the scheduler keeps them. Before this fix they had
  no consumers and were silently dropped, which removed `fpRange(v)` from the main routine.
- the build re-runs the 18 non-canonical coordinate cases (`../range_cases.mjs`, shipped
  as `rangeInvalid`) against the optimized artifact and fails if any is accepted.
  `node singleton/bn254/range_checks_test.mjs <vectors.json>` runs them standalone.

The converse case, a require-only body whose require fails on random inputs (an on-curve
check such as the BLS12-381 `g1Check`), has no measurable arity: it errors for every probed
input count. `probeArity` throws `ArityProbeError` for such a body instead of returning a
made-up 31 -> 31 signature. The BLS12-381 opt builder catches it and skips its golf
candidate. The rescheduled compile (candidate B) already won there, so the artifact is
unchanged.

## Scope / floor

After this pass, ~54% of the remaining bytes are `ROLL`/`PICK` addressing (the depth-arg
push + the opcode) and ~25% is irreducible constant data. The remaining lever is
register-allocation-style layout (keep the ≤16 hottest values shallow, spill cold ones to
the altstack), which is bounded because the Miller working set is 25 > 16 live values. See
`../../../archive/cashc-stack-optimization.md` for the full floor analysis and the upstream cashc
improvement proposal.

# recompiler/ — opcode-optimizing stack-scheduler for the BN254 singleton

A post-pass over the cashc-compiled `../groth16.cash` that re-emits the bytecode with a
better stack schedule. Semantics are unchanged — it only changes *how operands are moved
on the stack* — but it cuts the locking bytecode **14,641 → ~9,675 B (~34%)**, which drops
under BCH's 10,000-byte standard script-size cap. Op-cost (~750M) is essentially unchanged;
the win is purely byte size.

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
| `build_vectors_optimized.mjs` | the runnable: compile groth16.cash → recompile → write the verifier benchmark vectors |

## Reproduce

```
node singleton/bn254/recompiler/build_vectors_optimized.mjs
```

Compiles `../groth16.cash`, recompiles it, re-validates against the committed proof
witnesses (the runtime interface is identical, so the same unlocking witnesses apply), and
writes:

- `verifier/src/bch/groth16-singleton-opcode-optimized-vectors.json`
- `verifier/src/bch/groth16-singleton-opcode-optimized-multiproof-vectors.json`

Benchmark entry: `bch-groth16-singleton-opcode-optimized`
(`verifier/src/implementations/bch-groth16-singleton-opcode-optimized.ts`).

## Correctness

Every rewritten subroutine is differential-tested against the cashc original on random
inputs (`recompiler.mjs` `bodyEquiv`), and the full contract is checked accept-valid /
reject-tampered plus all distinct multiproofs before any vectors are written. The
`asm.mjs` parser/serializer round-trips the original bytecode byte-for-byte.

## Scope / floor

After this pass, ~54% of the remaining bytes are `ROLL`/`PICK` addressing (the depth-arg
push + the opcode) and ~25% is irreducible constant data. The remaining lever is
register-allocation-style layout (keep the ≤16 hottest values shallow, spill cold ones to
the altstack), which is bounded because the Miller working set is 25 > 16 live values. See
`../../../cashc-stack-optimization.md` for the full floor analysis and the upstream cashc
improvement proposal.

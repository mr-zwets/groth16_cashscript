# The `rescheduleStacks` Compile Mode

The verifiers in this repo are compiled with a stack-rescheduling pass in the
[CashScript compiler fork](cashscript-compiler-fork.md) (branch
`compiler-optimizations`). This is the single biggest codegen lever in the project: on
the op-cost-bound chunk families it is worth **−4.9 % to −6.7 %** of the whole verifier
score, and on the plain BN254 singleton **−37.7 %** of bytecode. This doc explains what
the mode is, how it works, and how to turn it on.

It is the *landed* form of the rescheduling win first prototyped as the external `golf/`
recompiler and diagnosed in [cashc-stack-optimization.md](cashc-stack-optimization.md);
that doc is the *why* (the structural inefficiency in stock cashc codegen), this doc is
the *what* (the compiler pass that fixes it). The chunk-build wiring and the
per-family result table live in
[chunked/rescheduler/README.md](chunked/rescheduler/README.md).

## The two knobs

Two independent compiler options govern this mode:

- **`optimizeFor: 'size' | 'opcost'`** — the optimisation *objective*. Exposed on the
  CLI as `-O, --optimize-for <target>` (default `opcost`). It is a global setting that
  several passes read: it flips the inlining threshold, gates constant-hoisting and
  definition-sinking (both `'size'`-only), chooses whether function-exit cleanup lowers
  to the altstack, and — crucially here — decides how `rescheduleStacks` *ranks*
  candidate schedules.
- **`rescheduleStacks: boolean`** — turns the DAG rescheduling pass on. **API-only**
  (there is no CLI flag): the build harnesses pass it in the `compileString` options.
  It is opt-in because it is restricted to **single-function contracts** — with a
  function selector the entry stack depth differs per spend path, which the block model
  below does not represent. Every verifier contract in this repo has exactly one
  `spend()` function, so the restriction is a no-op here.

The two compose: `rescheduleStacks: true` with `optimizeFor: 'opcost'` (the default
objective) is what the chunk and minop builds use; the size-scored singleton recompile
uses `optimizeFor: 'size'`.

## Why a rescheduler at all

Stock cashc pins every variable to a fixed stack "home" slot and fetches each read with
a `<depth> OP_PICK` / `<depth> OP_ROLL` pair, bubbling reassigned values back to their
home with `OP_TOALTSTACK … OP_FROMALTSTACK` parking. On a pairing verifier — which
carries a deep working set (the Miller loop alone holds ~25 live values: `F[12] + R[6] +
Q[4] + P[2] + counter`) and reassigns 12-wide `Fp12` accumulators every iteration — this
stack-shuffling *dominates* the bytecode: 82–87 % of the bytes in loop/branch bodies are
shuffle, not math. [cashc-stack-optimization.md](cashc-stack-optimization.md) measures
and dissects this in full.

## How the pass works

The pass (`packages/cashc/src/stack-rescheduling.ts` in the fork) operates on cashc's
*already-emitted, already-optimised* bytecode — it runs after the legacy peephole
optimiser, not on the AST.

1. **Split into basic blocks.** The compiled script is cut at every control opcode
   (`IF`/`ELSE`/`ENDIF`, `BEGIN`/`UNTIL`) and every side-effecting check
   (`VERIFY`-family, `CLTV`/`CSV`). The control opcodes themselves are kept verbatim and
   in order.
2. **Lift each block to a dataflow DAG** over its opaque entry stack slots. A block reads
   some entry items, computes, and leaves some exit items; the DAG captures the true
   data dependencies, discarding cashc's fixed-home addressing.
3. **Re-emit with a scheduler** that walks the DAG in dependency order, and for each
   operand chooses the cheapest way to make it available on top: a consuming move
   (`SWAP`/`ROT`/`ROLL`), a copy (`DUP`/`OVER`/`PICK`), or re-pushing a constant.
4. **Keep `min(original, rescheduled)` per block.** Because every block reproduces its
   exact entry→exit stack layout, blocks compose and the transform is
   semantics-preserving by construction; and since a block is only replaced when the new
   schedule is smaller/cheaper, **no block ever regresses**.

### Entry-layout search

For each `OP_DEFINE`'d function the pass *also* chooses the stack **order in which its
arguments arrive**, jointly with the schedule (the optimal order depends on the schedule
and vice versa), using a small beam search over node orders. Call sites already stage
arguments explicitly, so a permuted calling convention costs nothing extra at the call —
every caller is re-emitted to stage arguments in the callee's chosen order. If any
validation fails, the pass falls back to identity layouts wholesale.

### Validation

`OP_DEFINE`'d function bodies are differentially tested on a loosened VM (random input
vectors; the rescheduled body must reproduce the original body's output stack), and
under `'opcost'` they are ranked by **measured** op-cost rather than the static
estimate. The main routine cannot be executed standalone (it reads transaction context),
so it relies on the per-block structural guarantee plus static ranking.

## How the objective changes ranking

- **`'size'`** — candidate schedules are ranked by serialized bytes.
- **`'opcost'`** — ranked by the BCH2026 op-cost meter: 100 per evaluated instruction
  plus the bytes it pushes. `SWAP`/`ROT` push 0; a copy pushes the item; `ROLL` pushes
  item + depth. So, e.g., **re-pushing a 32-byte constant (~132) beats `PICK`ing a
  stashed copy (~234)** — the opposite of the size-optimal choice. This is the right
  objective for op-bound contracts whose unlocking scripts are zero-padded to buy op
  budget: there, **800 op-cost saved = 1 byte of zero-padding removed** from the
  unlocking.

## Invoking it

```js
import { compileString } from 'cashc';

// op-cost objective (default) + rescheduling — the chunk/minop builds
const artifact = compileString(src, { rescheduleStacks: true });

// size objective + rescheduling — the size-scored singleton
const artifact = compileString(src, { rescheduleStacks: true, optimizeFor: 'size' });
```

In this repo, rescheduling is **ON by default** in the chunk builders'
`compileBytecode` / `compileFileBytecode` helpers (see
[chunked/rescheduler/README.md](chunked/rescheduler/README.md)); `RESCHEDULE=off`
compiles plain for A/B comparison, and the `compile*Raw` exports always compile plain
(the vector builders keep, per chunk, whichever redeem yields the smaller tuned
unlocking, and the chunk planners use the raw path so generated manifests stay
independent of the pass).

## What it buys (committed-proof benchmark)

| entry | before | after | Δ |
|---|---:|---:|---:|
| bch-groth16-grouped-residue | 257,810 | 241,628 | −6.3 % |
| bch-groth16-grouped | 405,813 | 378,538 | −6.7 % |
| bch-groth16-chunked | 407,968 | 381,549 | −6.5 % |
| bch-pairing-chunked | 228,811 | 217,562 | −4.9 % |
| bch-vkx-chunked-covenant | 17,695 | 13,950 | −21.2 % |
| bch-groth16-singleton (size-scored) | 14,240 | 8,874 | −37.7 % |

Flagship total op-cost 195.4M → 181.5M (−7.1 %); the non-residue grouped verifier packs
into 5 standard transactions instead of 6. Full per-family table, validation status, and
the census of what rescheduling *cannot* recover (intrinsic arithmetic, seam/boundary
overhead) are in [chunked/rescheduler/README.md](chunked/rescheduler/README.md).

Currently ported to the BN254 families and the plain singleton; **not yet** applied to
the BLS12-381 chunk families or the shamir `vk_x` build (own compile path).

## Related docs

- [cashc-stack-optimization.md](cashc-stack-optimization.md) — the diagnosis and the
  `golf/` prototype the pass was ported from, plus the analysis of the *floor* that
  remains after rescheduling (stack-addressing tax, the case for VM-level addressable
  locals).
- [chunked/rescheduler/README.md](chunked/rescheduler/README.md) — chunk-build wiring,
  `census.mjs` / `opcost.mjs`, and the full result table.
- [The CashScript Compiler Fork](cashscript-compiler-fork.md) — the rest of the fork's
  feature set and the `optimizeFor` objective in context.

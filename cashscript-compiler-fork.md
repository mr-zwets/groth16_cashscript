# The CashScript Compiler Fork

The verifiers in this repo are compiled with a fork of `cashc`:
[`mr-zwets/cashscript`](https://github.com/mr-zwets/cashscript), branch
`compiler-optimizations-5`, eight commits on top of upstream `next` at v0.14.0-next.5.
`node_modules/cashc` in this repo links to that checkout; rebuild with `yarn build` in
`packages/utils` and `packages/cashc` after any compiler edit. The graders and
`_harness.mjs` call `packages/cashc/dist/cashc-cli.js`.

## Why not stock cashc

CashScript v0.14 has every language feature the verifier needs (see the
[README](README.md#why-a-cashscript-fork)). What it does not have is a cost model for
contracts of this size. A pairing verifier runs thousands of field operations per input,
and on BCH both bytes and executed operations are consensus-limited per input: the
unlocking script is capped at 10,000 bytes and buys `(41 + length) * 800` op-cost. Stock
`cashc` has one objective, bytes. The fork adds a second objective and one large
scheduling pass, both of which only matter once a contract is big enough that stack
traffic and per-iteration stepping dominate.

They are experimental. The objective changes are small and local; the rescheduler is a
new backend pass with its own correctness argument and test rig. Neither has been
proposed upstream yet; the intent is to do so once they are better understood, and to
eventually compile with stock CashScript.

## What the fork adds

### The `optimizeFor` objective

`optimizeFor: 'size' | 'opcost'` (CLI `-O, --optimize-for`, default `opcost`) selects
what codegen decisions trade against. Passes that read it:

- **Inlining.** Upstream inlines a function wherever that is cheaper by exact byte
  accounting. Under `opcost`, bodies of at most 6 bytes inline regardless of use count
  (each call site saves the ~200 op-cost invoke overhead), unless their call sites are
  spread across contract entry functions, where an inlined body in an untaken branch
  would be stepped for nothing. Under `size`, a byte tie keeps the function defined.
- **Loop-resident functions stay `OP_DEFINE`'d.** The VM charges every opcode inside a
  loop on every iteration, including untaken branches, so an inlined body costs its
  full length per iteration while an invoke site costs two ops. Functions called inside
  a loop (directly or through their callees) are excluded from inlining; a `for`-init
  call runs once and is not loop-resident.
- **Constant hoisting** (`size` only). Repeated in-body literals such as the field prime
  are bound to a local, so later uses are 2-byte stack picks. Literal-sensitive
  positions (split and slice bounds, `toPaddedBytes` sizes, `.length == N` comparisons,
  console arguments) are never hoisted, and the hoisted compile is kept only when it is
  strictly smaller.
- **Definition sinking** (`size` only). Definitions move down to just before their first
  use, so values sit near the top of the stack and accesses get shallower. Both variants
  are compiled and the smaller one kept. Sinking can change which `require` fails first
  on an invalid witness, never whether a spend is accepted; definitions count as
  assignments in the reorder analysis so a use-before-definition program cannot be
  reordered into a valid one.
- **Right-to-left argument staging.** User-function call sites push arguments so the
  first parameter arrives on top of the stack, which is the common access pattern in the
  tower code. Upstream showed this is a mirror image of the current convention (reversing
  a parameter list gives byte-identical output), so it stays in the fork only because
  the contract sources are written for it.

The byte-scored singletons compile with `optimizeFor: 'size'`; the chunk and `minop`
builds use the `opcost` default.

### `rescheduleStacks`

An opt-in pass (`packages/cashc/src/stack-rescheduling.ts`) that lifts each
straight-line block of the compiled script to a dataflow DAG and re-emits it so operands
are computed onto the top of the stack instead of fetched from variable slots with
`<depth> OP_PICK` / `OP_ROLL`. It also chooses each `OP_DEFINE`'d function's
argument-arrival order jointly with its schedule. Candidate schedules are ranked by the
`optimizeFor` objective, per block the compiler keeps `min(original, rescheduled)`, and
the pass is restricted to single-function contracts. Worth −4.9 % to −6.7 % of the whole
score on the op-bound chunk families and −37.7 % on the plain BN254 singleton.

This is the risky part of the fork. Its safety rests on a per-block structural guarantee
(exact entry-to-exit stack layout, boundaries kept verbatim), fail-closed fallbacks to
the plain compile on any unexpected condition, never eliminating dead computation (a
node unreachable from a block's exit can only reject a spend), and differential tests of
function bodies on a loosened BCH2026 VM. Rescheduling compiles are slow (about a minute
for the BN254 singleton). Read [The `rescheduleStacks` Compile Mode](rescheduling-stacks.md)
before relying on it; the chunk-build wiring and result table are in
[chunked/rescheduler/README.md](chunked/rescheduler/README.md), and the pre-landing
diagnosis of why stock codegen wastes these bytes is in
[cashc-stack-optimization.md](cashc-stack-optimization.md).

## What used to be in the fork

Earlier fork branches carried language features that upstream has since landed, and
the contracts were converted to the upstream forms as they arrived:

- user-defined functions, `import`, dead-code elimination, multi-return functions
  (#423), global constants and byte-accounted inlining (#426): the first fork
  (`feat/library-support`, from v0.13.1) had its own `library` / `internal function`
  front-end for these;
- the `unused` modifier (#425), tuple reassignment (#436), the exact inlining byte model
  and the faster peephole optimiser (#441): carried by `compiler-optimizations` and
  `compiler-optimizations-2` until v0.14.0-next.4/5 absorbed them.

Recompiling the converted singletons after the first switch to upstream functions
(2026-07-02) shrank all 28 contracts by 2.1 % in total and the full BN254 verifier by
1.5 %; the move to `compiler-optimizations-2` (2026-07-23) improved the byte-scored
singletons a further 1–4 % while trading some op-cost back under the size objective, and
regressed a few op-bound chunk builds (shamir vk_x +12 % op; the BN254 grouped-residue
plan overflows its per-input caps and awaits replanning).

## Branch history and pins

| branch | base | status |
| --- | --- | --- |
| `feat/library-support` | v0.13.1 | retired; custom `library` front-end |
| `compiler-optimizations` | next.0 (`1c707c1`) | retired; still needed to reproduce kallisti's BLS `run_full_multiproof.mjs` build |
| `compiler-optimizations-2` | next.2 (`9fb1483`) | the compiler the committed verifier artifacts were last built with |
| `compiler-optimizations-3` / `-4` | next.3 / next.4 | review references for the upstream discussion |
| `compiler-optimizations-5` | next.5 | current |

`compiler-optimizations-5` reproduces the `9fb1483` singleton templates byte-for-byte
(BN254 and BLS12-381 `groth16`, `verify`, `minop`) except the `vkx` contracts, where
upstream now drops an `unused` parameter at function entry rather than at the
end-of-scope cleanup (+2 bytes unrescheduled, −2 rescheduled). The artifacts are not yet
recompiled under it.

# The CashScript Compiler Fork

The verifiers in this repo are compiled with a **local fork of `cashc`**, not the
released compiler. The fork adds the language features the Groth16 field tower could
not be written (or organised) without:

- **reusable (user-defined) functions** — the central enabler (§1),
- **multi-return functions** (§2),
- a multi-file **library / import** system with **global constants** and
  **tree-shaking** (§3),
- an **`unused` declaration modifier** for op-cost padding (§4),

plus a codegen bug fix (§5) and a compile-speed optimisation (§6) that the generated
pairing chunks need in order to build in reasonable time.

These are the features the README used to list as the *"No Reusable Functions"*,
*"No Library Support"* and *"No Global Variable Support"* CashScript shortcomings.
They are no longer shortcomings for this project: we built them.

- **Fork:** `C:\Users\mathi\Desktop\cashscript`, branch `feat/library-support`
  (forked from CashScript v0.13.1).
- **CLI used by the graders and `_harness.mjs`:** `packages/cashc/dist/cashc-cli.js`,
  rebuilt with `yarn build` in `packages/cashc` after any compiler edit.
- **Status:** local-only, not yet upstreamed. The full `cashc` suite is green except
  one pre-existing, unrelated failure on the branch (`test/ast/Location.test.ts`).

## 1. Reusable functions (issue [#369](https://github.com/CashScript/cashscript/issues/369))

Stock CashScript only allows calling built-in functions: you cannot define your own
function and call it from a contract function or from another function. The fork adds
user-defined function definition and invocation, compiled to `OP_DEFINE` / `OP_INVOKE`.

This is the central enabler for the whole verifier. The BN254 field tower
(`Fp2 → Fp6 → Fp12`), the G1/G2 point operations, and the Miller / final-exponentiation
steps are each **defined once and invoked**, so the loop body (and, in the chunked
deployment, the per-chunk bytecode) is compiled once rather than inlined N times. The
real source (`singleton/bn254/*.cash`, `chunked/`) relies on this everywhere; without
it the verifier would not fit BCH's bytecode limits.

## 2. Multi-return functions

A user function can return a tuple of values (commit *"add multi-return to functions"*),
e.g. `function mulFp2(...) returns (int, int)` or `mulFp12(...) returns (int, int, ...)`.

This is required because CashScript has no array or struct type, so each tower element
is carried as separate ints: an `Fp2` value is 2 ints, `Fp6` is 6, `Fp12` is 12. Every
tower operation therefore takes and returns its components as a flat list of ints, which
is only expressible with multi-return functions.

## 3. Libraries, imports, and global constants (issues [#153](https://github.com/CashScript/cashscript/issues/153), [#264](https://github.com/CashScript/cashscript/issues/264))

Stock CashScript has no multi-file construct: no `library`, no `import`, and no
top-level `constant`. Every `.cash` file had to re-declare the slice of the field
tower it used, with the field prime and other constants pasted in by hand. The fork
adds all three:

- **`library Name { ... }`** — a file-level bag of reusable functions and
  `constant`s. A library has no spending function, so its member functions are
  implicitly `internal`, compiled to the same `OP_DEFINE` / `OP_INVOKE` backend as the
  reusable functions of §1.
- **`import "./Rel.cash";`** — pulls another file's libraries and constants into scope
  **unqualified** (call `addFp(...)` directly, not `Fp.addFp`). Imports form a
  dependency graph: `lib/Fp2.cash` imports `lib/Fp.cash`, a consumer imports
  `lib/Fp2.cash`, and the resulting diamond is de-duplicated; import cycles are
  rejected.
- **`int constant P = <const-expr>;`** — a global constant, valid at file top level or
  inside a library. It is folded to a literal and **inlined at every use site** (no
  stack slot), so the BN254 prime has a single source of truth instead of being
  copy-pasted as a 32-byte literal into every function.

**Resolution runs *before* any AST-visitor pass.** `resolveDependencies` merges the
imported libraries (in dependency order) and inlines the constants, producing a plain
single-contract AST — so the symbol-table, type-check and codegen stages are unchanged.
The whole library system is a front-end addition.

**Tree-shaking.** Codegen only `OP_DEFINE`s functions transitively reachable from a
spending function (a BFS over the call graph), so importing a large shared library costs
nothing for the functions a given consumer never calls. This is what lets one shared
tower back many different consumers and still compile each to minimal bytecode:
`singleton/bn254/fp2.cash` is a three-line consumer that `import`s `lib/Fp2.cash`
(→ `lib/Fp.cash`) yet compiles **byte-identical** to the old hand-inlined `fp2.cash`,
because the unreachable tower functions are shaken out.

Both the BN254 and BLS12-381 singletons were migrated to this layout: a shared
`singleton/<curve>/lib/` tower (`Fp → Fp2 → Fp6 → Fp12`, plus `Miller`, `FinalExp`,
and for BN254 `G1`), with every `*.cash` reduced to a thin `import` + `spend()`
consumer (see each `lib/README.md`). 27 singleton contracts use `import` today.

Not yet supported (so still divergent from the upstream proposals): selective
`import { x } from "..."`, qualified `Lib.fn(...)` calls, and constants declared
*inside* a `contract` (top-level and in-`library` only).

## 4. The `unused` declaration modifier (issues [#125](https://github.com/CashScript/cashscript/issues/125), [#412](https://github.com/CashScript/cashscript/issues/412))

Syntax: `bytes unused zeroPadding` on a parameter, or `int unused x = ...` on a local.
It exempts that symbol from the compiler's `UnusedVariableError` while leaving it a real
stack item (pushed by the unlocker, dropped at end-of-scope cleanup) — so it still
appears in the artifact ABI and is otherwise size/cost-neutral.

The use here is **op-cost budgeting**. A BCH input often needs a longer unlocking script
to buy compute budget (op-cost scales with unlocking-script length). Previously that
meant a hand-built `[OP_DROP, ...contract]` redeem prefix plus a separately pushed pad;
now the contract simply declares a non-functional `bytes unused zeroPadding` argument
that the unlocker fills with zero bytes — the language expresses the intent directly,
with no manual `OP_DROP`.

Pad **position** matters for cost. A *trailing* pad param (pushed first → bottom of the
stack) leaves every other argument at its original depth and adds only a single
`OP_NIP`, whereas a *leading* pad deepens every other access by one. So the tight-budget
chunked families use a trailing pad, while the singleton vk_x contracts use a leading
pad (it sits under the constructor args, stays byte-identical, and keeps the tamper test
valid). In the source today it appears in `singleton/{bn254,bls12-381}/vkx.cash`,
`singleton/bn254/miller.cash`, and the chunked generators.

## 5. Codegen fix: repeated variable in a call's argument list

Calling a user function with the same variable in more than one argument position
(e.g. `fp6Mul(a, a)`, `add2(z, z)`) threw `Expected variable 'z' does not exist on the
stack`. The cause: `visitUserFunctionCall` emits arguments in reverse source order, but
the last-use analysis marks the textually-last occurrence as `OP_ROLL` (consume), so
under the reversal that occurrence is emitted first and consumes the variable before its
earlier uses are read. Fixed by suppressing `OP_ROLL` (using `OP_PICK`, copy) while
emitting call arguments, via a `userCallArgDepth` counter checked in `isOpRoll`.

This pattern is unavoidable here: every tower squaring is `fpNSqr(a) = fpNMul(a, a)`,
which passes all of `a`'s limbs twice. Full write-up in `COMPILER_FIX_NOTE.md` in the
fork (`packages/cashc/src/generation/GenerateTargetTraversal.ts`).

## 6. Compile-speed optimisation in the bytecode optimiser

`optimiseBytecode` (`packages/utils/src/script.ts`) was `O(n²)` in script length: it
stringified the whole script to ASM and regex-scanned a growing prefix to recover each
match's index on every replacement. That is pathological for large, constant-heavy
contracts (the BN254 pairing chunks bake dozens of 32–40 byte field constants), so a
single chunk could spend most of its compile time in the optimiser.

The fork pre-parses the optimisation patterns into opcode sequences once and matches
them directly against the `Script` array (no per-match stringify, structural equality
for the fixed-point check). Profiling scripts used to measure this live in the fork
root: `profile-compile.mjs` (per-phase breakdown on a heavy Miller chunk),
`bench-compile.mjs`, and `opt-scaling.mjs`.

## What is still a genuine CashScript gap

The fork now covers reusable functions, multi-file libraries/imports
([#153](https://github.com/CashScript/cashscript/issues/153)) and global constants
([#264](https://github.com/CashScript/cashscript/issues/264)). The remaining genuine
CashScript gap is **array/struct types**
([#266](https://github.com/CashScript/cashscript/issues/266)): there is still no
aggregate type, which is why every field-tower element is carried as a flat list of
ints and threaded through the multi-return functions of §2 (see
[README.md](README.md#cashscript-shortcomings) and [arrays.md](arrays.md)).

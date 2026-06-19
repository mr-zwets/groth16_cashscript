# The CashScript Compiler Fork

The verifiers in this repo are compiled with a **local fork of `cashc`**, not the
released compiler. The fork adds the one language feature the Groth16 field tower
could not be written without, **reusable (user-defined) functions**, plus a
multi-return extension, a codegen bug fix, and a compile-speed optimisation that the
generated pairing chunks need in order to build in reasonable time.

This is the feature the README used to list as the *"No Reusable Functions"*
CashScript shortcoming. It is no longer a shortcoming for this project: we built it.

- **Fork:** `C:\Users\mathi\Desktop\cashscript`, branch `feat/reusable-functions`
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
real source (`singleton/pairing/*.cash`, `chunked/`) relies on this everywhere; without
it the verifier would not fit BCH's bytecode limits.

## 2. Multi-return functions

A user function can return a tuple of values (commit *"add multi-return to functions"*),
e.g. `function mulFp2(...) returns (int, int)` or `mulFp12(...) returns (int, int, ...)`.

This is required because CashScript has no array or struct type, so each tower element
is carried as separate ints: an `Fp2` value is 2 ints, `Fp6` is 6, `Fp12` is 12. Every
tower operation therefore takes and returns its components as a flat list of ints, which
is only expressible with multi-return functions.

## 3. Codegen fix: repeated variable in a call's argument list

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

## 4. Compile-speed optimisation in the bytecode optimiser

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

The fork adds reusable functions; it does **not** add multi-file libraries/imports
([#153](https://github.com/CashScript/cashscript/issues/153)), global constants
([#264](https://github.com/CashScript/cashscript/issues/264)), or array/struct types
([#266](https://github.com/CashScript/cashscript/issues/266)). Those remain real
limitations (see [README.md](README.md#cashscript-shortcomings)) and shape the source
layout (each `.cash` re-declares the field tower it needs, with constants inlined).

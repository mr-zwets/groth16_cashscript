# The CashScript Compiler Fork

The verifiers in this repo are compiled with a **local fork of `cashc`**, not the
released compiler.

- **Fork:** `C:\Users\mathi\Desktop\cashscript`, branch **`feat/multi-returns`** —
  a five-commit patch series on top of **upstream's `next` branch** (v0.14.0-next.0).
- **CLI used by the graders and `_harness.mjs`:** `packages/cashc/dist/cashc-cli.js`,
  rebuilt with `yarn build` in `packages/utils` and `packages/cashc` after any compiler
  edit (`node_modules/cashc` in this repo symlinks to the fork).
- **Status:** local-only, not yet upstreamed. The intent is to propose the remaining
  patches upstream and, over time, compile this repo with **stock CashScript**.

## Alignment with upstream

Earlier iterations of this project carried a much larger custom front-end (branch
`feat/library-support`, forked from v0.13.1): a custom `internal function` construct for
reusable functions, a `library Name { ... }` / `import` / global-`constant` module
system, and assorted codegen fixes. Upstream CashScript has since landed **user-defined
functions on `next`**
([#413](https://github.com/CashScript/cashscript/pull/413), for issue
[#369](https://github.com/CashScript/cashscript/issues/369)): plain top-level (global)
`function`s compiled to `OP_DEFINE` / `OP_INVOKE`, **`import "./file.cash";`**
directives that bring another file's functions into scope, SDK debugging support for
user functions, and **dead-code elimination** of uncalled functions.

That covered most of what the old custom front-end existed for, so the fork was rebuilt
as a small patch series on top of upstream `next`, and the contracts were converted to
the upstream model (2026-07-02):

- `library X { ... }` wrappers → plain **top-level functions** (the `library` and
  `internal` keywords are gone);
- global `constant`s → the value written as a **literal at its use sites** (the
  compiler folds it; no stack slot). Top-level constants are no longer part of the
  language — [#264](https://github.com/CashScript/cashscript/issues/264) remains open
  upstream;
- the old repeated-call-argument codegen fix (`fpNSqr(a) = fpNMul(a, a)` used to
  mis-compile) is **obsolete** — upstream's function model handles it;
- `pragma cashscript ^0.14.0;`.

Every remaining custom feature below is a candidate for an upstream PR; the end state
is no fork at all.

## What upstream `next` provides (formerly custom here)

**User-defined functions** are the central enabler for the whole verifier. The BN254
field tower (`Fp2 → Fp6 → Fp12`), the G1/G2 point operations, and the Miller /
final-exponentiation steps are each **defined once and invoked**, so the loop body
(and, in the chunked deployment, the per-chunk bytecode) is compiled once rather than
inlined N times. Without this the verifier would not fit BCH's bytecode limits.

**Imports** give the multi-file layout: `singleton/<curve>/lib/` holds one shared
tower (`Fp → Fp2 → Fp6 → Fp12`, plus `Miller`, `FinalExp`, and for BN254 `G1` and the
lazy tower), and every contract is a thin `import` + `spend()` consumer (see each
`lib/README.md`). The import graph is resolved depth-first with de-duplication by
absolute path (diamonds collapse; cycles terminate).

**Dead-code elimination** drops every imported function a contract never calls, so
importing a large shared tower costs only the bytecode actually used — this is what
lets one shared tower back 27 different consumers and still compile each to minimal
bytecode.

## The custom patch series (branch `feat/multi-returns`)

### 1. Multi-return functions

A global function can declare and return multiple values —
`function fp2Mul(...) returns (int, int)` / `return c0, c1;` — destructured at the
call site with N-ary tuple assignment (`int m0, int m1 = fp2Mul(...);`).

This is required because CashScript has no array or struct type, so each tower element
is carried as separate ints: an `Fp2` value is 2 ints, `Fp6` is 6, `Fp12` is 12. Every
tower operation therefore takes and returns its components as a flat list of ints,
which is only expressible with multi-return functions. Codegen leaves the return
values on the stack in declared order; type checking enforces return arity and that a
multi-return call is only used as a destructuring RHS.

### 2. Tuple-destructuring into existing variables (issue [#136](https://github.com/CashScript/cashscript/issues/136))

A destructuring target may omit its type to mean "reassign this existing variable":

```solidity
(Z0, Z1, ..., Z11) = cycSqr(Z0, Z1, ..., Z11);   // reassign in place
```

Mixed forms — leading fresh declarations, trailing reassignments — are allowed,
including inside loops/branches
(`(int dc0,..,int dc5, Rxa,Rxb,Rya,Ryb,Rza,Rzb) = pointDouble(..)`).

**Why it matters here.** The field tower threads **12-wide** `Fp12` accumulators
through loops (`cycExpX`'s square-and-multiply ladder, `millerSingle`'s `F`); without
this feature every iteration needs 12–24 throwaway temps plus scalar copy-backs, which
double the depth every in-place rotate has to travel. Measured on the old branch when
the feature landed: BN254 `finalexp.cash` −15.9 % bytes / −14.5 % op-cost; full BN254
`groth16.cash` −6.1 % bytes. Only the singletons benefit (the chunked builds are
fully-unrolled SSA and never rebind).

### 3. The `unused` declaration modifier (issues [#125](https://github.com/CashScript/cashscript/issues/125), [#412](https://github.com/CashScript/cashscript/issues/412))

Syntax: `bytes unused zeroPadding` on a parameter, or `int unused x = ...` on a local.
It exempts that symbol from `UnusedVariableError` while leaving it a real stack item —
it still appears in the artifact ABI and is otherwise size/cost-neutral.

The use here is **op-cost budgeting**: a BCH input buys compute budget with unlocking
-script length, so contracts declare a non-functional zero-pad argument instead of a
hand-built `[OP_DROP, ...contract]` redeem prefix. Pad **position** matters: a
*trailing* pad (pushed first → bottom of stack) leaves every other argument at its
original depth (+1 `OP_NIP` only); a *leading* pad deepens every access by one. The
tight-budget chunked families use trailing pads; the singleton vk_x contracts use a
leading pad (it sits under the constructor args and keeps the tamper test valid).

### 4. Byte-accounted inlining of global functions

Sharing a function via `OP_DEFINE` / `OP_INVOKE` costs its body once (as a push) plus
`<id> OP_DEFINE`, and `<id> OP_INVOKE` per call site; inlining costs the body at every
call site. The fork splices a function's compiled body at its call sites **whenever
that is cheaper by exact byte accounting** (a single-use function always inlines;
recursive functions never; ties favour inlining). An inlined body is compiled with its
arguments staged on top of the stack and its cleanup baked in, so splicing it where
the args sit runs identically to invoking. Debug info (logs, require messages, source
locations) is preserved across inlining. On by default; `disableInlining` exists as a
compiler option (not exposed on the CLI).

This converted the old "define everything" cost model into a per-function optimum and
shaved 1–9 % off every contract in `singleton/` (see the conversion results below).

### 5. Optimiser performance + commutative `OP_MUL` rule

`optimiseBytecode` (`packages/utils/src/script.ts`) was `O(n²)` in script length
(stringify-to-ASM + regex per replacement), which was pathological for the large,
constant-heavy generated contracts (the 67 KB op-optimized singleton, the pairing
chunks). The fork matches pre-parsed opcode sequences directly against the `Script`
array, and adds a peephole rule exploiting `OP_MUL` commutativity.

## Conversion results (2026-07-02)

Recompiling the converted singletons with the new branch vs the old
`feat/library-support` compiler, same sources modulo syntax:

| contract | old | new | Δ |
| --- | --- | --- | --- |
| all 28 singleton contracts (total) | 178,540 B | 174,747 B | **−2.1 %** |
| BN254 `groth16.cash` (full verifier) | 14,641 B | 14,415 B | −1.5 % |
| BN254 opcode-optimized locking (recompiler) | 8,776 B | **8,600 B** | −2.0 % (score 9,135 → **8,959**) |
| BN254 `groth16_minop.cash` | 67,632 B | 66,507 B | −1.7 % |
| BLS12-381 `groth16.cash` | 14,915 B | 14,676 B | −1.6 % |

Small harnesses shrank 3–9 % (the DEFINE/INVOKE overhead dominates there and the
inliner removes it). Op-costs broadly dropped too (e.g. BN254 `miller4` ~957 M →
~599 M). Two tiny regressions: both `vkx` contracts +2 B, and the minop variant's
op-cost +1.6 % (191.6 M → 194.6 M, 24 → 25 inputs) — worth bisecting if the minop
op-cost axis matters for a future comparison. All graders pass and all verifier
benchmark vectors were rebuilt.

## What is still a genuine CashScript gap

The remaining genuine gap is **array/struct types**
([#266](https://github.com/CashScript/cashscript/issues/266)): there is still no
aggregate type, which is why every field-tower element is carried as a flat list of
ints and threaded through multi-return functions (see
[README.md](README.md#cashscript-shortcomings) and [arrays.md](arrays.md)).

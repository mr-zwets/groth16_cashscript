# Groth16 in CashScript

A working zk-SNARK **Groth16 verifier** in CashScript, implemented over two
pairing-friendly curves and validated against `py_ecc` / `@noble/curves` on the loosened
BCH 2026 VM:

- **BN254** (a.k.a. BN256 / alt_bn128, the curve behind Ethereum's pairing precompiles)
  — the full singleton, op-optimized singletons, and the BCH-limit-viable chunked
  verifiers. The best non-withdrawn deployable one, `bch-groth16-intratx-crown8-rawchain`,
  is **8 inputs in one standard transaction, 77,193 bytes**. On the proposed `bch-spec` VM,
  [`chunked/bn254/sound-si-gls`](chunked/bn254/sound-si-gls/README.md) verifies in **one
  input at 21,915 bytes**. The 35,143-byte densless-msm-slim entry previously listed here is
  withdrawn: its author withdrew the densless soundness claims ([#28](https://github.com/mr-zwets/groth16_cashscript/issues/28), [#32](https://github.com/mr-zwets/groth16_cashscript/issues/32) F6).
- **BLS12-381** — the singleton verifier (baseline and op-optimized), on the **same
  curve as the nChain reference** so the benchmark gets a true apples-to-apples
  comparison (7,347 B vs nChain's 522,564 B, ~71× smaller), **plus** current-BCH
  linked and grouped-residue chunked constructions (the grouped quotient-residue
  verifier is 26 inputs in 3 standard transactions; the Fiat-Shamir intra-tx build fits
  one standard transaction; the smallest non-withdrawn one,
  `bch-groth16-bls12381-intratx-fs-fused-coordinator-head`, is 60,285 B in 9 inputs).

This has grown into a whole family of verifiers across two curves, two forms, and
baseline/op-optimized variants — **[verifiers.md](verifiers.md) is the map** of which is
which and where each deployable frontier sits, and which entries are withdrawn
([#32](https://github.com/mr-zwets/groth16_cashscript/issues/32), [bench#49](https://github.com/mr-zwets/zk-verifier-bench/issues/49)).

The deterministic BN254 and BLS12-381 verifier.cash fixtures are equation-execution
benchmarks, not circuit-generated proofs: their setup scalars are published so the harness
can mint many valid proofs under one fixed verification key per curve. The frontier
bytecode still evaluates the complete four-pair equation and does not use those scalar
relations to collapse the on-chain statement, but the fixtures do not establish circuit
knowledge, secure binding of the public-input vector, arbitrary-key verification, or
interoperability with an independently generated setup.

It comes in two forms:

- **`singleton/`**: full single-transaction reference verifiers (the correctness
  oracles). They compile and run, are checked against the reference libraries, but
  exceed BCH consensus limits per input, so they are not meant to run on-chain. One
  self-contained folder per curve. See [`singleton/README.md`](singleton/README.md),
  [`singleton/bn254/README.md`](singleton/bn254/README.md), and
  [`singleton/bls12-381/README.md`](singleton/bls12-381/README.md).
- **`chunked/`**: the same computation split across a chain of stateful transactions so
  that **every** chunk fits one BCH input (≤10,000 bytes, ≤8,032,800 op-cost), carrying
  state forward in a hash commitment. This is the BCH-limit-viable on-chain form. See
  [`chunked/README.md`](chunked/README.md).

The verifier is compiled with a small fork of `cashc` that adds an op-cost objective and
a stack-rescheduling pass for very large contracts; see [Why a CashScript fork](#why-a-cashscript-fork).

This repo also documents the surrounding design: the map of all the verifiers
([verifiers.md](verifiers.md)), why the work is split across transactions
([multi-step-computation.md](multi-step-computation.md)), how this compares to prior
ZKP-on-Bitcoin attempts ([zkp-on-bch-vs-prior-attempts.md](zkp-on-bch-vs-prior-attempts.md)),
the field-tower representation ([arrays.md](arrays.md)), the compiler fork
([cashscript-compiler-fork.md](cashscript-compiler-fork.md)), the codegen op-cost lever
([rescheduling-stacks.md](rescheduling-stacks.md)), and the frontier certificates and
soundness notes ([BLS12381_FRONTIER_VERIFICATION.md](BLS12381_FRONTIER_VERIFICATION.md),
[BLS_QSPLIT_TAIL22_STATUS.md](BLS_QSPLIT_TAIL22_STATUS.md),
[psi-subgroup-degeneracy.md](psi-subgroup-degeneracy.md)). Earlier planning and compiler
investigations are kept under [archive/](archive/README.md) as a historical record.

## Why a CashScript fork

Everything the verifier needs from the language is in CashScript v0.14: user-defined functions compiled to `OP_DEFINE` / `OP_INVOKE`,
multi-file `import`s with dead-code elimination, multi-return functions, global
constants, tuple reassignment, and the `unused` modifier for op-cost padding arguments.
The one remaining language gap is arrays: each field-tower element is carried as
separate ints (2 for `Fp2`, 12 for `Fp12`) through multi-return functions, which costs
readability rather than bytes (see [Arrays and the Field Tower](arrays.md)).

We still compile with a fork ([`mr-zwets/cashscript`](https://github.com/mr-zwets/cashscript),
branch `compiler-optimizations-8`, on v0.14.0) because a pairing
verifier is an unusual contract: thousands of field operations per input, with every
byte and every executed op counted against consensus limits. Two things matter at that
scale that stock `cashc` does not do:

- **An op-cost objective** (`optimizeFor: 'opcost'`). Stock `cashc` optimises for bytes.
  A chunk that only fits its op-cost budget by zero-padding its unlocking script pays for
  every executed op, so the fork trades bytes for ops where that wins: helpers called
  in a branch that repeats inside a loop stay `OP_DEFINE`'d instead of re-stepping an
  inlined body every iteration, and tiny bodies inline to drop the invoke overhead. Under the `size` objective it adds
  constant hoisting and definition sinking for the byte-scored singletons.
- **DAG stack rescheduling** (`rescheduleStacks`). An opt-in pass that re-plans each
  straight-line block so operands are computed onto the top of the stack instead of
  fetched with `<depth> OP_PICK` / `OP_ROLL`. It is the single biggest codegen lever
  here (−5 to −7 % on the chunk families, −38 % on the plain BN254 singleton) and also
  the riskiest: it re-derives the evaluation order from a dataflow model, guarded by
  per-block "never worse" selection and differential VM tests.

Both are experimental and only pay off on contracts of this size. They may land
upstream once they are better understood; until then the fork is the smallest set of
patches that keeps the verifiers deployable. Details, measurements and branch history:
[The CashScript Compiler Fork](cashscript-compiler-fork.md) and
[The `rescheduleStacks` Compile Mode](rescheduling-stacks.md).

Branch `compiler-optimizations-7` renames reassigned variables inside loops and branches
instead of re-inserting them at fixed stack slots, which cuts loop-heavy code by about 20 %
op-cost. The current `compiler-optimizations-8` adds loop inversion, re-optimises after stack
rescheduling, and inlines functions that run on every loop iteration (only those called
inside a repeated branch stay `OP_DEFINE`'d). Builds that share functions across inputs (the
vk_x MSM helpers loaded from genesis) compile with `disableInlining`, since the compiler
cannot see that sharing.

`cashc` is linked from `../cashscript/packages/cashc`, so check that sibling repo out on
`compiler-optimizations-8` before building. The singletons, pairing singletons and the
densless-msm / residue-large / BLS grouped-residue builds are compiled with co-8; several
older chunked families are still on `compiler-optimizations-2` and await regeneration — see
[which artifacts were built with which compiler](cashscript-compiler-fork.md#which-artifacts-were-built-with-which-compiler).

## BCH Shortcomings

Loops and shift operators are now available (CashScript v0.13.0 / CHIP-2021-05 Loops), so the binding constraints are no longer missing language features but the BCH [script & transaction limits](https://cashscript.org/docs/compiler/limits). In practice the **maximum unlocking bytecode length (10,000 bytes for P2SH)** is the real wall: for P2SH the contract is supplied in the unlocking bytecode, so this single consensus limit caps how large the verifier can be, and (since the op-cost budget scales with script length) also caps the maximum compute budget that can be bought by padding.

- **Contract size / unlocking bytecode (the real practical limit):** 10,000 bytes for P2SH (consensus), or just 201 bytes for P2S. The full singletons do fit in under 10 KB of bytecode (4–8 KB), but need hundreds of millions of op-cost, far beyond what one input can buy.
- **Operation cost budget (op-cost):** a compute budget enforced per input, scaled by unlocking-script length (`(41 + unlockingBytecodeLength) * 800`). Extra budget can be "bought" by zero-padding the input script, but only up to the 10,000-byte unlocking bytecode limit above, so the two limits are really one wall. The `unused` modifier lets a contract declare this pad directly as a `bytes unused zeroPadding` argument instead of a hand-built `OP_DROP` prefix.

Because these limits are per input, a full verifier cannot run in one input and must be split into steps: sibling inputs of one transaction (the one-transaction verifiers) or sequential transactions linked by covenant commitments. See [Breaking Up Computation Across Multiple Steps](multi-step-computation.md) for both forms and [verifiers.md](verifiers.md) for the current entries.

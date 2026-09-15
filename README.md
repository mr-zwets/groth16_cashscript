# Groth16 in CashScript

A working zk-SNARK **Groth16 verifier** in CashScript, implemented over two
pairing-friendly curves and validated against `py_ecc` / `@noble/curves` on the loosened
BCH 2026 VM:

- **BN254** (a.k.a. BN256 / alt_bn128, the curve behind Ethereum's pairing precompiles)
  — the full singleton, an op-optimized singleton, and the BCH-limit-viable chunked
  verifier (plain and residue-optimized packings).
- **BLS12-381** — the singleton verifier (baseline and op-optimized), on the **same
  curve as the nChain reference** so the benchmark gets a true apples-to-apples
  comparison (~21× smaller bytecode), **plus** current-BCH linked and grouped-residue
  chunked constructions (the grouped quotient-residue verifier is 34 inputs in 3 standard
  transactions).

This has grown into a whole family of verifiers across two curves, two forms, and
baseline/op-optimized variants — **[verifiers.md](verifiers.md) is the map** of which is
which and where each deployable frontier sits.

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
the field-tower representation ([arrays.md](arrays.md)), the codegen op-cost lever
([rescheduling-stacks.md](rescheduling-stacks.md)), and the build plan
([roadmap.md](roadmap.md)).

## Why a CashScript fork

Everything the verifier needs from the language is in CashScript v0.14 (currently the
`next` pre-release): user-defined functions compiled to `OP_DEFINE` / `OP_INVOKE`,
multi-file `import`s with dead-code elimination, multi-return functions, global
constants, tuple reassignment, and the `unused` modifier for op-cost padding arguments.
The one remaining language gap is arrays: each field-tower element is carried as
separate ints (2 for `Fp2`, 12 for `Fp12`) through multi-return functions, which costs
readability rather than bytes (see [Arrays and the Field Tower](arrays.md)).

We still compile with a fork ([`mr-zwets/cashscript`](https://github.com/mr-zwets/cashscript),
branch `compiler-optimizations-5`, rebased on v0.14.0-next.5) because a pairing
verifier is an unusual contract: thousands of field operations per input, with every
byte and every executed op counted against consensus limits. Two things matter at that
scale that stock `cashc` does not do:

- **An op-cost objective** (`optimizeFor: 'opcost'`). Stock `cashc` optimises for bytes.
  A chunk that only fits its op-cost budget by zero-padding its unlocking script pays for
  every executed op, so the fork trades bytes for ops where that wins: loop-resident
  helpers stay `OP_DEFINE`'d instead of re-stepping an inlined body every iteration, and
  tiny bodies inline to drop the invoke overhead. Under the `size` objective it adds
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

## BCH Shortcomings

Loops and shift operators are now available (CashScript v0.13.0 / CHIP-2021-05 Loops), so the binding constraints are no longer missing language features but the BCH [script & transaction limits](https://cashscript.org/docs/compiler/limits). In practice the **maximum unlocking bytecode length (10,000 bytes for P2SH)** is the real wall: for P2SH the contract is supplied in the unlocking bytecode, so this single consensus limit caps how large the verifier can be, and (since the op-cost budget scales with script length) also caps the maximum compute budget that can be bought by padding.

- **Contract size / unlocking bytecode (the real practical limit):** 10,000 bytes for P2SH (consensus), or just 201 bytes for P2S. A full pairing verifier (F_p¹² tower arithmetic, Miller loops, final exponentiation) is very unlikely to fit under 10 KB even with loops collapsing repeated bytecode.
- **Operation cost budget (op-cost):** a compute budget enforced per input, scaled by unlocking-script length (`(41 + unlockingBytecodeLength) * 800`). Extra budget can be "bought" by zero-padding the input script, but only up to the 10,000-byte unlocking bytecode limit above, so the two limits are really one wall. The `unused` modifier lets a contract declare this pad directly as a `bytes unused zeroPadding` argument instead of a hand-built `OP_DROP` prefix.

Because these limits are per input, a full verifier cannot run in one input and must be split into steps: sibling inputs of one transaction (the one-transaction verifiers) or sequential transactions linked by covenant commitments. See [Breaking Up Computation Across Multiple Steps](multi-step-computation.md) for both forms and [verifiers.md](verifiers.md) for the current entries.

# Groth16 in CashScript

A working zk-SNARK **Groth16 verifier** in CashScript, implemented over two
pairing-friendly curves and validated against `py_ecc` / `@noble/curves` on the loosened
BCH 2026 VM:

- **BN254** (a.k.a. BN256 / alt_bn128, the curve behind Ethereum's pairing precompiles)
  — the full singleton **and** the BCH-limit-viable chunked verifier.
- **BLS12-381** — the singleton verifier, on the **same curve as the nChain reference**,
  so the benchmark gets a true apples-to-apples comparison (~21× smaller bytecode).

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

The verifier is built with a **local fork of `cashc`** (branch `feat/multi-returns`): a
small patch series on top of **upstream's `next` branch**, which now provides
user-defined functions and file imports itself. The fork adds multi-return functions and
a few codegen improvements, with the goal of upstreaming those too and eventually
compiling with stock CashScript. See
[The CashScript Compiler Fork](cashscript-compiler-fork.md).

This repo also documents the surrounding design: why the work is split across
transactions ([multi-step-computation.md](multi-step-computation.md)), how this compares
to prior ZKP-on-Bitcoin attempts ([zkp-on-bch-vs-prior-attempts.md](zkp-on-bch-vs-prior-attempts.md)),
the field-tower representation ([arrays.md](arrays.md)), and the build plan
([roadmap.md](roadmap.md)).

## CashScript Shortcomings

Implementing a pairing verifier pushed CashScript past several of its limits. The two biggest — reusable functions and multi-file imports — have since **landed upstream on the `next` branch**; the remaining custom features live in a small fork rebased on top of it (see [The CashScript Compiler Fork](cashscript-compiler-fork.md)); the rest still shape the code. Each is
tracked on the [CashScript v0.14.0 milestone](https://github.com/CashScript/cashscript/milestone/).

### Reusable Functions (landed upstream on `next`)

Released CashScript (≤0.13) only allows calling built-in functions: you cannot define your
own function and call it from a contract function or from another function. The verifier
relies on user-defined functions everywhere (the `Fp2 → Fp6 → Fp12` tower, G1/G2 point ops,
the Miller and final-exponentiation steps), compiled to `OP_DEFINE` / `OP_INVOKE`. This was
originally a custom fork feature; upstream has since implemented it on `next`
([#369](https://github.com/CashScript/cashscript/issues/369) /
[#413](https://github.com/CashScript/cashscript/pull/413), tied to the 2026 network
upgrade), and our fork is now rebased on that implementation. The remaining custom pieces
(multi-return functions, tuple reassignment, `unused`, inlining) are in
[The CashScript Compiler Fork](cashscript-compiler-fork.md).

### Multi-file Imports (landed upstream on `next`)

Separately from reusable functions within a file, released CashScript has no multi-file construct: no way to pull definitions from another file with a dependency graph. Upstream `next` now supports top-level (global) functions and `import "./Rel.cash";`, which brings a file's functions into scope unqualified, with the import graph resolved (and de-duplicated) before compilation — covering what this repo previously did with a custom `library` keyword. Each `.cash` in `singleton/<curve>/` is a thin consumer that imports the shared `Fp → Fp2 → Fp6 → Fp12 → Miller → FinalExp` tower:

```solidity
import "./lib/Fp2.cash";

contract Fp2Ops() {
  function spend(...) { ... fp2Mul(...) ... }
}
```

Dead-code elimination means importing the big shared tower costs nothing for the functions a consumer doesn't call (and the fork's byte-accounted inlining removes the `OP_DEFINE`/`OP_INVOKE` overhead wherever splicing is cheaper). Note this tidies the **singleton** source layout; it does not shrink the **chunked** deployment, where each transaction is independent and the per-chunk function prologues are repeated regardless of source organisation.

The original library/macros request is [#153](https://github.com/CashScript/cashscript/issues/153); upstream's file imports of top-level functions cover this repo's needs.

### Global Constants (still open upstream)

CashScript has no file-level constant — tracked in [#264 Add Global constants](https://github.com/CashScript/cashscript/issues/264). An earlier fork iteration added `int constant NAME = <expr>;`, but to stay close to upstream that was dropped in the rebase: shared values like the BN254 base field prime are now written as literals at each use site (the compiler folds them; no stack slot), at the cost of the prime appearing once per function that reduces mod p.

### No Array Type

Groth16 in Solidity usually allows for an array of input parameters, CashScript doesn't allow for `array` types. Now that bounded loops exist, it would be useful to 'loop' over the number of elements in an array, however this would require very heavy abstraction on the CashScript side as arrays don't natively exist. In practice each tower element is instead carried as separate ints (2 for `Fp2`, 12 for `Fp12`), passed through multi-return functions.

Tracked in [#266 Add support for Array types](https://github.com/CashScript/cashscript/issues/266). Arrays are not strictly needed, and since they would compile to a long concatenated byte string for these 256-bit field elements the performance effect would be small. The main win would be cleaner, more auditable code. See [Arrays and the Field Tower](arrays.md) for details.

## BCH Shortcomings

Loops and shift operators are now available (CashScript v0.13.0 / CHIP-2021-05 Loops), so the binding constraints are no longer missing language features but the BCH [script & transaction limits](https://cashscript.org/docs/compiler/limits). In practice the **maximum unlocking bytecode length (10,000 bytes for P2SH)** is the real wall: for P2SH the contract is supplied in the unlocking bytecode, so this single consensus limit caps how large the verifier can be, and (since the op-cost budget scales with script length) also caps the maximum compute budget that can be bought by padding.

- **Contract size / unlocking bytecode (the real practical limit):** 10,000 bytes for P2SH (consensus), or just 201 bytes for P2S. A full pairing verifier (F_p¹² tower arithmetic, Miller loops, final exponentiation) is very unlikely to fit under 10 KB even with loops collapsing repeated bytecode.
- **Operation cost budget (op-cost):** a compute budget enforced per input, scaled by unlocking-script length (`(41 + unlockingBytecodeLength) * 800`). Extra budget can be "bought" by zero-padding the input script, but only up to the 10,000-byte unlocking bytecode limit above, so the two limits are really one wall. The fork's [`unused` modifier](cashscript-compiler-fork.md#3-the-unused-declaration-modifier-issues-125-412) lets a contract declare this pad directly as a `bytes unused zeroPadding` argument instead of a hand-built `OP_DROP` prefix.

Because these limits are per input per transaction, a full verifier almost certainly cannot run in a single transaction and the work must be split into steps. See [Breaking Up Computation Across Multiple Steps](multi-step-computation.md) for why this is done across sequential transactions (carrying state forward in an NFT commitment, using a hash when the state exceeds 128 bytes) rather than across the inputs of one transaction.

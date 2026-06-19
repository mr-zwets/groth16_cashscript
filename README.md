# Groth16 in CashScript

A working zk-SNARK **Groth16 verifier over BN254** (a.k.a. BN256 / alt_bn128, the curve
behind Ethereum's pairing precompiles), implemented in CashScript and validated against
`py_ecc` / `@noble/curves` on the loosened BCH 2026 VM. It comes in two forms:

- **`singleton/`**: full single-transaction reference verifiers (the correctness
  oracles). They compile and run, are checked against the reference libraries, but
  exceed BCH consensus limits per input, so they are not meant to run on-chain. See
  [`singleton/README.md`](singleton/README.md) and
  [`singleton/pairing/README.md`](singleton/pairing/README.md).
- **`chunked/`**: the same computation split across a chain of stateful transactions so
  that **every** chunk fits one BCH input (≤10,000 bytes, ≤8,032,800 op-cost), carrying
  state forward in a hash commitment. This is the BCH-limit-viable on-chain form. See
  [`chunked/README.md`](chunked/README.md).

The verifier is built with a **local fork of `cashc`** that adds reusable functions and
a few related capabilities. See [The CashScript Compiler Fork](cashscript-compiler-fork.md).

This repo also documents the surrounding design: why the work is split across
transactions ([multi-step-computation.md](multi-step-computation.md)), how this compares
to prior ZKP-on-Bitcoin attempts ([zkp-on-bch-vs-prior-attempts.md](zkp-on-bch-vs-prior-attempts.md)),
the field-tower representation ([arrays.md](arrays.md)), and the build plan
([roadmap.md](roadmap.md)).

## CashScript Shortcomings

Implementing a pairing verifier pushed CashScript past several of its limits. One of them, the biggest, we solved by forking the compiler; the rest still shape the code. Each is
tracked on the [CashScript v0.14.0 milestone](https://github.com/CashScript/cashscript/milestone/).

### Reusable Functions (added in custom fork)

Stock CashScript only allows calling built-in functions: you cannot define your own
function and call it from a contract function or from each other. The verifier relies on
user-defined functions everywhere (the `Fp2 → Fp6 → Fp12` tower, G1/G2 point ops, the
Miller and final-exponentiation steps). We added them in a **local `cashc` fork**, compiled
to `OP_DEFINE` / `OP_INVOKE`, so this is no longer a blocker for this project. Details and
the other compiler changes (multi-return functions, a codegen fix, an optimiser speedup)
are in [The CashScript Compiler Fork](cashscript-compiler-fork.md).

Tracked upstream in [#369 Add support for reusable function definition / invocation](https://github.com/CashScript/cashscript/issues/369) (tied to the 2026 network upgrade); our fork is local and not yet upstreamed.

### No Library Support

Separately from reusable functions within a file, CashScript has no multi-file library construct: there is no `library` keyword and no `import` to pull definitions from another file with a dependency graph. This matters mainly for code organisation, and for code reuse across contracts when a large implementation is broken up. It is the reason each `.cash` file in `singleton/pairing/` re-declares the slice of the field tower it needs rather than importing a shared `FieldTower → Curve → Pairing → Groth16` module chain:

```solidity
import { mulFp12 } from "FieldTower.cash";

library Pairing {
  ...
}
```

Note this would only tidy the source layout; it would not shrink the **chunked**
deployment, where each transaction is independent and the per-chunk function prologues
are repeated regardless of how the source is organised.

Tracked in [#153 Add support for libraries/macros](https://github.com/CashScript/cashscript/issues/153).

### No Global Variable Support

There is no file- or library-level constant, so shared values like the BN254 base field prime must be inlined at each use site (the real code hard-codes it into `mulFp`, which also lets it constant-fold):

```solidity
int constant p = 21888242871839275222246405745257275088696311157297823662689037894645226208583; // BN254 prime
```

Tracked in [#264 Add Global constants](https://github.com/CashScript/cashscript/issues/264).

### No Array Type

Groth16 in Solidity usually allows for an array of input parameters, CashScript doesn't allow for `array` types. Now that bounded loops exist, it would be useful to 'loop' over the number of elements in an array, however this would require very heavy abstraction on the CashScript side as arrays don't natively exist. In practice each tower element is instead carried as separate ints (2 for `Fp2`, 12 for `Fp12`), passed through multi-return functions.

Tracked in [#266 Add support for Array types](https://github.com/CashScript/cashscript/issues/266). Arrays are not strictly needed, and since they would compile to a long concatenated byte string for these 256-bit field elements the performance effect would be small. The main win would be cleaner, more auditable code. See [Arrays and the Field Tower](arrays.md) for details.

## BCH Shortcomings

Loops and shift operators are now available (CashScript v0.13.0 / CHIP-2021-05 Loops), so the binding constraints are no longer missing language features but the BCH [script & transaction limits](https://cashscript.org/docs/compiler/limits). In practice the **maximum unlocking bytecode length (10,000 bytes for P2SH)** is the real wall: for P2SH the contract is supplied in the unlocking bytecode, so this single consensus limit caps how large the verifier can be, and (since the op-cost budget scales with script length) also caps the maximum compute budget that can be bought by padding.

- **Contract size / unlocking bytecode (the real practical limit):** 10,000 bytes for P2SH (consensus), or just 201 bytes for P2S. A full pairing verifier (F_p¹² tower arithmetic, Miller loops, final exponentiation) is very unlikely to fit under 10 KB even with loops collapsing repeated bytecode.
- **Operation cost budget (op-cost):** a compute budget enforced per input, scaled by unlocking-script length (`(41 + unlockingBytecodeLength) * 800`). Extra budget can be "bought" by zero-padding the input script, but only up to the 10,000-byte unlocking bytecode limit above, so the two limits are really one wall.

Because these limits are per input per transaction, a full verifier almost certainly cannot run in a single transaction and the work must be split into steps. See [Breaking Up Computation Across Multiple Steps](multi-step-computation.md) for why this is done across sequential transactions (carrying state forward in an NFT commitment, using a hash when the state exceeds 128 bytes) rather than across the inputs of one transaction.

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

The verifier is built with a **local fork of `cashc`** that adds reusable functions and
a few related capabilities. See [The CashScript Compiler Fork](cashscript-compiler-fork.md).

This repo also documents the surrounding design: why the work is split across
transactions ([multi-step-computation.md](multi-step-computation.md)), how this compares
to prior ZKP-on-Bitcoin attempts ([zkp-on-bch-vs-prior-attempts.md](zkp-on-bch-vs-prior-attempts.md)),
the field-tower representation ([arrays.md](arrays.md)), and the build plan
([roadmap.md](roadmap.md)).

## CashScript Shortcomings

Implementing a pairing verifier pushed CashScript past several of its limits. Three of them — reusable functions, multi-file libraries, and global constants — we solved by forking the compiler (see [The CashScript Compiler Fork](cashscript-compiler-fork.md)); the rest still shape the code. Each is
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

### Library Support (added in custom fork)

Separately from reusable functions within a file, stock CashScript has no multi-file library construct: no `library` keyword and no `import` to pull definitions from another file with a dependency graph. We added both in the fork: a `library Name { ... }` bag of functions and constants, and `import "./Rel.cash";` that brings its members into scope unqualified, with the import graph resolved (and de-duplicated) before compilation. Each `.cash` in `singleton/<curve>/` is now a thin consumer that imports the shared `Fp → Fp2 → Fp6 → Fp12 → Miller → FinalExp` library tower:

```solidity
import "./lib/Fp2.cash";

contract Fp2Ops() {
  function spend(...) { ... fp2Mul(...) ... }
}
```

Tree-shaking means importing the big shared tower costs nothing for the functions a consumer doesn't call, so the library version compiles byte-identically to the old hand-inlined files. Details in [The CashScript Compiler Fork](cashscript-compiler-fork.md#3-libraries-imports-and-global-constants-issues-153-264). Note this tidies the **singleton** source layout; it does not shrink the **chunked** deployment, where each transaction is independent and the per-chunk function prologues are repeated regardless of source organisation.

Tracked upstream in [#153 Add support for libraries/macros](https://github.com/CashScript/cashscript/issues/153); our fork is local and not yet upstreamed.

### Global Constants (added in custom fork)

Stock CashScript has no file- or library-level constant. The fork adds `int constant NAME = <expr>;` at file top level or inside a library; it is folded to a literal and inlined at each use site (no stack slot), so a shared value like the BN254 base field prime has a single source of truth instead of being copy-pasted into every function:

```solidity
int constant P = 21888242871839275222246405745257275088696311157297823662689037894645226208583; // BN254 prime
```

Tracked upstream in [#264 Add Global constants](https://github.com/CashScript/cashscript/issues/264); our fork is local and not yet upstreamed.

### No Array Type

Groth16 in Solidity usually allows for an array of input parameters, CashScript doesn't allow for `array` types. Now that bounded loops exist, it would be useful to 'loop' over the number of elements in an array, however this would require very heavy abstraction on the CashScript side as arrays don't natively exist. In practice each tower element is instead carried as separate ints (2 for `Fp2`, 12 for `Fp12`), passed through multi-return functions.

Tracked in [#266 Add support for Array types](https://github.com/CashScript/cashscript/issues/266). Arrays are not strictly needed, and since they would compile to a long concatenated byte string for these 256-bit field elements the performance effect would be small. The main win would be cleaner, more auditable code. See [Arrays and the Field Tower](arrays.md) for details.

## BCH Shortcomings

Loops and shift operators are now available (CashScript v0.13.0 / CHIP-2021-05 Loops), so the binding constraints are no longer missing language features but the BCH [script & transaction limits](https://cashscript.org/docs/compiler/limits). In practice the **maximum unlocking bytecode length (10,000 bytes for P2SH)** is the real wall: for P2SH the contract is supplied in the unlocking bytecode, so this single consensus limit caps how large the verifier can be, and (since the op-cost budget scales with script length) also caps the maximum compute budget that can be bought by padding.

- **Contract size / unlocking bytecode (the real practical limit):** 10,000 bytes for P2SH (consensus), or just 201 bytes for P2S. A full pairing verifier (F_p¹² tower arithmetic, Miller loops, final exponentiation) is very unlikely to fit under 10 KB even with loops collapsing repeated bytecode.
- **Operation cost budget (op-cost):** a compute budget enforced per input, scaled by unlocking-script length (`(41 + unlockingBytecodeLength) * 800`). Extra budget can be "bought" by zero-padding the input script, but only up to the 10,000-byte unlocking bytecode limit above, so the two limits are really one wall. The fork's [`unused` modifier](cashscript-compiler-fork.md#4-the-unused-declaration-modifier-issues-125-412) lets a contract declare this pad directly as a `bytes unused zeroPadding` argument instead of a hand-built `OP_DROP` prefix.

Because these limits are per input per transaction, a full verifier almost certainly cannot run in a single transaction and the work must be split into steps. See [Breaking Up Computation Across Multiple Steps](multi-step-computation.md) for why this is done across sequential transactions (carrying state forward in an NFT commitment, using a hash when the state exceeds 128 bytes) rather than across the inputs of one transaction.

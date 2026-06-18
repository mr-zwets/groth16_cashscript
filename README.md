# Exploration of Groth16 in CashScript

**Note:** this is CashScript pseudo-code to learn how the language needs to be upgraded. The code was written by GPT so likely has errors.

## CashScript Remaining Shortcomings

The following limitations still apply as of CashScript v0.13.x and keep this code as pseudo-code that does not yet compile. Each is tracked on the [CashScript v0.14.0 milestone](https://github.com/CashScript/cashscript/milestone/).

### No Library Support

CashScript does not have library support currently although it is on the roadmap. Because of the complexity of this library they are split up across multiple separate libraries which import each other. CashScript v0.13.x also only allows calling built-in functions, so the cross-library function calls used here are not yet possible.

```solidity
import { powMod  } from "Math.cash";

library BN256 {
  ...
}
```

Tracked in [#153 Add support for libraries/macros](https://github.com/CashScript/cashscript/issues/153) and [#369 Add support for reusable function definition / invocation](https://github.com/CashScript/cashscript/issues/369) (the latter tied to the 2026 network upgrade).

### No Global Variable Support

```solidity
library BN256 {
  int constant p = 21888242871839275222246405745257275088696311157297823662689037894645226208583; // BN256 prime
```

Tracked in [#264 Add Global constants](https://github.com/CashScript/cashscript/issues/264).

### No Array Type

Groth16 in Solidity usually allows for an array of inputs parameters, CashScript doesn't allow for `array` types. Now that bounded loops exist, it would be useful to 'loop' over the number of elements in an array, however this would require very heavy abstraction on the CashScript side as arrays don't natively exist. There would also need to be two types of arrays: 'fixed-size arrays' & 'dynamic arrays'

Tracked in [#266 Add support for Array types](https://github.com/CashScript/cashscript/issues/266).

## BCH Shortcomings

Loops and shift operators are now available (CashScript v0.13.0 / CHIP-2021-05 Loops), so the binding constraints are no longer missing language features but the BCH [script & transaction limits](https://cashscript.org/docs/compiler/limits). In practice the **maximum unlocking bytecode length (10,000 bytes for P2SH)** is the real wall: for P2SH the contract is supplied in the unlocking bytecode, so this single consensus limit caps how large the verifier can be, and (since the op-cost budget scales with script length) also caps the maximum compute budget that can be bought by padding.

- **Contract size / unlocking bytecode (the real practical limit):** 10,000 bytes for P2SH (consensus), or just 201 bytes for P2S. A full pairing verifier (F_p¹² tower arithmetic, Miller loops, final exponentiation) is very unlikely to fit under 10 KB even with loops collapsing repeated bytecode.
- **Operation cost budget (op-cost):** a compute budget enforced per input, scaled by unlocking-script length (`(41 + unlockingBytecodeLength) * 800`). Extra budget can be "bought" by zero-padding the input script, but only up to the 10,000-byte unlocking bytecode limit above, so the two limits are really one wall.
- **Stack element size:** max 10,000 bytes per element, relevant when packing the F_p², F_p⁶ and F_p¹² tower elements.
- **SigChecks / hashing limits:** per-transaction caps on signature and hashing operations.

Because these limits are per input per transaction, a full verifier almost certainly cannot run in a single transaction and the work must be split into steps. See [Breaking Up Computation Across Multiple Steps](multi-step-computation.md) for why this is done across sequential transactions (carrying state forward in an NFT commitment, using a hash when the state exceeds 128 bytes) rather than across the inputs of one transaction.

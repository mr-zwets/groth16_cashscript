# Exploration of Groth16 in CashScript

**Note:** this is CashScript pseudo-code to learn how the language needs to be upgraded. The code was written by GPT so likely has errors.

## CashScript Shortcomings

### No loop syntax

`powMod` in `math.cash` and `scalarMult` & `millerAlgorithm` in `BN256.cash` both need looping a fixed amount of times which could be unrolled by the compiler

```solidity
unroll(256) {
  ...
}
```

### No Library Support

CashScript does not have library support currently although it is on the roadmap. Because of the complexity of this library they are split up across multiple separate libraries which import each other.

```solidity
import { powMod  } from "Math.cash";

library BN256 {
  ...
}
```

### No Global Variable Support

```solidity
library BN256 {
  int constant p = 21888242871839275222246405745257275088696311157297823662689037894645226208583; // BN256 prime
```

## BCH Shortcomings

### Need to Unroll Loops

would be solved with `CHIP-2021-05-loops: Bounded Looping Operations`

### No Shift Operator

`mathShift.cash` is simpler than `math.cash` as it is able to do the following

```solidity
if ((exp & (1 << i)) != 0) {   // Check if the ith bit of exp is set
  ...
}
```
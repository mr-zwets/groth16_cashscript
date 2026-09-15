# Six-host public-input authentication and resource certificate

The `qsplit22-tail22-six-pic-balanced` resource profile covers the 22-input BLS12-381 construction with six public-input authentication hosts and zero density padding. Its certificate implementation is [`prove_q132_pic_five_batch_resource_ceiling.mjs`](chunked/bls12-381/prove_q132_pic_five_batch_resource_ceiling.mjs); the historical filename is retained. The owning transaction generator is [`measure_d3_two_chart_binary.mjs`](chunked/bls12-381/measure_d3_two_chart_binary.mjs).

## Ordered authentication coverage

| Input | Program | First window | Count | Windows |
|---:|---|---:|---:|---|
| 0 | Coordinator | 0 | 6 | 0–5 |
| 1 | First | 6 | 4 | 6–9 |
| 2 | AdditionTail | 10 | 5 | 10–14 |
| 3 | Regular | 15 | 6 | 15–20 |
| 16 | AdditionMiddle | 21 | 6 | 21–26 |
| 21 | Terminal | 27 | 5 | 27–31 |

The generator requires positive counts, contiguous starts and total count 32. Each host accepts only its compiled first/count pair. It derives each window's digit from the two public scalars in the statement, loads the record from its prescribed carrier, and reconstructs the root through 16 domain-separated Merkle levels. Leaf framing binds the carrier block, window, digit and four canonical projective parameters. Node framing binds the level and parent index. Exhausted path length and final global index are checked.

For a batch starting at `s` with `n` windows, its fixed commitment is

```text
SHA256(PIC_BATCH_TAG || byte(s) || byte(n) || root[s] || … || root[s+n−1])
```

The helper selects the exact commitment for that pair; all six commitments occupy 192 bytes. The roots and projective table are derived exclusively from the public verification key. The ordered list of 32 roots, record locations, statement/proof commitments and Fiat–Shamir transcript ordering remain bound by the existing construction.

Every host imports authentication helper 117 from the prescribed slice of input 5's redeem script. First consumes the helper's success with `OP_VERIFY` before continuing its existing verifier. The coordinator pins the ordered sibling P2SH locking programs, including First and the helper carrier. Successful verification requires every transaction input, so early helper execution does not bypass the later statement or program checks.

## Complete conditional inventory

Each window contributes 21 fixed conditionals and 16 Merkle-order conditionals. The six-way commitment selection adds one fixed conditional to each helper invocation relative to the five-host construction. Fixed work outside the window loop is 6/7/7/16/6/6 for the hosts listed above.

The strict profile requires this complete inventory; counts are execution counts, including loop iterations:

| Inputs | Fixed | PIC order | Identity | State swap | Select | Terminal reset | Split reset | B identity |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| 0 | 132 | 96 | 0 | 0 | 0 | 0 | 0 | 1 |
| 1 | 91 | 64 | 2 | 0 | 2 | 1 | 1 | 0 |
| 2 | 112 | 80 | 1 | 1 | 1 | 0 | 1 | 0 |
| 3 | 142 | 96 | 1 | 1 | 1 | 0 | 1 | 0 |
| 4, 6–15, 17–20 | 10 | 0 | 1 | 1 | 1 | 0 | 1 | 0 |
| 5 | 134 | 0 | 1 | 1 | 1 | 0 | 1 | 0 |
| 16 | 132 | 96 | 2 | 1 | 2 | 1 | 1 | 0 |
| 21 | 111 | 80 | 1 | 1 | 1 | 1 | 1 | 0 |

The original profiles retain their own inventories. Unknown profiles, missing/extraneous inputs, unknown branch shapes, unexpected counts, unsupported operations, unproved numeric provenance and negative certified density margins reject.

## Exact size-compiled B branch

Let `P` be the BLS12-381 base-field prime, `Fp2 = Fp[i]/(i²+1)`, `X = Bxa + Bxb·i` and `Y = Bya + Byb·i`. The coordinator checks each effective B coordinate in `[0,P)` and `Bidentity` in `{0,1}` before this branch.

The size-compiled schedule implements the same predicates:

- If `Bidentity == 1`, the four effective coordinates equal their corresponding authenticated substitute coordinates.
- Otherwise, `Bxa+Bxb+Bya+Byb != 0` and `Y² = X³ + (4+4i)`.

Independent symbolic execution of the exact parsing, stack operations and helper bodies establishes the coordinate bindings from statement/header/fixed-blob byte spans. The two nonidentity equality residuals reduce to

```text
Bya² − Byb² − Bxa³ + 3·Bxa·Bxb² − 4 = 0 mod P
2·Bya·Byb − 3·Bxa²·Bxb + Bxb³ − 4 = 0 mod P
```

Helper outputs are canonical, so these congruences correspond to the checked integer equalities. Both arms preserve all 24 prebranch stack items exactly after consuming the condition; no merged output interval is assumed.

The certificate recognizes this schedule only at input 0 under the explicit six-PIC profiles. `SIX_PIC_B_IDENTITY_BRANCH` pins all 90 instructions from `OP_IF` through `OP_ENDIF`, including each literal stack depth. `SIX_PIC_B_IDENTITY_FUNCTIONS` pins the complete live bytecode of all invoked helpers:

| Function ID | Meaning | Bytes |
|---:|---|---:|
| 0 | Fp2 square (`c2Sqr`) | 20 |
| 1 | `(a+b) mod P` (`cAdd`) | 51 |
| 2 | `(a−b+P) mod P` (`cSub`) | 56 |
| 3 | `(a·b) mod P` (`cMul`) | 51 |

The call graph is finite and contains no conditional, loop or recursion. For canonical operands, addition's numerator lies in `[0,2(P−1)]`, corrected subtraction in `[1,2P−1]`, and multiplication in `[0,(P−1)²]`. The two square multiplications receive reduced operands. Since `P < 2^381`, the effective-coordinate sum is below `2^383` and products are below `2^762`. Including the VM sign bit, coordinates, sums and corrected differences fit 48 bytes; products fit 96. No negative remainder case is introduced. The exact helper pins include the positive P constants and operand scheduling.

## Why both B classes are required

The shadow interpreter follows actual native invocation frames and propagates complete numeric ranges through each executed operation. It charges worst-case arithmetic widths and stack pushes using the existing interval rules. A helper call is not assigned an opaque fixed arithmetic cost.

B identity and B nonidentity have different executed work, so each needs its own strict trace. For the exact six-PIC branch variant, the observed branch decision must match the declared resource fixture class: `b-identity`/`all-identity` select the identity arm; the other fixtures select the nonidentity arm. A mislabeled cheaper identity execution therefore cannot certify the nonidentity class. No certificate for one B arm claims to bound the unexecuted arm.

The frozen balanced corpus yields minimum universal margins 23,838 for the committed nonidentity class and 122,142 for the identity class. These results retain exact inventory, branch, provenance and density checks; `RESOURCE_PROBE=1` is diagnostic and cannot establish acceptance.

## Replay from source

Use the compiler and dependencies pinned in [`BLS_QSPLIT_TAIL22_STATUS.md`](BLS_QSPLIT_TAIL22_STATUS.md). From the repository root, replay both frozen resource certificates:

```sh
RESOURCE_PROFILE=qsplit22-tail22-six-pic-balanced \
RESOURCE_SINGLE=0 RESOURCE_PROBE=0 \
RESOURCE_CORPUS_PATH=qsplit-tail22-final-resource-bytecodes.json \
RESOURCE_FIXTURE=committed \
RESOURCE_EXPECTED_CERTIFICATE_PATH=qsplit-tail22-final-committed-ceiling.json \
COMPACT=1 node chunked/bls12-381/prove_q132_pic_five_batch_resource_ceiling.mjs

RESOURCE_PROFILE=qsplit22-tail22-six-pic-balanced \
RESOURCE_SINGLE=0 RESOURCE_PROBE=0 \
RESOURCE_CORPUS_PATH=qsplit-tail22-final-resource-bytecodes.json \
RESOURCE_FIXTURE=b-identity \
RESOURCE_EXPECTED_CERTIFICATE_PATH=qsplit-tail22-final-b-identity-ceiling.json \
COMPACT=1 node chunked/bls12-381/prove_q132_pic_five_batch_resource_ceiling.mjs
```

This resource argument preserves the declared Fiat–Shamir and cofactor-equivalence semantics. It does not upgrade the construction's input-validation claim: the official status **NOT DEMONSTRATED** remains unchanged. Full proof/mutation corpus, mathematical audits and official benchmark gates remain separate requirements.

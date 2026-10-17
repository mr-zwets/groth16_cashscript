# Breaking Up Computation Across Multiple Steps

A full Groth16 verifier (or any heavy computation) will not fit within a single input's op-cost budget or the 10,000-byte unlocking bytecode limit (see [BCH Shortcomings](README.md#bch-shortcomings)). The work has to be split into smaller pieces. There are two axes to consider: across the inputs of one transaction, and across a sequence of transactions.

## Across inputs of one transaction (the linked-input method)

Each input is validated independently, and its script runs in isolation: there is no shared VM stack, so an input cannot read another input's *stack*. But introspection lets an input read another input's **unlocking bytecode** (`OP_INPUTBYTECODE` = `tx.inputs[i].unlockingBytecode`), which is its pushed arguments. So intermediate results *can* be passed between sibling inputs — not through the stack, but by putting each chunk's output in its witness as an argument and having the next chunk read and check it.

Concretely, for `y = f1(f0(x))`:

```
input i:    <inBlob = x>            redeem: out = f0(x); require( out == tx.inputs[i+1].unlockingBytecode[arg slice] )
input i+1:  <inBlob = f0(x)>        redeem: out = f1(f0(x)); ... (verdict)
```

Input `i` recomputes its chunk and `require`s that input `i+1`'s incoming argument equals that output — a raw byte-equality check across sibling inputs (the "verify `arg01 == arg10`" pattern). This shards one running computation across the inputs of a single transaction and binds it end-to-end, with the verdict asserted by the last input.

Compared with the across-transactions covenant below, this needs **no NFT-commitment hand-off and no hashing**, the intermediate state is **not limited to 128 bytes** (it is just a pushed argument, any size), and the whole computation is **one transaction** instead of a chain of them — so no per-step block/mempool hop. Each input still gets its own op-cost budget and 10,000-byte script cap. The plain and BLS constructions remain larger non-standard transactions; the optimized BN254 constructions fit one standard transaction: 11 inputs / 86,950 B for the quotient-torus residue build, and 5 inputs / 35,143 B for the current frontier (`bch-groth16-intratx-pairfold5-densless-msm-slim`). These are implemented in [`chunked/intratx`](chunked/intratx) and benchmarked as the `bch-{pairing,groth16}-intratx` (and `-bls12381-`) entries.

> Earlier revisions of this document claimed intra-transaction sharing was "not viable" because inputs cannot pass state. That was wrong: they cannot share a stack, but they can read each other's arguments by introspection, which is enough.

## Across transactions (the covenant pattern)

Computation can be carried forward across a chain of transactions using a stateful covenant UTXO (a CashToken NFT) that is spent and recreated at each step:

1. Each transaction performs one chunk of the computation, sized to fit that step's op-cost and bytecode budget.
2. The updated intermediate state is committed to the NFT output that is created for the next step.
3. A step or phase counter tracks progress. The final step asserts the result (for the verifier, that the pairing product equals the Fp12 identity).

Because the op-cost and size limits are per input per transaction, spreading the work across many sequential transactions lets the total computation exceed any single transaction's budget. The costs are latency (one block-or-mempool hop per step), fees and dust per transaction, and the overhead of carrying state forward described below.

### The 128-byte state limit and the hashing workaround

An NFT commitment can store at most 128 bytes of local state. The Groth16 intermediate state is much larger than that: an Fp12 accumulator alone is 12 field elements (~384 bytes), plus the running G2 point, the loop counter, and the partial products.

The workaround (the standard one recommended in the CashScript limits docs) is to store only a `hash256` of the full state in the commitment (32 bytes), and pass the full state in the spending transaction:

1. The spender provides the full current state in the unlocking bytecode.
2. The contract checks `hash256(providedState)` equals the state hash stored in the input's NFT commitment, rejecting any tampered state.
3. The contract runs one chunk of work to produce `newState`.
4. The contract requires the next output's NFT commitment to equal `hash256(newState)`.

This keeps the (unbounded) working state off the commitment while still binding it on-chain through the hash.

### Sketch

```
// pseudo-code for a single computation step
function step(bytes providedState, ...chunkInputs) {
    // 1. validate incoming state against the stored commitment hash
    require(hash256(providedState) == tx.inputs[this.activeInputIndex].nftCommitment);

    // 2. perform one bounded chunk of the computation
    bytes newState = computeChunk(providedState, chunkInputs);

    // 3. commit to the outgoing state for the next step
    require(hash256(newState) == tx.outputs[0].nftCommitment);

    // 4. advance the step counter; on the final step, assert the result
    //    (e.g. the Fp12 pairing product equals the identity)
}
```

### Trade-offs

- The full state must be re-provided and re-hashed every step, costing bytes (toward the 10,000-byte unlocking limit) and hashing budget.
- Steps are strictly sequential because each depends on the previous state, so this approach cannot be parallelised.
- More steps means more transactions, more fees, and more latency. The chunk size per step should be tuned to use as much of each transaction's op-cost budget as possible while staying under the limits.

### Possible future relief: base instruction cost reduction

A reduction of the [base instruction cost](https://github.com/bitjson/bch-vm-limits#base-instruction-cost) from `100` to `10`, which has been proposed before and may happen in a future upgrade, would lower the flat per-opcode component of op-cost by 10x. The relief for this workload is real but modest, not the ~10x that suggests: the base component is a small share of a field operation's cost (a measured `OP_MUL` + `OP_MOD` over the BN256 prime is ~3,800 op-cost, only ~700 of it base instructions; the rest is operand-length-dependent big-number arithmetic the change does not touch). So it would help the cheap glue opcodes (stack shuffling, `OP_PICK`/`OP_ROLL`, F_p¹² state management) more than the field multiplications that dominate the budget.

## Why keep the singleton: the unchunked ideal

The repo keeps a single-transaction verifier (`singleton/`, benchmarked as `bch-groth16-singleton`) even though it cannot run on BCH. Its bytecode now fits under the 10,000-byte script cap (8,145 B), but it needs about 96 inputs' worth of op-cost budget (771M), so it is not deployable. It is kept on purpose, for two reasons.

First, it is the simplest expression of the verifier. One contract computes `vk_x` on-chain, runs the four pairings, and asserts the product is the F_p¹² identity, with none of the chaining workarounds the chunked version needs: no `hash256` state hand-off between transactions, no per-chunk function prologues, no zero-padding to buy budget, no step counter. That makes it the readable algorithmic reference, and the correctness oracle the chunked steps are graded against.

Second, it anchors what the chunking actually costs. Comparing the two plain BN254 benchmark entries (`results.json`, 2026-10-17):

| | singleton | chunked (covenant chain) |
|---|---|---|
| bytes | 8,145 | 239,773 |
| total op-cost | ~771M | ~183M |
| steps | 1 | 32 |

The gap is almost entirely bytes, not compute. The ~29x byte blow-up is the chunking tax: about 29 % of the chunked total is zero-padding that buys each input's op-cost budget (`(41 + len) * 800`), and most of the rest is per-chunk code re-shipped in every independent transaction plus the re-provided, re-hashed state and transaction skeletons. The intra-tx and residue constructions in [verifiers.md](verifiers.md) cut that tax sharply (down to 35,143 B in 5 inputs), which is where the project's effort has gone since.

One caveat on the op-cost numbers. The chunked total is far *lower* than the singleton's, so the singleton is not the op-cost floor the chunks improve on. The chunked builds use a different algorithm (a prepared, batched Miller loop with the fixed `e(alpha, beta)` and VK lines baked in, lazy reduction), while the plain singleton stays the direct, readable reference and is compiled for bytes. The op-cost-optimised single-script reference is `bch-groth16-singleton-minop` (~65M op). Read the plain singleton as the byte floor and the algorithmic reference, not as the op-cost floor.

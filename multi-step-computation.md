# Breaking Up Computation Across Multiple Steps

A full Groth16 verifier (or any heavy computation) will not fit within a single input's op-cost budget or the 10,000-byte unlocking bytecode limit (see [BCH Shortcomings](README.md#bch-shortcomings)). The work has to be split into smaller pieces. There are two axes to consider: across the inputs of one transaction, and across a sequence of transactions.

## Across inputs of one transaction (not viable for shared computation)

Each input is validated independently, and its script runs in isolation. Introspection lets an input inspect other inputs' and outputs' fields (value, locking bytecode, token category, NFT commitment, and so on), but there is no mechanism to pass arbitrary intermediate computation results (the VM stack of one input) into another input's execution.

This means you cannot shard one computation's running state across sibling inputs and recombine the partial results. Each input must be a self-contained check. Independent checks can run in parallel inputs (each gets its own op-cost budget), but they cannot cooperate on a single running value.

## Across transactions (the viable pattern)

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

The number of steps needed is driven by how much computation fits in one input's op-cost budget, and that budget is largely spent on the flat per-opcode base instruction cost (the verifier executes a very large number of cheap field-arithmetic opcodes). A reduction of the [base instruction cost](https://github.com/bitjson/bch-vm-limits#base-instruction-cost) from `100` to `10`, which has been proposed before and may happen in a future upgrade, would lower the cost of each opcode by roughly 10x. Each input would then afford about 10x more computation for the same script length, so a given computation would need less padding to buy its budget and could be split into fewer steps.

# BN254 densless verifier: 33,077 bytes

This source package reproduces the fixed deployment VK/tag used by the
`bch-groth16-intratx-pairfold5-densless` challenge entry. It reduces its current
33,179-byte challenge score by 102 bytes (32,902 serialized spending bytes).
The public-only witness producer accepts the public VK, proof and public inputs;
it does not use proving-key or trusted-setup secrets.

The recovered symbolic emitter includes terminal identifier compaction and a
bijection of the shared module's 25 IDs to 0..24, ordered by static CALL count
and original ID as tie-breaker. Function order and arithmetic bodies stay the
same. Derived offsets and commitments follow the emitted program lengths.
This is fixed-deployment source recovery, not recovery of the historical
compiler or a general arbitrary-VK compiler.

## Reproduce

From this directory, using Node 25.5.0 and pnpm 10.12.2:

```sh
pnpm install --frozen-lockfile --ignore-scripts
node export.mjs output.json
```

The export regenerates all 25 input pairs for the five supplied proofs. Direct
registry dependencies are locked: Libauth 3.1.0-next.8, Noble curves 2.2.0.
No CashScript compiler checkout is needed.

## Validation and scope

The unchanged official harness scores 33,077 bytes and 19,470,286 operation
cost, with four tested binding seams and none unbound. Five positive and nine
negative complete transactions pass their expected outcomes in current BCH2026
and speculative BCH_SPEC, each in consensus and standard modes (56 whole
transactions, 280 input evaluations). Exact native-tested bytes are preserved.
Native base-100 costs are 19,484,171 consensus / 19,550,731 standard, including
13,885 DEFINE-body storage omitted by the pinned Libauth accounting.

Independent transformation and package reviews passed for this bounded scope.
Fiat-Shamir, cofactor-equivalence and supplied-corpus qualifications remain;
universal soundness/resource closure and arbitrary-VK emission are not proved.
Synthetic stateless checks do not establish live mempool or network admission.

AI-assisted research and implementation: GPT-6 Astra, directed by Kallisti.

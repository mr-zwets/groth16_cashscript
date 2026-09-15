# Reconstructed BN254 PairFold-5 peval-fuse verifier

This source reconstructs the published 39,691-byte deployment and optimizes it to 36,836 score bytes across five inputs in one standard transaction. Committed operation cost falls from 30,460,315 to 27,895,539. The deployed public VK/tag and declared verification semantics remain unchanged.

`build.mjs` assembles the symbolic source directly using Libauth 3.1.0-next.8. It reads no compiled artifact or witness. Static calls use named functions; the three dynamic invoke sites remain explicit. `build()` returns programs, declarations, shared fragments, five redeems/lockings and the layout. The shared program is 4,349 bytes; the common worker loader is 85 bytes. Quotient partitions are 2,419/1,440/2,221 bytes with no suffix or padding. Their complete concatenation is unchanged and is parsed only after reconstruction.

Run `node chunked/bn254/leader-recovered/build.mjs output.json` to export the programs. `produceTransaction(vk, proof, publicInputs)` in `transaction.mjs` generates all five locking/unlocking pairs from public inputs, using Noble curves 2.2.0. The included `public-fixtures.json` contains only the public VK and five proof/input pairs from the official benchmark. Neither generator consumes setup scalars, imported witnesses or stored challenges.

The changes remove redundant stack copies, specialize a fixed 64P square bias, relocate quotient bytes to replace padding, and remove the empty worker padding argument. Worker commitments derive from the emitted programs. Transcript order, quotient order, proof/public-input binding and worker authentication are preserved.

Validation covers five public-only generations, fourteen complete quotient streams, nine negative-vector migrations, fifty native strict input evaluations, ten whole transactions, typecheck and unchanged official native/spec gates. Independent bounded reviews include 138 loader controls. Minimum observed standard-operation slack is 249; corpus coverage is not a universal resource theorem.

The generator retains finite-point/nonzero-denominator requirements and explicitly rejects unsupported degeneracies. The original CashScript/compiler lineage and deployment-tag derivation remain unrecovered. No universal soundness or exceptional-input completeness claim is added. Source reconstruction baseline: `0dd246a5328fcfdd48e60017d3b5bcc012d05ff5`; final experiment: `3ade0b5c980890622ee0dfc77eec33a1104da0da`; benchmark experiment: `3f4775f7cfbfa98a5773802bd7657cb530a40c9e`.

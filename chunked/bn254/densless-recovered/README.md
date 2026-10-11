# BN254 densless verifier: 33,036 bytes

This source package reproduces the fixed deployment VK/tag used by the
`bch-groth16-intratx-pairfold5-densless` challenge entry. It reduces the
current 33,179-byte challenge score by 143 bytes (32,861 serialized spending
bytes), a 35-byte improvement over the reviewed 33,071-byte package
(32,896 serialized spending bytes).
The public-only witness producer accepts the public VK, proof and public inputs;
it does not use proving-key or trusted-setup secrets.

The recovered symbolic emitter includes terminal identifier compaction and a
bijection of the shared module's 25 IDs to 0..24, ordered by static CALL count
and original ID as tie-breaker. Retained function order and arithmetic bodies stay the
same. The duplicate three-byte genesis helper at ID 10 is removed and its 19 calls
reuse identical helper ID 2. The genesis factor candidate adds helper ID 30 for
22 exact five-byte `OP_PICK OP_MOD OP_OVER OP_7 OP_MUL` sites, saving 35
integrated bytes after the helper frame and DEFINE body are accounted for. All
remaining IDs, including the two dynamic call sites, retain their values.
Genesis shrinks from 4,043 to 4,008 bytes. Derived offsets and commitments
follow the emitted program lengths. This is fixed-deployment source recovery,
not recovery of the historical compiler or a general arbitrary-VK compiler.

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

The unchanged official harness scores this candidate at 33,036 bytes and
19,473,867 modeled operation cost, with four tested binding seams and none
unbound. Five positive and nine negative complete transactions pass their
expected outcomes in current BCH2026 and speculative BCH_SPEC, each in
consensus and standard modes (56 whole transactions, 280 input evaluations).
Exact candidate bytes are preserved.

Separate native resource evidence records base-100 costs of 19,487,754
consensus / 19,554,186 standard, including a 13,887 DEFINE-body storage charge
omitted by pinned Libauth accounting. These are resource-accounting results,
not execution-time measurements. Absolute cached VerifyScript wall time and
VMLA-relative verification time remain unmeasured for this candidate.

The opcost work is experimental: it compares modeled Libauth accounting with
separate native resource accounting to inform future VM schedule research. It
does not recommend a schedule change. Fiat-Shamir, cofactor-equivalence and
supplied-corpus qualifications remain; universal soundness/resource closure
and arbitrary-VK emission are not proved. Synthetic stateless checks do not
establish live mempool or network admission.

Historical AI-assisted source recovery: GPT-6 Astra, directed by Kallisti.

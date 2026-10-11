# BN254 densless verifier: 33,016 bytes

This source package is a fixed-deployment BCH-native BN254 Groth16 verifier
candidate. It reduces the current 33,179-byte challenge score by 163 bytes
(32,841 serialized spending bytes), and improves the reviewed 33,036-byte
candidate by 20 bytes (32,861 to 32,841 serialized spending bytes). The
public-only witness producer accepts the public VK, proof and public inputs;
it does not use proving-key or trusted-setup secrets.

The recovered symbolic emitter preserves the published verifier's fixed
module boundaries, dynamic stack-selected IDs and public runtime proofs. This
candidate introduces helper 33, which factors ten exact six-byte terminal
subsequences and reduces the terminal program from 3,452 to 3,432 bytes after
its frame and DEFINE body. The first four input roots remain unchanged;
the terminal locking root changes with the candidate. This is fixed-deployment
source recovery, not recovery of the historical compiler or a general
arbitrary-VK compiler.

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

The unchanged official harness scores this candidate at 33,016 bytes and
19,476,020 modeled operation cost, with four tested binding seams and none
unbound. Five positive and nine negative complete transactions pass their
expected outcomes in current BCH2026 and speculative BCH_SPEC, each in
consensus and standard modes (56 whole transactions, 280 scheduled per-input evaluator invocations).
These are fixed-corpus results; they do not establish universal soundness,
full-node admission or live network behavior.

Separate native resource evidence records base-100 costs of 19,489,913
consensus / 19,556,217 standard, including a 13,893 DEFINE-body storage charge
omitted by pinned Libauth accounting. The native 0.184062-second value is a
whole-process diagnostic, not VerifyScript time. Absolute cached VerifyScript
wall time and VMLA-relative verification time remain unmeasured for this
candidate, so no timing comparison or opcost optimum is claimed.

The opcost work is experimental: it compares modeled Libauth accounting with
separate native resource accounting to inform future VM schedule research.
It does not recommend a schedule change. Fiat-Shamir, cofactor-equivalence
and supplied-corpus qualifications remain; arbitrary-VK emission and broader
resource closure remain open research questions.

Historical AI-assisted source recovery: GPT-6 Astra, directed by Kallisti;
subsequent publication assistance by Codex.

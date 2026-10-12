# BN254 densless verifier: terminal-factor candidate 33,003

This is a fixed-deployment BCH-native BN254 Groth16 source candidate derived
from the reviewed 33,016 frontier. It adds `terminalSubsequenceB` (ID 34),
whose body is `OP_PICK OP_MOD OP_OVER OP_7 OP_MUL`, at eleven terminal sites.
The generated terminal redeem is 3,419 bytes, down from 3,432; the first four
lockings and authenticated worker-root inputs remain unchanged. The terminal
tail is `0x20 || root32 || 0x88`; the generated tail is the authority for the
exact 32-byte worker root.

The challenge score is 176 bytes below the published 33,179-byte deployment.
The latest reduction is 13 bytes relative to the reviewed 33,016 candidate;
matched supplied positive transactions add 2,457 native operation-cost units.

The supplied public-only corpus and fixed public VK are retained. This is
experimental source recovery; it does not claim historical compiler recovery,
arbitrary-VK emission, universal soundness, full-node admission, live network
acceptance, or an op-cost schedule recommendation.

## Reproduce

From this directory, using Node 25.5.0 and pnpm 10.12.2:

```sh
pnpm install --frozen-lockfile --ignore-scripts
node build.mjs generated-programs.json
node export.mjs source-export.json
```

The export regenerates the five supplied public fixtures. Direct registry
dependencies remain locked: Libauth 3.1.0-next.8 and Noble curves 2.2.0. No
CashScript compiler checkout is needed.

## Validation and scope

The reviewed Libauth controls report 32,768 script bytes, a 33,003 challenge
score, 32,828 serialized spending bytes, and 19,478,472 modeled operation cost.
The unchanged owning benchmark
records 56 primary and 16 binding current/spec whole-transaction contexts,
360 explicit `evaluatePair` input evaluations, and 72 separate `vm.verify`
calls. The corpus has five positive, five ordinary-negative and four
invalid-input run groups per current/spec mode. These fixed-corpus controls do
not establish universal soundness or full-node admission.

The separate finite B100 native gate observed canonical costs of 19,492,370
consensus and 19,558,674 standard across 36 current-mode contexts, accepting 10 and
rejecting 26. It observed 122 input evaluations against 180 scheduled inputs;
the minimum accepted-input budget margin was 30,978. Source-derived DEFINE
body storage adds 13,898 native accounting units, matching the observed
consensus native-minus-model difference under the pinned charging rule.
These are finite synthetic resource
results, not a full-node or live-network admission claim.

Selected canonical base-100 cached VerifyScript wall time is now measured on a
shared M4 Max: standard median 3.589056 ms (3.563547–3.815732), consensus
3.588507 ms (3.524997–3.826565), across four counterbalanced processes.
Matched annual and accepted bare-multisig relative metrics, absolute reference
denominators, setup and process times are reported in
[benchmark PR36](https://github.com/mr-zwets/zk-verifier-bench/pull/36).
Paired 33,003/33,016 ratio ranges cross 1 in both modes; no consistent speedup
or regression was established. The native resource gate's whole-process
diagnostic is not verification time. Op-cost work remains experimental and
does not recommend changing a schedule or establish VM memory or full-stock
performance.

Historical AI-assisted source recovery: GPT-6 Astra, directed by Kallisti;
subsequent publication assistance by Codex. The fixed public deployment,
Fiat-Shamir, cofactor-equivalence and supplied-corpus qualifications remain;
broader resource closure remains open research.

# BN254 densless verifier: public-offset candidate 32,774

This fixed-deployment BCH-native BN254 Groth16 candidate reduces the shared
program and updates its dependent slice offsets and P2SH32 commitments. It
retains the public-only witness producer and fixed public verification key.
Relative to the reviewed 33,003 source, executable changes are confined to
`constants.mjs`, `shared.mjs` and `terminal.mjs`; the third fragment shrinks
from 810 to 581 bytes. The shared/executor and terminal locking commitments
change. The genesis locking remains unchanged. Updated locking scripts require
matching deployment outputs; this package does not assume existing funded coins.

The challenge score is **32,774**, comprising 32,539 script bytes and 235 bytes
of challenge transaction overhead. The canonical serialized spending transaction
is **32,599 bytes**, with five inputs. The 175 bytes of spent locking scripts
count toward the challenge score but are not serialized in the spending transaction.
This saves 229 bytes against 33,003 and 405 against the published 33,179 deployment.
Canonical modeled operation cost increases by 223,694 to 19,702,166.

## Reproduce

From this directory, using the pinned package environment (Node 25.5.0 and
pnpm 10.12.2):

```sh
pnpm install --frozen-lockfile --ignore-scripts
node build.mjs generated-programs.json
node export.mjs source-export.json
```

The export regenerates five supplied public fixtures. Direct registry dependencies
remain locked: Libauth 3.1.0-next.8 and Noble curves 2.2.0. No historical CashScript
compiler checkout is required. Benchmark labels and checkpoints come from the
owning benchmark corpus; the source export contains transaction bytecode only.

## Validation and limits

The completed Z4 package review covers eight actual commands: both source
builds, both exports, expanded functional controls, official scoring, and owner
and adapter typechecks. Candidate-only supplied Libauth controls cover 72 whole
transaction contexts across current/spec consensus/standard modes: 20 accepted
positives and 52 expected rejects, including 16 manual proof-splice rejects.
There are 360 scheduled per-input evaluations. Both candidate and baseline
together comprise 144 contexts and 720 scheduled per-input evaluations. These
counts do not imply that rejected transactions execute every body successfully.
Official current/spec controls report correctness, standardness and BCH
compatibility, four supplied proof checks, five ordinary-negative groups,
four isolated invalid-input groups and four cross-stage binding seams.

The exact package uses synthetic five-input transactions with zero-hash outpoints,
1,000-satoshi source outputs, sequence zero, and one 1,000-satoshi OP_RETURN output.
These are library/script controls, not funded full-node, mempool or live-network
admission.

A separate completed B100 native replay review covers 36 contexts per variant
(10 accepted positives and 26 expected rejects), with 122 observed input records
against 180 scheduled inputs per variant. Failed transactions stop early.
Canonical candidate native cost is 19,715,377 consensus and 19,780,145 standard;
matched increases over 33,003 are 223,007 and 221,471 respectively. The minimum
accepted standard input budget margin is 30,978. These are native script-resource
controls in synthetic transactions, not full-node standardness or live admission.
All five actual gate jobs exited zero. The frozen aggregate remains FAIL because
its postprocessor indexed a dictionary as a list; independent offline correction
validated the same raw outputs without rerunning native jobs. No standalone
DEFINE-storage or VM-memory conclusion is inferred from the cost difference.

Cached VerifyScript timing for 32,774 is unmeasured. Measurements from 33,003 or earlier
sources must not be transferred to these changed bytes.

Op-cost research is experimental. The methodology requires measured absolute
VerifyScript times and per-spending-byte costs, matched VMLA annual and accepted
1-of-3 bare-multisig reference ratios and absolute denominators, repeated paired
schedule comparisons, and separate setup/process times. Actual VM-attributable
memory needs its own attribution controls; process RSS is not a substitute.
No schedule change, worst-case ceiling or optimum is recommended here.

Historical AI-assisted source recovery: **GPT-6 Astra**, directed by Kallisti;
subsequent source, research and publication assistance by Codex. This fixed
public deployment does not recover the historical compiler or arbitrary-VK
emission, prove universal soundness, or close the remaining Fiat-Shamir,
cofactor-equivalence, whole-verifier and adversarial resource obligations.

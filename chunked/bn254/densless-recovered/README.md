# BN254 densless verifier: bounded-slice candidate 32,507

This fixed-deployment BCH-native BN254 Groth16 verifier reconstructs the public
PairFold-5 densless artifact with public-only witness generation. Its shared
input reader returns the exact requested slice using two range-checked SPLIT
operations. The helper consumes length, offset and input index, preserves the
caller prefix and alternate stack, and returns only the slice.

The helper remains a range-checked 7-opcode-byte reader. This candidate's
function-ID remap exchanges IDs 25 and 7, saving 5 bytes from the prior 32,512
candidate. Shared fragments are 867, 982 and 559 bytes; input 2's fixed-table
and quotient payloads begin at offsets 3427 and 4358. Both consumers use these
relocated cursors. The inherited fragment-reader loader uses a distinct
function identifier and the build checks for identifier collisions.

The shared program is 2,408 bytes. Executor redeems remain 79 bytes, genesis
4,008 bytes and terminal 3,366 bytes. Reproduction regenerates the executor and
terminal locking commitments together. The public verification key, public
witness semantics and proof/context checks remain fixed.

The completed finite package scores **32,507**: 32,272 script bytes plus 235
challenge-overhead bytes, with five inputs and 32,332 canonical serialized
spending bytes. Each supplied positive spending transaction is 5 bytes smaller than its
corresponding baseline transaction; the canonical baseline was 32,337 bytes. The challenge includes 175 bytes of spent locking
scripts, which are distinct from spending-transaction serialization.

## Reproduce

From this directory, using the pinned package environment:

```sh
pnpm install --frozen-lockfile --ignore-scripts
node build.mjs generated-programs.json
node export.mjs source-export.json
```

The export regenerates five supplied public fixtures. Registry dependencies are
locked in `pnpm-lock.yaml`; benchmark labels and checkpoints belong to the
companion corpus. Deployment outputs must match the regenerated locking scripts.

## Validation and limits

Matched baseline/candidate checks cover 144 whole-transaction contexts across
current/spec consensus/standard, including 40 accepted and 104 rejected
contexts, with 720 scheduled input evaluations. The official proof suite has
4/4 proof-generality checks plus a separate worst-case proof, 5 generic
negative cases, 4 point-negative cases, 4 binding seams, and 2 typechecks.
Equivalent helper behavior assumes sufficient execution resources; internal
failure diagnostics and resource-limit acceptance may differ.

Native current-rule replay covers 36 contexts per variant: 10 accepted and 26
rejected, with 122 actual input calls. The two-variant native package covers 72
contexts, 20 accepted and 52 rejected, with 244 actual input calls. Libauth
modeled cost is 20,024,168; canonical native costs are 20,036,281 consensus
and 20,099,769 standard. The minimum accepted input margins are
44,564 and 30,996. These are finite synthetic verifier checks. The fixed
deployment vector payload contains the tested positive and negative scenarios;
this package still does not claim full-node or public-network admission. Historical compiler recovery,
arbitrary-VK emission, universal soundness, Fiat-Shamir and cofactor-equivalence
obligations remain outside this package.

Historical AI-assisted source recovery: **GPT-6 Astra**, directed by Kallisti;
current source and publication assistance: **GPT-6.1 Sol**, directed by Kallisti.

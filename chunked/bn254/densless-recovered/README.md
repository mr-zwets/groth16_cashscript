# BN254 densless verifier: low-ID bounded-slice candidate 32,457

> **Withdrawn (2026-10-26).** The densless author has withdrawn the full-verifier soundness
> claims for the submitted densless constructions ([#28 reply](https://github.com/mr-zwets/groth16_cashscript/issues/28), [#32](https://github.com/mr-zwets/groth16_cashscript/issues/32) F6,
> [zk-verifier-bench#49](https://github.com/mr-zwets/zk-verifier-bench/issues/49)): the shared `millerEvent` consumes slopes without the
> tangent/chord equations, the terminal's carried-R predicate compares a value with itself
> instead of checking the B endpoint, and line/root values are not bound to the committed state.
> No end-to-end false acceptance is claimed. Do not treat this verifier as sound. For a sound
> BN254 design see [`../sound-si-gls`](../sound-si-gls/README.md).

This fixed-deployment BCH-native BN254 Groth16 verifier reconstructs the public
PairFold-5 densless artifact with public-only witness generation. Its shared
input reader returns the exact requested slice using two range-checked SPLIT
operations. The helper consumes length, offset and input index, preserves the
caller prefix and alternate stack, and returns only the slice.

The helper remains a range-checked 7-opcode-byte reader. This candidate remaps
genesis sequence IDs 19→8, 20→11 and 25→10, saving 7, 3 and 5 bytes (15 total)
from the prior 32,472 candidate. Function references follow their existing owners.
Shared fragments remain 867, 982 and 559 bytes; input 2's fixed-table and quotient
payload cursors are 3427 and 4358. The local namespaces and regenerated locking
commitments retain the fixed deployment's proof/context checks.

The integrated candidate script is 32,222 bytes and the canonical serialized
spending transaction is 32,282 bytes (five inputs and 235 bytes of challenge
overhead). Reproduction regenerates all five locking commitments together. The
public verification key, public witness semantics and proof/context checks remain
fixed.

The completed finite package scores **32,457**: 32,222 script bytes plus 235
challenge-overhead bytes, with five inputs and 32,282 canonical serialized
spending bytes. The candidate is 15 bytes smaller than the prior 32,472 source
package; this is a finite measured package result, not a universal size claim. The challenge includes 175 bytes of spent locking scripts, which are
distinct from spending-transaction serialization.

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
modeled cost is 20,023,512; canonical native costs are 20,035,625 consensus
and 20,099,113 standard. The minimum accepted input margins are
14,202 consensus and 634 standard (input 3). These are finite synthetic verifier checks. The fixed
deployment vector payload contains the tested positive and negative scenarios;
this package still does not claim full-node or public-network admission. The
historical 152-evaluation helper controls are inherited, not fresh runs of this
candidate. Historical compiler recovery,
arbitrary-VK emission, universal soundness, Fiat-Shamir and cofactor-equivalence
obligations remain outside this package.

Historical AI-assisted source recovery: **GPT-6 Astra**, directed by Kallisti;
current source and publication assistance: **GPT-6.1 Sol**, directed by Kallisti.

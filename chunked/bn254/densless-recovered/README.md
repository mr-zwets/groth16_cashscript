# BN254 densless verifier: shared-loader candidate 32,529

This fixed-deployment BCH-native BN254 Groth16 candidate factors the three
repeated fragment extractions in the selected 32,547 executor into one local
helper. Only `build.mjs` and `loader.mjs` change executable source. The helper's
function identifier is the byte string `81`, emitted using `OP_1NEGATE`; it is
distinct from the shared program's existing identifiers. The build checks for
identifier collisions. The helper preserves the alternate stack and returns
the selected fragment prefix.

Each of the first three executor redeems decreases from 85 to 79 bytes.
Genesis remains byte-for-byte unchanged. The terminal keeps its length but
binds the new worker-locking root, so the regenerated executor and terminal
locking scripts must be deployed together. The fixed public verification key,
public-witness semantics and fragment partition remain unchanged.

The completed package produces a challenge score of **32,529**: 32,294 script
bytes plus 235 challenge-overhead bytes, with five inputs and 32,354 canonical
serialized spending bytes. All five supplied spending transactions are 18
bytes smaller than the 32,547 deployment. The challenge score includes the
175 bytes of spent locking scripts; these are distinct from spending-transaction
serialization.

## Reproduce

From this directory, using the pinned package environment:

```sh
pnpm install --frozen-lockfile --ignore-scripts
node build.mjs generated-programs.json
node export.mjs source-export.json
```

The export regenerates five supplied public fixtures. Registry dependencies are
locked in `pnpm-lock.yaml`; benchmark labels and checkpoints belong to the
companion benchmark corpus. Updated locking scripts require matching deployment
outputs and do not assume existing funded coins.

## Validation and limits

The finite package checks cover 144 whole-transaction contexts across
current/spec consensus/standard, including positive and negative supplied
fixtures, isolated input validation and binding seams. Native current-rules
replay covers 36 contexts per variant: 10 accepted and 26 rejected. Rejected
transactions may stop before later inputs, so 122 observed inputs are not 180
executed inputs. These synthetic controls establish the recorded finite result;
they do not establish full-node, mempool, live-network, universal-witness, or
whole-block admission. Historical compiler recovery and arbitrary-VK emission,
universal soundness, Fiat-Shamir and cofactor-equivalence obligations also
remain outside this source package.

Historical AI-assisted source recovery: **GPT-6 Astra**, directed by Kallisti;
current source and publication assistance: **GPT-6.1 Sol**, directed by Kallisti.

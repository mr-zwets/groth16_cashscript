# BN254 densless verifier: public-offset base-field helper candidate 32,547

This fixed-deployment BCH-native BN254 Groth16 candidate preserves the selected
32,774 public-only verifier and replaces repeated `NUM BASE_FIELD` sequences in
the shared and terminal programs with one positive-ID helper. The source change
is confined to `constants.mjs`, `shared.mjs`, and `terminal.mjs`; `genesis.mjs`
remains byte-for-byte identical to the selected baseline. Regenerated deployment
outputs must be used together: the helper changes shared, terminal, and their
P2SH32 commitments while preserving the fixed public verification key and
public-witness semantics.

The reviewed package produces a challenge score of **32,547**: 32,312 script
bytes plus 235 challenge-overhead bytes, and 32,372 canonical serialized
spending bytes. This is 227 bytes smaller than the selected 32,774 deployment
and 632 bytes below the published 33,179 deployment. The completed native
review records candidate costs of 20,111,940 consensus and 20,175,812 standard,
with minimum accepted input margins of 44,546 consensus and 30,978 standard in
the supplied corpus.

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

The completed finite package and native reviews cover current/spec
consensus/standard controls, positive and negative supplied fixtures, isolated
input validation, binding seams, and 36 native contexts per variant. The native
corpus contains 10 accepted and 26 rejected contexts per variant; rejected
transactions may stop before later inputs, so 122 observed inputs are not 180
executed inputs. These synthetic controls establish the recorded finite result;
they do not establish full-node, mempool, live-network, universal-witness, or
whole-block admission. Historical compiler recovery and arbitrary-VK emission,
universal soundness, Fiat-Shamir and cofactor-equivalence obligations also
remain outside this source package.

Historical AI-assisted source recovery: **GPT-6 Astra**, directed by Kallisti;
current source and publication assistance: **GPT-6.1 Sol**, directed by Kallisti.

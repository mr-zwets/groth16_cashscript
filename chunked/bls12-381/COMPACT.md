# Compact BLS12-381 records

The compact layout replaces each zero public-input window's 704-byte table
record with its authenticated 32-byte root. Runtime canonical scalar bytes
determine each record length. Worker parsing, predecessor extraction and
Coordinator commitment framing use those same lengths; shortening happens
before commitment and challenge construction.

The committed challenge score is **70,009**, versus **79,948** for the existing
fixed layout. Six of ten supplied fixtures shrink and four grow. The largest
supplied score is **90,169** (89,399 serialized spending bytes). Keep the fixed
entry as a Pareto alternative. This uses the current base-100 opcode schedule.

## Reproduction

The recorded replay used Node 25.5.0, Libauth 3.1.0-next.8, Noble curves 2.2.0,
and the existing sibling CashScript compiler at revision
`1c707c1dbf87396b30ba5e0704b1db44475ce893`. Its cashc dist entrypoint SHA256 was
`2ebf0b95e78a2b7dc12c4778a1ee2fcac258aa3244d9f3a6871d8000b2b3e6fc`.
This was an existing-runtime replay, not an independently rebuilt compiler or
a fresh-install certification. Use the repository's dependency/compiler setup.

From the repository root, with the existing GT cache
`bls-gt-merkle-w8-position-regular-projective-v1.json` (SHA256
`79f150d0090db38e04270d4091b9944c29a0d2bddf249fb910f6947ecd4db0a8`):

```sh
RPA_GT_CACHE="$PWD/bls-gt-merkle-w8-position-regular-projective-v1.json" \
RPA_CORPUS_RESULT="$PWD/compact-full-results.json" \
RPA_RESOURCE_EXPORT="$PWD/compact-resource-bytecodes.json" \
RPA_INVERSES=off RPA_SKIP_GAMMA=1 RPA_PIC32=1 RPA_PIC_LAYOUT=regular \
RPA_TEMPLATE_RUN=1 RPA_Q_TAIL_COEFFICIENTS=22 \
RPA_TEMPLATE_FACTOR_DENSITY_PADDING=0 RPA_TEMPLATE_TAIL_DENSITY_PADDING=0 \
RPA_TEMPLATE_TERMINAL_DENSITY_PADDING=0 RPA_COORDINATOR_DENSITY_PADDING=0 \
RPA_PIC_BLOCK2_DENSITY_PADDING=80 RPA_PIC_BLOCK4_DENSITY_PADDING=0 \
RPA_REGULAR_DENSITY_PADDING='{}' \
RPA_COMPACT_REGULAR_DENSITY_PADDING='{"3":444,"5":432,"6":423,"7":431,"8":413,"9":421,"10":423,"11":431,"12":423,"13":431,"14":433,"16":419,"17":428,"18":430,"19":438}' \
node chunked/bls12-381/run_full_multiproof.mjs
```

Generator SHA256:
`1d218a27133d198c348b8757171ff0575d9082250b1a574c447e5790665721b2`.
The recorded 220-pair resource export SHA256 is
`f0ef961d062c6bc065878fdb2e21446320ac8db57b32a8a1c709d4a212fa713a`.

## Validation and scope

All ten source fixtures regenerate the exact 220 locking/unlocking pairs.
The source runner records 540 rejection cases per VM mode, including auxiliary
PIC cases; these are not 540 distinct production-proof attacks. The benchmark
passes all 22 negative fixtures and nine additional proof checks. Its actual
BCH_SPEC whole-transaction replay accepts ten positives and rejects 22
negatives in each of consensus and standard mode (64 calls, 1,408 separate
input diagnostics). Synthetic stateless checks do not establish live mempool,
fee-policy or chain-state admission.

Native accounting includes an additional 99,480 DEFINE-body storage charge
omitted by the pinned Libauth accounting. The supplied-corpus native resource
checks and independent package review passed within their bounded scope.
Universal input-5 helper `OP_INVOKE 0x65` composition, arbitrary-witness
producer/resource bounds and whole-graph proof remain incomplete. Fiat-Shamir
PIT, cofactor-equivalence and input-validation qualifications remain in force.

AI-assisted research and implementation: GPT-6 Astra, directed by Kallisti.

# Compact BLS12-381 records

The compact layout replaces each zero public-input window's 704-byte table
record with its authenticated 32-byte root. Runtime canonical scalar bytes
determine each record length. Worker parsing, predecessor extraction and
Coordinator commitment framing use those same lengths; shortening happens
before commitment and challenge construction.

The current candidate challenge score is **69,947**, versus **79,948** for the
existing fixed layout and 62 fewer score bytes than the prior compact candidate.
Six of ten supplied fixtures shrink and four grow. The largest supplied score is
**90,107** (89,337 serialized spending bytes). Keep the fixed entry as a Pareto
alternative. This uses the current base-100 opcode schedule. The candidate
remaps exactly three template identifiers: `101 -> 16`, `117 -> 15`, and
`104 -> -1`; identifiers 102 and 103 are unchanged. This is a finite candidate
record, not a universal resource or deployment claim.

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

Candidate generator SHA256 (an export pin, not a Git revision):
`7d21a55fbab9146ba62bf97321e2160e047524189041ee7c809311b7affad691`.
The candidate 220-pair resource export SHA256 is
`e7ad9eaaab5cbc1cc29427098a6e7184a9efbbcbfeb43515175295c97d820d28`.
The candidate length-prefixed locking-set SHA256 is
`1db77c2b7c6a0c6a39979cf5aaac5838abe766c4785ecbc4080ca395d264649e`.

## Validation and scope

All ten source fixtures regenerate the exact 220 locking/unlocking pairs.
The source runner records 540 mutation cases per BCH2026 consensus/standard
mode; these are source/Libauth checks, not 540 native rejections. The separate
native gate covers 64 contexts: 20 accepted and 44 rejected across 566 actual
calls. The candidate benchmark passes all 22 negative fixtures and all 9/9
proof-generality checks. The separate supplied worst-case fixture also passes.
Synthetic stateless checks do not establish live
mempool, fee-policy or chain-state admission.

For this candidate, native-minus-Libauth DEFINE-body accounting is 99,442
operation-cost units per mode (`42,779,223 - 42,679,781` and
`42,969,175 - 42,869,733`). The prior baseline's 99,480-unit figure remains
historical and is not overwritten by this
candidate. The supplied-corpus native resource checks and independent package
review passed within their bounded scope.
Universal input-5 helper `OP_INVOKE 0x10` (historically `0x65`) composition, arbitrary-witness
producer/resource bounds and whole-graph proof remain incomplete. Fiat-Shamir
PIT, cofactor-equivalence and input-validation qualifications remain in force.

AI-assisted research and implementation: GPT-6.1 Sol, directed by Kallisti; prior historical source credits GPT-6 Astra.

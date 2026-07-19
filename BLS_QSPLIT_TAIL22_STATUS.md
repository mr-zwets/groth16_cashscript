# BLS12-381 qsplit tail-22 — latest-main integration

Benchmark entry name: `bch-groth16-bls12381-intratx-fs` (intra-tx packing +
Fiat-Shamir polynomial-identity checking). Listed in
[verifiers.md](verifiers.md) under its own security-model category; "qsplit
tail-22" remains the internal build codename used by the sources and artifact
files below.

This source integration is based on
`6a309f506f87ef584165b9d3ae4c0ec6d66ad56f`; the frozen hashes below pin the
reviewed candidate artifacts.

## Claim

This construction performs the complete two-public-input BLS12-381 Groth16
pairing check in one transaction that passes the current BCH consensus and
standard relay virtual machines.

| Measurement | Result |
| --- | ---: |
| Inputs | 22 |
| Spending transaction wire bytes | 89,553 |
| P2SH32 locking bytes | 770 |
| Challenge score | **90,323** |
| Script bytes | 89,357 |
| Serialization overhead | 196 |
| Relay margin | 10,447 bytes |
| Maximum consensus opcost across ten fixtures | 69,798,359 |
| Maximum standard opcost across ten fixtures | 70,171,351 |
| Maximum consensus input opcost | 6,733,184 |
| Maximum standard input opcost | 6,737,920 |
| Maximum redeem bytecode | 5,071 bytes |
| Maximum unlocking bytecode | 8,406 bytes |
| Minimum measured input density margin | 4,744 |

The score is `89,553 + 22 * 35 = 90,323`. Current BCH operation-cost
density is checked per input. Every input passes the standard VM; the aggregate
opcost is retained as a comparison measurement.

## Integration boundary

The existing shared BLS generators keep their NAF defaults. The qsplit source
opts into separate binary/direct8 exports:

- `QSPLIT_ATE_LOOP_DIGITS`
- `qsplitSinglePairMiller` and `qsplitMillerBatchOps`
- `qsplitMillerFusedOps` and `qsplitMillerFusedAffineDirect8Ops`
- `qsplitPairsFor`, including a qsplit-local zero-safe public-input MSM

The shared compile functions accept optional compiler settings while preserving
their existing settings when no option is supplied. No existing generator is
implicitly switched to the qsplit arithmetic path.

For the coordinator and block-20 programs, the PIC helper loader retains the
already redeem-relative block-4 carrier with `OP_DUP`. After authentication, the
same carrier supplies the fixed-blob slice. This removes a duplicate
`OP_INPUTBYTECODE`/length-normalization sequence without changing the authenticated
source input, slice boundaries, function definition, or fixed blob.

## Construction and binding

The transaction enforces

```text
e(-A, B) * e(alpha, beta) * e(vk_x, gamma) * e(C, delta) = 1
vk_x = IC0 + input0*IC1 + input1*IC2
```

The coordinator commits to all 21 sibling locking programs. The transaction-wide
transcript binds the proof and public inputs, each Miller-block payload, the fixed
program graph, and the public-verification-key contribution.

The logical q132 quotient is one transcript leaf carried as a fixed
110-coefficient head and 22-coefficient tail. The owning programs enforce exact
lengths, order, root, recurrence, and the terminal residue relation, so all 132
coefficients are evaluated once.

The fixed Miller and authenticated GT data are derived from the public
verification-key points. The repository's published synthetic VK scalar
relations are used only by `syntheticFixture` to mint equation-valid benchmark
fixtures; locking-program compilation and PIC table generation consume only the
public VK points. No proof value, private witness, or setup secret is embedded in
the locking programs. All ten fixtures share one locking set with SHA-256
`4cd6f93829da3708513aa61d408c0b2bd4bba851ba31abefaad573b82c1d0284`.

In the SHA-256 random-oracle model, the 24 pre-beta relations give a beta
cancellation degree of at most 23, and the alpha identity has degree at most
137. The construction's conservative union bound is `160/(2^256-1)`, which is less
than `161/2^256`.

`B` is checked on-curve and in the order-r G2 subgroup using the psi relation and
the affine tangent/chord denominator guards. `A` and `C` are canonical on-curve
G1 points, and the pairing equation binds their prime-order projections.
Cofactor-equivalent G1 encodings remain equivalent for this pairing verdict, so
this construction does not claim a separate unique-G1-encoding grade.

## Reproduced evidence

The strict runner requires exactly ten distinct equation-valid benchmark
fixtures minted with the repository's published synthetic VK scalars:

```text
committed, proof1, dense, zero, max, msm-identity, b-identity,
a-identity, c-identity, all-identity
```

For every shape, all 22 inputs and the complete transaction pass both VMs, the
transaction is below 100,000 bytes at one satoshi per byte, and all 33 changed-field
checks produce the required non-accepting result. This is 10 complete valid
transactions plus 330 changed-field checks.

The proof-independent resource classifier derives ceilings from the exported
locking and unlocking bytecode for both top-level B classes:

| Resource branch | Minimum universal density margin |
| --- | ---: |
| B nonidentity | 219 |
| B identity | 95,753 |

The compiled-path G2 audit enumerates all 12 nonzero points in the order-13
subgroup. Every point reaches an affine addition-denominator guard, while the
ordinary G2 case completes the same fused affine/direct8 schedule and satisfies
the terminal psi relation. This audit does not rely on a projective Rz check.

The post-wording latest-main replay left the frozen results hash unchanged. The
resource export and benchmark-vector payloads changed only in their source and
resource provenance hashes; all locking, unlocking, valid-proof, worst-case, and
changed-field vector bytes remained identical.

## Reproduction

From this repository root:

```sh
RPA_CORPUS_RESULT=qsplit-tail22-final-results.json \
RPA_RESOURCE_EXPORT=qsplit-tail22-final-resource-bytecodes.json \
node chunked/bls12-381/run_full_multiproof.mjs

RESOURCE_PROFILE=qsplit22-tail22 \
RESOURCE_CORPUS_PATH=qsplit-tail22-final-resource-bytecodes.json \
RESOURCE_FIXTURE=committed \
RESOURCE_EXPECTED_CERTIFICATE_PATH=qsplit-tail22-final-committed-ceiling.json \
RESOURCE_RESULT_PATH=/tmp/qsplit-tail22-committed-ceiling-replay.json \
COMPACT=1 \
node chunked/bls12-381/prove_q132_pic_five_batch_resource_ceiling.mjs

RESOURCE_PROFILE=qsplit22-tail22 \
RESOURCE_CORPUS_PATH=qsplit-tail22-final-resource-bytecodes.json \
RESOURCE_FIXTURE=b-identity \
RESOURCE_EXPECTED_CERTIFICATE_PATH=qsplit-tail22-final-b-identity-ceiling.json \
RESOURCE_RESULT_PATH=/tmp/qsplit-tail22-b-identity-ceiling-replay.json \
COMPACT=1 \
node chunked/bls12-381/prove_q132_pic_five_batch_resource_ceiling.mjs

RPA_SUMMARY=1 node chunked/bls12-381/prove_rpa_two_chart_binary.mjs
node qsplit_soundness_audit.mjs
node qsplit_psi_degeneracy_test.mjs

QSPLIT_BENCHMARK_VECTOR_PATH=/tmp/qsplit-tail22-vectors.json \
node chunked/bls12-381/export_qsplit_tail22_benchmark_vectors.mjs
```

The compiler is `cashc` `0.14.0-next.1` from CashScript revision
`1c707c1dbf87396b30ba5e0704b1db44475ce893`; its built `dist/index.js`
hash is `2ebf0b95e78a2b7dc12c4778a1ee2fcac258aa3244d9f3a6871d8000b2b3e6fc`.

## Frozen hashes

| Artifact | SHA-256 |
| --- | --- |
| `qsplit-tail22-final-results.json` | `b10e514471c0f74131ce058b10c44105f1aca32ce15a82b6de8ad03ca772d5b4` |
| `qsplit-tail22-final-resource-bytecodes.json` | `254ee78bda438f4ec8589a30f1acd58a25b39fc10b156a37e9da8ca62db4b314` |
| `qsplit-tail22-final-committed-ceiling.json` | `37cf64c36211ab8c658a81f878bf26a046635a671fba0bdc1a65b008691aa30d` |
| `qsplit-tail22-final-b-identity-ceiling.json` | `2e11c53cceed95894d01ee194a43ad24c59f9b8cb86d30361c6a92537c2ec1d3` |
| `bls-gt-merkle-w8-position-regular-flat-v1.json` | `8544c835d36af1148a49f05f003e8a7c05b4f7ae645032774a0aa5f9ffb0f423` |
| `measure_d3_two_chart_binary.mjs` | `f0c15ed60d1507542f40ea392478693b7e7b8ded73a666313ee82e748602c46d` |
| `run_full_multiproof.mjs` | `a856f8c93bdfb981137b73a8ce1b07046c6ac2c447ec7524e0ec837b79bda988` |
| `prove_q132_pic_five_batch_resource_ceiling.mjs` | `11796ed73b89102a79d55bc323c9b75398f3352568fec3df499877a91c5e6a7e` |
| `_pairingmath.mjs` | `0c71d9cf21bba959df82f3bc7b3b0f9236b07aef2425645b04652cceb0863fc4` |
| `_residuemath.mjs` | `c8c536f2ff5e72ff3397e6b3295ca47a43af5ea520552f2253aef11ca1aae00a` |
| `_vkxmath.mjs` | `b81b6e7b0103b61d9002c29c1936a12d5e56fb20725ce9c087410895ac907d33` |
| `export_qsplit_tail22_benchmark_vectors.mjs` | `1d8a8eafe1219163191d12dedf0266aa7cd5bcbe5a26e1f3324bbd28dbf45236` |
| Generated latest-main benchmark vector | `9152db69265b2b15e8b5ef4720ecc6c6e3bcdf07a7847068e42a457d1692b102` |

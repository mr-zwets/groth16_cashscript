# BLS12-381 qsplit tail-22 — balanced six-host authentication

Benchmark entry name: `bch-groth16-bls12381-intratx-fs` (intra-tx packing +
Fiat-Shamir polynomial-identity checking). Listed in
[verifiers.md](verifiers.md) under its own security-model category; "qsplit
tail-22" remains the internal build codename used by the sources and artifact
files below.

This source integration is based on
`0cff585eff44571bcb6917e006ecdd65446fdfe0`; the frozen hashes below pin the
reviewed candidate artifacts.

## Claim

This construction performs the complete two-public-input BLS12-381 Groth16
pairing check in one transaction that passes the current BCH consensus and
standard relay virtual machines.

| Measurement | Result |
| --- | ---: |
| Inputs | 22 |
| Spending transaction wire bytes | 79,178 |
| P2SH32 locking bytes | 770 |
| Challenge score | **79,948** |
| Script bytes | 78,982 |
| Serialization overhead | 196 |
| Relay margin | 20,822 bytes |
| Maximum consensus opcost across ten fixtures | 55,081,462 |
| Maximum standard opcost across ten fixtures | 55,430,774 |
| Maximum consensus input opcost | 5,820,192 |
| Maximum standard input opcost | 5,822,857 |
| Maximum redeem bytecode | 2,857 bytes |
| Maximum unlocking bytecode | 8,399 bytes |
| Minimum measured input density margin | 40,456 |

The score is `79,178 + 22 * 35 = 79,948`. Current BCH operation-cost
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
`4d7e68150d02a5f170cb3845bd117fed6af903ad8cddce16a132a2d8d70e51b3`.

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
transaction is below 100,000 bytes at one satoshi per byte, and all 50 changed-field
checks produce the required non-accepting result. This is 10 complete valid
transactions plus 500 changed-field checks.

The proof-independent resource classifier derives ceilings from the exported
locking and unlocking bytecode for both top-level B classes:

| Resource branch | Minimum universal density margin |
| --- | ---: |
| B nonidentity | 23,838 |
| B identity | 122,142 |

The compiled-path G2 audit enumerates all 12 nonzero points in the order-13
subgroup. Every point reaches an affine addition-denominator guard, while the
ordinary G2 case completes the same fused affine/direct8 schedule and satisfies
the terminal psi relation. This audit does not rely on a projective Rz check.

The September 4 optimization fuses Horner and pair-update multiply/add reductions,
then postpones reduction in Fp2 multiplication/squaring, torus squaring, and line
evaluation until their complete integer polynomials have been evaluated. Added
multiples of P keep subtraction-derived terms nonnegative for canonical operands.
The existing `mAdd`, `mulFp`, and `mulAddFp` helpers accept these wide integer
arguments without narrowing and return canonical field values. Conservative
intermediate bounds are 96 VM bytes for Fp2 arithmetic, 128 for torus squaring,
and 144 for the collapsed line numerator; the unchanged interval engine
propagates those operand intervals through the helper calls.

PIC path traversal retains direct tuple reassignment. First, Regular, AdditionMiddle,
and Terminal import the identical 799-byte prefix containing 13 arithmetic
function definitions from the authenticated AdditionTail carrier. Source guards
pin its hash, sequential definition IDs, complete instruction boundaries, and
exact equality with every consumer's original prefix. Scoped prime reuse reduces
the common body to 823 bytes; the extra 257-byte body remains byte-identical at
its regenerated offsets.

The projective table encodes each contribution in four canonical Fp coordinates,
reducing each authenticated record from 800 to 704 bytes. Cache version 5 uses the
`BLSGTP1` domain and a public-VK-derived, inverse-free quadric map. The exact
scaled decoder and its universal nonzero/identity/chart arguments are documented
in [BLS_PROJECTIVE_GT_MATH.md](BLS_PROJECTIVE_GT_MATH.md). All 2,097,152 entries
pass canonical, projective-class and decoder differential checks. All 256 saved
record paths and all eight position-adjusted fixture replays pass.

The Regular worker reuses its existing alpha powers and `pairMulEval` helper.
The latter preserves the compiler call graph and the original shared arithmetic
prefix. At the projective-table step, the other four raw template cores remained
byte-identical to the preceding arithmetic candidate; the subsequent First change
is described below. The full schedule still requires at most 137 relation
degree and 132 quotient coefficients; transcript ordering and binding remain
unchanged despite the new authenticated payloads and roots.

First now evaluates the root polynomial once and negates the result canonically
with `mulFp(P-rootEval,1)`, including rootEval=0. Its first pair-multiplication
step is locally expanded with simultaneous-state semantics. These changes align
its compiler-discovered function IDs with the other templates, allowing it to
import the exact existing arithmetic prefix. Carrier layout runs before consumers
without changing template or transaction ordering. Existing slice, ID, complete
instruction-boundary and authentication guards remain intact.

Scoped prime reuse declares P once immediately before the canonical outU checks
and reuses it for the following outU/outR and first slope checks. Every original
canonical predicate remains exact. Independent restoration of the repeated literal
reproduces the previous CashScript source; the 799-byte arithmetic prefix
and extra 257-byte body remain unchanged. The common body is 823 bytes with independently checked
slice boundaries and source-pinned hash.

Six existing inputs now authenticate the public-input windows in contiguous
batches: inputs 0/1/2/3/16/21 own 6/4/5/6/6/5 windows starting at
0/6/10/15/21/27. Every window is checked exactly once. Record storage and transcript
ordering are unchanged. First imports the same authenticated helper 117 from
input 5 and consumes its success with OP_VERIFY before its existing arithmetic.
All six batch commitments retain domain, start/count and ordered-root framing.

Only the coordinator is compiled for size. Its B-identity check has a different
instruction schedule, so the resource certificate recognizes one exact encoded
branch and its four exact helper bodies, only at input 0 in explicitly named
six-host profiles. Unknown shapes still reject. The observed branch must match
the declared B class. Old profiles and the interval/cost propagation remain
unchanged. The balanced profile pins its own exact 22-input conditional inventory.
See [BLS_SIX_PIC_RESOURCE_MATH.md](BLS_SIX_PIC_RESOURCE_MATH.md) for the algebra,
stack preservation, helper bounds and profile derivation.

The factor/path helper now evaluates `record.split(192)` once with tuple
assignment, preserving both outputs and malformed-record rejection. Independent
review confirms the rest of the runtime source, full runner, and resource
classifier are unchanged from the frozen 79,955-byte candidate. This saves seven
score bytes and 64,421 committed consensus operation units.

All density padding is zero. The committed fixture uses 53,133,274 consensus
and 53,482,586 standard operation-cost units. The score is 79,948 bytes, saving
2,531 from the preceding 82,479-byte scoped-prime candidate and 10,375 from the
merged 90,323-byte baseline. It satisfies the strictly below-80,000-byte objective.
The first six-host partition needed padding; the final balanced partition uses
measured coordinator capacity to remove it without changing the input count.

Five retained First-specific mutation cases test its arithmetic carrier body, slice
start/end, function ID and source input. All 38 prior cases remain required, so
seven additional First PIC body/loader/path/factor cases bring the full runner
to 500 changed-field checks. All six authentication-host gates and all six
batch-commitment mutations are also required on every fixture. The wrong-count
mutation evaluates its actual modified batch owner. Independent review checks
canonical zero handling, exact algebra, loader ordering and branch semantics.

The 50 additional mutation checks retained from the shared-library candidate
exercise library bytes, slice start, slice end, function ID, and source input
across all ten fixtures. Independent nested-definition microtests establish VM
scoping with earlier libraries; this exact 799-byte, 13-definition prefix is
covered by the full integrated corpus and both resource certificates.

## Unchanged historical singleton variant (`bch-groth16-bls12381-singleton-fs`)

This independent variant was not regenerated by the September 4 optimization.
`chunked/bls12-381/measure_fs_singleton.mjs` emits the same construction as ONE
contract (single-script oracle, loosened BCH 2026 VM, same category as
`bch-groth16-bls12381-singleton-minop`): the Fiat-Shamir commitment roots and the
beta/alpha challenges are recomputed in-script over the witness blobs, the 32 PIC
GT-table Merkle authentications run inline against the baked window roots, and
the 21 Miller blocks chain through locals instead of cross-input reads. The
witness blobs belong to the historical six-coordinate transaction. The new
projective GT payloads described above were not integrated into this singleton.

| Measurement | Result |
| --- | ---: |
| Locking bytes | 61,147 |
| Unlocking bytes (witness pushes) | 63,005 |
| Maximum op-cost across the ten fixtures | 60,575,949 |
| Committed-fixture op-cost | 58,690,636 |
| Previous unconditional op-cost oracle (`-minop`) | 149.2M |

All ten fixtures produce one identical contract (proof-independent script), and
twelve changed-field mutations per fixture (statement, proof points, residue
root, slopes, chart outputs, PIC factor and path, quotient coefficient and
truncation, payload swap) are all rejected:

```sh
RPA_PROOF_FIXTURE=committed node chunked/bls12-381/measure_fs_singleton.mjs
```

`chunked/bls12-381/export_fs_singleton_vectors.mjs` runs the full corpus and
writes the zk-verifier-bench vector file
(`../verifier/src/bch/groth16-bls12381-singleton-fs-vectors.json`, sha256
`3421cd9e805e27d0bd2ae6513039f775b229489587fffc90033a86fceeca7f3e`).

## Reproduction

From this repository root, regenerate the public cache when required:

```sh
GT_CACHE_ENCODING=projective node --max-old-space-size=2048 \
  chunked/bls12-381/prove_gt_window_preimage.mjs
```

The committed cache is pinned below. Replay the verifier and its gates:

```sh
RPA_CORPUS_RESULT=qsplit-tail22-final-results.json \
RPA_RESOURCE_EXPORT=qsplit-tail22-final-resource-bytecodes.json \
node chunked/bls12-381/run_full_multiproof.mjs

RESOURCE_PROFILE=qsplit22-tail22-six-pic-balanced \
RESOURCE_CORPUS_PATH=qsplit-tail22-final-resource-bytecodes.json \
RESOURCE_FIXTURE=committed \
RESOURCE_EXPECTED_CERTIFICATE_PATH=qsplit-tail22-final-committed-ceiling.json \
RESOURCE_RESULT_PATH=/tmp/qsplit-tail22-committed-ceiling-replay.json \
COMPACT=1 \
node chunked/bls12-381/prove_q132_pic_five_batch_resource_ceiling.mjs

RESOURCE_PROFILE=qsplit22-tail22-six-pic-balanced \
RESOURCE_CORPUS_PATH=qsplit-tail22-final-resource-bytecodes.json \
RESOURCE_FIXTURE=b-identity \
RESOURCE_EXPECTED_CERTIFICATE_PATH=qsplit-tail22-final-b-identity-ceiling.json \
RESOURCE_RESULT_PATH=/tmp/qsplit-tail22-b-identity-ceiling-replay.json \
COMPACT=1 \
node chunked/bls12-381/prove_q132_pic_five_batch_resource_ceiling.mjs

RPA_SUMMARY=1 node chunked/bls12-381/prove_rpa_two_chart_binary.mjs
node qsplit_soundness_audit.mjs
node qsplit_psi_degeneracy_test.mjs
node chunked/bls12-381/prove_gt_projective_chart.mjs

QSPLIT_BENCHMARK_VECTOR_PATH=/tmp/qsplit-tail22-vectors.json \
node chunked/bls12-381/export_qsplit_tail22_benchmark_vectors.mjs
```

The compiler is `cashc` `0.14.0-next.1` from CashScript revision
`1c707c1dbf87396b30ba5e0704b1db44475ce893`; its built `dist/index.js`
hash is `2ebf0b95e78a2b7dc12c4778a1ee2fcac258aa3244d9f3a6871d8000b2b3e6fc`.

## Frozen hashes

| Artifact | SHA-256 |
| --- | --- |
| `qsplit-tail22-final-results.json` | `726c4fe4c4a37e38d3e1b50cd848e62761b33d8219f49c8a9e9d8f300e914817` |
| `qsplit-tail22-final-resource-bytecodes.json` | `d8195cb000a8488770a0cc9e038656e7bd3bbb68602d429abd3f7a68caa88ade` |
| `qsplit-tail22-final-committed-ceiling.json` | `88ce3f306fb1edf050b2e1bd6964a2467ee1cd389173b18da6f315a3d232c15f` |
| `qsplit-tail22-final-b-identity-ceiling.json` | `50b06949726628ea3187a7dcca5a76d7f428b540063b799ae9b6443f23b83b8d` |
| `bls-gt-merkle-w8-position-regular-projective-v1.json` | `79f150d0090db38e04270d4091b9944c29a0d2bddf249fb910f6947ecd4db0a8` |
| `chunked/bls12-381/measure_d3_two_chart_binary.mjs` | `83d2b28f27ead5a89e595a9a645492cb677f68f0f05c001f3a86d555d9860024` |
| `chunked/bls12-381/run_full_multiproof.mjs` | `9232393c0e9210262c2bc1dac2a20b9dc967a4ee10e7e4ddb72c920a41adb826` |
| `chunked/bls12-381/prove_gt_window_preimage.mjs` | `47d9325c765379e678a9049c28eb0413c4bf845e9f84159613e2f99035ff6665` |
| `chunked/bls12-381/prove_gt_projective_chart.mjs` | `fe86f33377740df6c94c6a53f192ed77c19284a5560957b19a4078ffb0d78a25` |
| `chunked/bls12-381/prove_q132_pic_five_batch_resource_ceiling.mjs` | `c696752158ba83700c38f0d66a84799b3e7ace78ba80fdfad1c10c5913903e80` |
| `chunked/bls12-381/_pairingmath.mjs` | `0c71d9cf21bba959df82f3bc7b3b0f9236b07aef2425645b04652cceb0863fc4` |
| `chunked/bls12-381/_residuemath.mjs` | `c8c536f2ff5e72ff3397e6b3295ca47a43af5ea520552f2253aef11ca1aae00a` |
| `chunked/bls12-381/_vkxmath.mjs` | `b81b6e7b0103b61d9002c29c1936a12d5e56fb20725ce9c087410895ac907d33` |
| `chunked/bls12-381/export_qsplit_tail22_benchmark_vectors.mjs` | `294d325d91289889d28c4c3ba4c0f297fd737380f8f730685da5ecf10bd43b5a` |
| Generated benchmark vector | `29eb23671ad67baf8951123490b1f0c2771857c7b0cacd74b7f4076cb43e9f7a` |
| `BLS_SIX_PIC_RESOURCE_MATH.md` | `c0a423c0c6868889a8120725d72359b75cf4f0a654f1712857acd718d39d9928` |

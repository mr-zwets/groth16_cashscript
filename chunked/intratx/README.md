# Intra-transaction linked chunks (the single-transaction verifier)

A second way to chunk the Groth16 verifier, alternative to the sequential
NFT-commitment covenant in [`../pairing`](../pairing) and [`../bls12-381`](../bls12-381).

## The idea

Where the covenant method (`../pairing`, `../bls12-381`) hands state forward through a
token NFT commitment across a chain of transactions, this lays the **whole computation
out as the inputs of ONE transaction**. A script can read its siblings' witnesses by
introspection (`OP_INPUTBYTECODE` = `tx.inputs[i].unlockingBytecode`), so a chunk passes
its result to the next by having the next chunk read it — no state token, no hashing,
intermediate values any size:

```
chunk i:   take inBlob (incoming state) in the witness
           recompute outgoing state
           require( outgoing == tx.inputs[i+1].unlockingBytecode[front slice] )   // forward-check
chunk i+1: take inBlob (== chunk i's outgoing) in the witness, ...
```

That `require` is the "verify `arg01 == arg10`" from the design discussion. The first
chunk of a stage is genesis (nothing binds its input); the last asserts the verdict
(`finalExp == 1`). Cross-stage links are bound where byte layouts line up: **vk_x** into
the Miller genesis input, the **Miller boundary** into the final-exp genesis input.

The quotient-torus verifier additionally treats input 0 as the graph root. The root requires exactly
11 inputs, and every nonterminal program pins its immediate successor's complete P2SH32 locking
bytecode at `activeInputIndex + 1`: inputs 2, 3, 5, and 6 use direct byte equality, while the remaining
edges pin its SHA-256. If the root were at index `j`, those ten pinned hops require `j + 10 < 11`,
so `j = 0` and every successor position follows. The final three
programs retain logically redundant position gates because public cashc compiles them smaller.
`OP_INPUTBYTECODE` binds each state handoff. Spending the designated input-0 UTXO enforces the
complete graph; an isolated suffix UTXO does not establish the omitted prefix.

Each input still fits one BCH budget (op-cost ≤ 8,032,800, script ≤ 10,000 B). The plain and BLS
graphs reuse the covenant chunks verbatim; the BN254 quotient-torus graph instead specializes its
arithmetic for the linked layout. In either case, every chunk is an input of one transaction instead
of one of many sequential transactions, with no per-step hashing and no 128-byte state cap. The
plain graphs remain larger non-standard transactions. The optimized BN254 quotient-torus graph is
11 inputs: the committed, alternate, density, resource, and all 11 identity/special fixtures are
standard and fund the default 1 sat/byte relay fee. The committed proof is 88,393 serialized bytes,
and the proof-independent resource certificate constructs a 96,909-byte relayable encoding for
every valid proof, leaving 3,091 bytes below the standard transaction limit. The
BLS12-381 quotient-torus graph is 34 inputs in one current-BCH consensus-valid 195,705-byte
transaction, non-standard only by total size.

The BN254 programs evaluate the complete four-pair equation and consume the proof and two public
inputs at runtime. The prescribed checkpoint key is nevertheless synthetic: its setup and IC
scalars are published. The BN254 measurements therefore establish equation execution, runtime
witness handling, and BCH resource validity for that key, not circuit knowledge, secure binding of
the public-input vector, or interoperability with an independently generated setup. Regenerating
the construction for a circuit-derived key requires new bytecode and a fresh resource certificate.

### P2SH deployment

The op-cost budget counts only the unlocking: `(41 + scriptSig length) × 800`. Deploying
each chunk as **P2SH** (the default; `INTRATX_BARE=1` for bare) puts the ~4–5 KB redeem in
the scriptSig, where it counts toward that budget instead of needing an equal-sized pad on
top — ~27–30% fewer on-chain bytes, and the forward-check is unaffected (`inBlob` is still
the first scriptSig push). This is a general lever, so the covenant chunks would shrink the
same amount.

## Large scripts: targeting the proposed `bch-spec` VM

Two variants target the **proposed `bch-spec` upgrade** instead of current BCH:
`build_vectors_residue_large.mjs` (BN254 → `bch-groth16-intratx-residue-large`) and
`build_vectors_residue_bls_large.mjs` (BLS12-381 → `bch-groth16-bls12381-intratx-residue-large`).
Both use the same forward-checking mechanism as the 10 kB builds. The BN254 build uses a
dedicated 128-position GLV schedule and a flatter Miller/verdict layout rather than simply
re-planning the 11-input graph; the BLS build keeps its residue graph under the larger per-input
budget. They are
graded against libauth's `createVirtualMachineBchSpec`, are **not valid on current BCH**
(`createVirtualMachineBch2026`), and the harness marks them `vm: 'bch-spec'` and files
them in their own leaderboard category, separate from the current-BCH frontier.

```
node build_vectors_residue_large.mjs       # BN254 -> groth16-intratx-residue-large-vectors.json
node build_vectors_residue_bls_large.mjs   # BLS   -> groth16-bls12381-intratx-residue-large-vectors.json
```

Each spawns the stage generators at the 100 kB budget (`BCH_VM=spec TARGET_UNLOCK=100000
OP_COST_TARGET=… BYTE_BUDGET=…`), assembles the single tx, and self-verifies on the spec VM. **They
leave `../{pairing,bls12-381}/generated/` at the 100 kB budget — regenerate the default 10 kB chunks
before rebuilding any flagship build** (the commands are printed at the end of each run).

### What `bch-spec` changes (and what it does not)

`ConsensusBchSpec = { ...ConsensusBch2026, ...overrides }`; the overrides are only these five, plus
two new opcodes (`OP_EVAL` = script-from-stack evaluation, `OP_POW` = exponentiation — we use neither
yet; both are open levers):

| setting | 2026 | bch-spec | governs |
|---|---|---|---|
| `densityControlBaseLength` | 41 | 10,000 | the per-input **budget** floor (see freebie below) |
| `maximumBytecodeLength` | 10,000 | 100,000 | max script size (locking and unlocking) |
| `maximumStackItemLength` | 10,000 | 100,000 | max size of one stack element |
| `maximumStandardUnlockingBytecodeLength` | 10,000 | 100,000 | standardness |
| `maximumVmNumberByteLength` | 10,000 | 100,000 | max big-int size |

Crucially, **no op-cost coefficient changes.** The spend formula is identical to 2025/2026 —

```
operationCost =  instructionCount × 100 (baseInstructionCost)
              +  sigChecks        × 26,000
              +  hashIterations   × 192 (standard) / 64 (consensus)
              +  arithmeticCost
              +  stackPushedBytes  (1 per byte)
```

— and the byte→budget rate `operationCostBudgetPerByte = 800` is unchanged. A given script spends the
**exact same** op-cost on spec as on current BCH; the ~250M-op verifier is ~250M either way. Only the
size *limits* grow and the budget *floor* grows.

### The density-base freebie → input-count vs bytes (the main consideration)

The per-input budget is `(densityControlBaseLength + unlockingLen) × 800`. On spec the base is 10,000,
so **every input is handed `10,000 × 800 = 8,000,000` op for free** (zero pad). That freebie drives
the central trade-off for spec-targeting verifiers:

- Total op is fixed (~250M). The pad bytes you must write are only the op you buy *beyond* the free
  allowances: `pad ≈ (totalOp − N × 8M) / 800 = totalOp/800 − N × 10,000` (N = number of inputs).
- **Each input you add is worth one freebie ≈ 10,000 fewer pad bytes.** So on spec, *more* inputs =
  *fewer* bytes; *fewer/fatter* inputs = *more* bytes.

That relationship holds when the arithmetic and layout stay fixed. The current two-input BN254
spec build also changes the scalar schedule and flattens the verifier layout, so its 72,201-byte
transaction is smaller than the 88,393-byte current-BCH construction despite using fewer inputs.
It remains a result in the separate proposed-VM category, not evidence that larger scripts make
operations cheaper. Within one fixed layout, `FUSE_FINAL` and `FUSE_TAIL` still trade each removed
input's 8M budget allowance for roughly 10 kB of additional pad, so compare alternatives using their
measured score rather than input count alone.

### The introspection read is ~free, and pad is not double-counted

A forward-check reads the *next* input's whole unlocking via `OP_INPUTBYTECODE`, which pushes it onto
the stack, so the `stackPushedBytes` term charges the reader **1 op per byte** read. But those same
bytes *grant* the sibling **800 op** of budget — an **800 : 1** ratio: reading a ~90 kB sibling costs
~90k op out of an ~84M budget (~0.1%). And there is **no byte double-count**: the pad is serialized in
the transaction once; introspection copies it to the evaluation stack at runtime, adding no on-chain
bytes (the score counts each pad byte once). Note that budget-buying pad *must* sit in the unlocking —
the op-cost budget counts only the scriptSig, not the locking — so it is unavoidably on the
introspected side; there is no placement (redeem, locking, …) that buys budget while hiding from a
sibling's forward-check.

### Standardness

Standardness is measured for each complete transaction. The BN254 spec fixture is 72,201 bytes and
passes the proposed VM's standard-policy checks. The BLS spec fixture is 164,474 bytes and exceeds
the 100,000-byte standard transaction limit. Among current-BCH intra-tx bundles, the optimized
BN254 quotient-torus verifier has a certified 96,909-byte proof-independent relay encoding, while
the 195,705-byte BLS quotient-torus transaction is non-standard by total size.

## Files

- `transform.mjs` — rewrites a covenant chunk (`../{pairing,bls12-381}/generated/*.cash`)
  into a linked chunk: the `covIn` hash check becomes `split` the `inBlob` into int
  limbs; the `covOut` commitment becomes rebuild the outgoing blob + the forward-check.
  The arithmetic body in between is reused verbatim. Curve-agnostic (`W` = limb width).
- `build_vectors.mjs` — BN254: assembles the Miller boundary (`bch-pairing-intratx`) and
  the full verifier (`bch-groth16-intratx`) into one-transaction vectors, evaluates every
  input on the real BCH 2026 VM, and writes `verifier/src/bch/{pairing,groth16}-intratx-vectors.json`.
- `build_vectors_bls.mjs` — BLS12-381 counterpart (`bch-pairing-bls12381-intratx`,
  `bch-groth16-bls12381-intratx`); the full track uses five stage-bound GLV vk_x inputs
  sharing one hash-bound VK table, 48-byte limbs, and an uncommitted easy-part inverse.
- `build_vectors_residue.mjs` / `build_vectors_residue_bls.mjs` — the residue-optimized chunk graph
  (GLV `vk_x` + fused Miller + residue verdict) assembled as one tx under the current-BCH 10 kB
  budget (`bch-groth16-intratx-residue`, `bch-groth16-bls12381-intratx-residue`). Their opt-in
  quotient modes carry six-limb classes in `Fp12*/Fp6*` and fuse the verdict into Miller.
- `../pairing/prove_vkx_glv_split.mjs` / `../pairing/prove_vkx_glv_resource_bound.mjs` — prove the
  grouped 3x43 MSM/table construction and its proof-independent equal-point event bound.
- `../pairing/prove_projective_vkx.mjs` / `../pairing/prove_miller_unit_lines.mjs` — prove the
  universal nonzero-Y projective handoff and the identity-complete normalized G1 representation.
- `../pairing/prove_miller_affine_raw.mjs` — differentially replays every runtime-G2 affine step
  against the field formulas and proves the unreduced integer intermediates remain below `8p^2`.
  The pipeline also compiles direct CashScript probes and executes both raw kernels on consensus
  and standard BCH VMs. The quotient-torus generator calls separately named raw kernels; the
  canonical affine kernels remain unchanged for the singleton-minop compiler schedule.
- `infinity_fixtures.mjs` — constructs every combination of identity A, B, and C, plus finite-B
  and runtime-MSM-identity disambiguation fixtures, under the same verification key.
- `prove_miller_intrinsic_ceiling.mjs` / `prove_resource_ceiling.mjs` — shadow the generated Miller
  bytecode, derive proof-independent intrinsic ceilings, solve the exact linked-input density
  fixed point, and verify both maximal envelopes on the standard BCH2026 VM.
- `../../singleton/bn254/test_fp12sqr_differential.mjs` and `../pairing/prove_miller_torus.mjs` —
  differentially check the signed square and short signed Frobenius formulas used by the hot path.
- `build_vectors_residue_large.mjs` / `build_vectors_residue_bls_large.mjs` — the same residue graph
  sized to 100 kB inputs for the proposed `bch-spec` VM (see "Large scripts" above);
  `bch-groth16-intratx-residue-large`, `bch-groth16-bls12381-intratx-residue-large`.

Run (after the corresponding `../{pairing,bls12-381}` generators have populated
`generated/`; the BN254 plain builders require the STAGE-BOUND layouts, so regenerate
`gen_g2check.mjs` and `gen_miller.mjs` with `STAGE_BOUND_LAYOUT=1` first):

```
STAGE_BOUND_LAYOUT=1 node ../pairing/gen_g2check.mjs
STAGE_BOUND_LAYOUT=1 node ../pairing/gen_miller.mjs
node build_vectors.mjs       # BN254  -> pairing-intratx + groth16-intratx vectors
node build_vectors_bls.mjs   # BLS    -> pairing-bls12381-intratx + groth16-bls12381-intratx
```

To reproduce the current-BCH BN254 residue vectors from the repository root, point
`VERIFIER_DIR` at a `zk-verifier-bench` checkout and generate the measured linked layouts before
assembling either deployment. The optimized quotient builder regenerates two grouped 3x43 GLV
inputs; the other builders retain their own measured manifests.

```
export VERIFIER_DIR=/absolute/path/to/zk-verifier-bench
STAGE_BOUND_LAYOUT=1 G2_LINKED_LAYOUT=1 node chunked/pairing/gen_g2check.mjs
STAGE_BOUND_LAYOUT=1 MILLER_LINKED_LAYOUT=1 node chunked/pairing/gen_miller_residue.mjs
node chunked/intratx/build_vectors_residue.mjs
node chunked/grouped/build_vectors_residue.mjs
```

The quotient-torus frontier has a separate deterministic entry point. It selects projective
`vk_x` internally (no hidden mode flag), enables the endpoint, affine-G2, unit-line, stage-bound,
covenant-residue, and linked layouts together, and uses the frozen measured cuts. The command runs
the grouped-GLV/table/event proofs, affine and normalized-line proofs, integer-bound analysis,
signed-square differential, endpoint and quotient/Frobenius proofs, projective handoff proof,
whole-transaction mutation suite, Miller shadow, and proof-independent relay certificate. It refuses
to write vectors unless the committed, alternate, density, and asymmetric-resource full-valid
transactions pass both whole current-BCH consensus and standard-policy VMs.

```
VERIFIER_DIR=/absolute/path/to/zk-verifier-bench pnpm vectors:intratx:torus
```

The generated verifier uses 11 inputs. Exact full-valid serialized transaction measurements are
88,393 bytes / 68,471,632 op-cost for the committed proof, 88,413 / 68,330,611 for the alternate
proof, 96,124 / 76,325,460 for the all-lanes density proof, and 96,199 / 76,381,586 for the
asymmetric resource fixture. The 11 identity/special fixtures range from 83,812 to 93,120 bytes.
All are consensus-valid, standard, and fund the default 1 sat/byte relay fee.

Three byte metrics are intentionally kept distinct. The benchmark CLI's script total is the
sum of locking and unlocking programs (88,285 for the committed proof). The serialized transaction
is 88,393 bytes because it contains the unlockings and transaction framing, but not the spent
outputs. The verifier.cash on-chain score is 88,778 bytes: serialized transaction bytes plus the
11 × 35-byte spent P2SH32 locking programs.

The concrete fixtures are regression evidence, not the proof-independent claim:
`prove_resource_ceiling.mjs` separately constructs a 96,909-serialized-byte relayable encoding for
every valid proof, with a 77,166,796-op-cost ceiling and 3,091 bytes below the 100,000-byte standard
transaction limit. The two componentwise-maximal GLV event allocations are checked on the standard
BCH2026 VM, and the certificate refuses a changed locking graph, compiler schedule, or lookup table.
The existing unused padding arguments can be enlarged within per-input limits, so this is an
existence result for a uniform relayable encoding rather than a maximum over all accepted byte strings.

The BLS12-381 quotient frontier has the same proof-before-write workflow and a separate opt-in
entry point; the unflagged BLS commands continue to generate the legacy Fp6-tail construction.

```
VERIFIER_DIR=/absolute/path/to/zk-verifier-bench pnpm vectors:intratx:torus:bls
```

It produces 34 inputs, 195,413 script bytes, 153,091,714 total op-cost, and a 195,705-byte
serialized transaction. The committed, alternate, and dense fixtures all pass current-BCH
consensus; each is non-standard only because the full transaction exceeds 100,000 bytes.

## Harness support

The benchmark harness (`verifier`) gained a `Step.intraTx { index, inputs }` context: a
step is one input of a shared multi-input transaction, evaluated against a tx built from
every input's `(locking, unlocking)` so its `tx.inputs[idx±1]` introspection resolves to
the real siblings (see `verifier/src/harness/vm.ts`). The four entries are classified
`structure: 'single-tx'` (they are one transaction) and run runtime-general (one fixed
set of input scripts verifies multiple proofs) with invalid runs that corrupt one input's
blob (the predecessor's forward-check then fails).

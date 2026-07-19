# The Verifiers — a Map

This repo now holds a whole family of Groth16 verifiers, not one. They vary along four
axes; this doc is the map. Individual folders have the authoritative per-verifier detail
(see the links); this page is the index and the "which one is which".

## The four axes

1. **Curve** — **BN254** (alt_bn128, Ethereum's pairing precompile curve) or
   **BLS12-381** (the curve the nChain reference uses, so the benchmark compares on the
   same curve).
2. **Form** — **singleton** (the whole verifier in one contract; a correctness *oracle*,
   exceeds BCH per-input limits, not deployable) or **chunked** (the same computation
   split so every piece fits one BCH input; the *deployable* form). See
   [singleton/README.md](singleton/README.md) and [chunked/README.md](chunked/README.md).
3. **Optimisation variant** — **baseline** (the direct, auditable reference) or
   **op-optimized** (`minop` for singletons / **residue** for chunked): the same result
   computed with far less on-chain work by moving cost to *witnesses the contract checks*
   (a `c^λ == …` residue in place of the hard-part final exponentiation, GLV `vk_x`,
   baked VK pairing lines, on-chain-G2 only for the one runtime pair).
4. **Packing method** (chunked only) — **covenant chain** (state rides an NFT commitment
   across a chain of txs), **intra-tx linked** (the whole verifier as the inputs of *one*
   tx, chunks forward-checking each other's unlocking bytecode), or **grouped** (the
   sweet spot: intra-tx *within* a tx, NFT hand-off *across* a handful of standard txs).

## BN254 verifiers

| entry | form / variant | headline | notes |
|---|---|---|---|
| `bch-groth16-singleton` | singleton, baseline | ~14.4 KB source; size-scored recompile **8,874 B** | correctness oracle; over per-input limits |
| `bch-groth16-singleton-minop` | singleton, op-optimized | ~58.8 KB / **~74.2M op-cost** | quotient-torus residue + affine GLV; still single-input (oracle) |
| `bch-groth16-chunked` | chunked, covenant chain | **43 inputs / 331,856 B / 261.42M op** | NFT-commitment chain |
| `bch-groth16-chunked-covenant-residue` | chunked, quotient-torus covenant chain | **12 tx / 93,938 B score / 93,936 B wire / 69.89M op** | standard-relayable measured fixture suite; token-bound state thread |
| `bch-groth16-intratx` | chunked, intra-tx linked | **42 inputs / 330,580 B / 262.68M op** | whole verifier in one (non-standard) tx |
| `bch-groth16-grouped` | chunked, grouped | **42 inputs / 330,628 B score / 261.50M op** | standard-relayable in 5 txs |
| `bch-groth16-intratx-residue` | chunked, intra-tx + quotient-torus residue | **11 inputs / 86,950 B score / 86,565 B wire / 68.49M op** | current-BCH standard; smallest current-BCH full verifier in this benchmark |
| `bch-groth16-grouped-residue` | chunked, grouped + residue | **26 inputs / 224,830 B / 179.59M op** | standard-relayable in 3 txs |
| `bch-groth16-intratx-residue-large` | chunked, intra-tx + quotient-torus residue, **`bch-spec`** | **4 inputs / 58,823 B score / 58,683 B wire / 68.32M op** | proposed-VM-only; passes its standard-policy model; own leaderboard category — see [Target VM](#target-vm-bch-spec) |
| `bch-pairing-chunked` | chunked pairing-only, covenant | **20 inputs / 175,788 B / 138.94M op**; score **178,368** | Miller-boundary milestone |
| `bch-pairing-intratx` | chunked pairing-only, intra-tx | **20 inputs / 174,134 B / 138.80M op**; score **175,014** | Miller-boundary milestone |
| `bch-vkx-chunked-covenant` | chunked `vk_x`-only | **8 inputs / 11,306 B / 7.07M op** | the G1 MSM checkpoint (see `chunked/shamir/`, `chunked/twoloop/`) |

Headline values are the current committed-proof benchmark totals after `rescheduleStacks`;
lower is better.

## BLS12-381 verifiers

Same curve as the nChain reference, so these give a true apples-to-apples size
comparison. Per-layer status and build commands are in
[singleton/bls12-381/README.md](singleton/bls12-381/README.md).

| entry | form / variant | headline | notes |
|---|---|---|---|
| `bch-groth16-bls12381-singleton` | singleton, baseline | ~24.2 KB / ~1.04–1.48B op-cost | **~21× smaller bytecode than the nChain reference** |
| `bch-groth16-bls12381-singleton-minop` | singleton, op-optimized | 58,345 B / **149.2M op-cost** | quotient torus (`λ=p+|x|`, 6-limb root u) + GLV; fused G2 ψ-check; A/C on-curve (G1 subgroup checks omitted) |
| `bch-groth16-bls12381-singleton-fs` | singleton, **Fiat-Shamir PIT** | 61,147 B locking / **60.58M worst-case op-cost** | single-script qsplit tail-22 (`chunked/bls12-381/measure_fs_singleton.mjs`); ten-fixture corpus, one proof-independent script; separate security model — see [Fiat-Shamir model](#security-model-fiat-shamir-pit) |
| `bch-pairing-bls12381-singleton` | singleton, pairing-only | ~19.8 KB / ~1.38B op-cost | the pairing verdict milestone (`verify.cash`) |
| `bch-groth16-bls12381-intratx-residue` | chunked, intra-tx + quotient-torus residue | **24 inputs / 193,369 B score / 192,529 B wire / 151.43M op** | one current-consensus-valid transaction; non-standard only by total size |
| `bch-groth16-bls12381-grouped-residue` | chunked, grouped + quotient-torus residue | **26 inputs / 3 standard tx / 205,734 B score / 204,894 B wire / 160.95M op** | current-policy grouped BLS verifier; exact successor pins and mutable-NFT state thread |
| `bch-groth16-bls12381-intratx-residue-large` | chunked, intra-tx + residue, **`bch-spec`** | **3 inputs / 164,579 B score / 164,474 B wire / 149.81M op** | proposed-VM-only; non-standard by total transaction size — see [Target VM](#target-vm-bch-spec) |
| `bch-groth16-bls12381-intratx-fs` | chunked, intra-tx + residue + **Fiat-Shamir PIT** | **22 inputs / 1 standard tx / 90,323 B score / 89,553 B wire / 69.80M op** | first single-standard-tx full verifier; separate security model — see [Fiat-Shamir model](#security-model-fiat-shamir-pit) |

The BLS chunked pairing/Miller/final-exp families also exist in
[chunked/bls12-381/](chunked/bls12-381/) (plain and residue generators); the
grouped-residue packing above is the assembled full-verifier deployment.

## Security model (Fiat-Shamir PIT)

Every other entry is an **unconditional algebraic certificate**: the script computes the
field arithmetic exactly, so acceptance is equivalent to the Groth16 pairing equation with
no extra assumptions. The `-fs` entries — `bch-groth16-bls12381-intratx-fs` (the deployable
22-input transaction) and `bch-groth16-bls12381-singleton-fs` (the same construction in one
script, the FS-family op-cost oracle on the loosened VM) — instead share this model.
`bch-groth16-bls12381-intratx-fs` (source and frozen artifacts:
[BLS_QSPLIT_TAIL22_STATUS.md](BLS_QSPLIT_TAIL22_STATUS.md), internal codename
"qsplit tail-22") instead verifies the Fp6/torus multiplication relations by
**polynomial identity testing at a SHA-256-derived Fiat-Shamir point**: Fp6 values are
committed as degree-5 polynomials, the per-block relations are batched by a challenge
`beta` and checked at a challenge `alpha` against one prover-supplied 132-coefficient
quotient, and the coordinator re-derives both challenges on-chain from Merkle roots over
the transaction's own payloads. The G2 walk, slope checks, ψ terminal relation, and the
`λ=p+|x|` residue terminal stay exact. Consequences, disclosed in its status doc:

- Soundness is computational, in the SHA-256 random-oracle model, with a stated union
  bound below `161/2^256` per spend attempt — STARK-class, but a **new assumption** the
  unconditional entries do not make. It is therefore filed under this separate name
  rather than as a successor to `-intratx-residue` / `-grouped-residue`.
- A and C are graded **cofactor-equivalent**: on-curve is enforced and the pairing verdict
  binds their prime-order projections, but unlike `-singleton-minop`'s ψ/φ subgroup
  checks, alternate cofactor encodings of the same valid proof also spend. No
  unique-G1-encoding grade is claimed.
- The `e(vk_x, γ)` pair is served from a **2,097,152-entry public-VK-derived GT table**
  (window-8 over the two public-input byte pairs), Merkle-committed in the locking
  programs; per-VK preprocessing regenerates ~1.2 GB of table data
  (`chunked/bls12-381/prove_gt_window_preimage.mjs`, deterministic, VK points only).

## Target VM (`bch-spec`)

Most entries target **current BCH** (libauth `createVirtualMachineBch2026`, 10 kB scripts). Two —
`bch-groth16-intratx-residue-large` and `bch-groth16-bls12381-intratx-residue-large` — instead target
the **proposed `bch-spec` upgrade** (`createVirtualMachineBchSpec`). The harness marks them
`vm: 'bch-spec'` and files them in their own leaderboard category, separate from the
current-BCH frontier. `bch-spec` = `{ ...ConsensusBch2026, ...overrides }`; the
overrides raise the script / stack-item / big-int size caps 10 kB → 100 kB, raise the density-control
base 41 → 10,000, and add two opcodes (`OP_EVAL`, `OP_POW`, unused so far).

Extra considerations for spec-targeting verifiers (full detail in
[chunked/intratx/README.md → Large scripts](chunked/intratx/README.md#large-scripts-targeting-the-proposed-bch-spec-vm)):

- **No op is cheaper.** Every op-cost coefficient (base 100, sig-check 26,000, hashing, arithmetic,
  1/byte stack push) and the 800 byte→budget rate are unchanged. A script spends the same op-cost on
  spec as on current BCH; only the size limits and the per-input budget floor grow.
- **The freebie ⇒ input-count vs bytes.** Holding the arithmetic and layout fixed, each additional
  input gets `10,000 × 800 = 8,000,000` op for free and can remove about 10 kB of pad. The current
  four-input BN254 spec build nevertheless beats the 11-input current-BCH build because it also uses
  a different scalar schedule and flatter verifier layout; that result is a construction win in the
  separate spec category, not a claim that larger scripts make operations cheaper.
- **Intra-tx introspection is ~free.** Reading a sibling's unlocking costs the reader 1 op/byte while
  those bytes grant the sibling 800 op of budget (800 : 1); pad is serialized once, so it is not
  double-counted in the score.
- **Standardness is measured per entry.** The BN254 spec transaction is 58,683 bytes and passes the
  proposed VM's standard-policy checks. A build that actually approaches a 100 kB input can still
  exceed the 100 kB transaction limit and require direct mining.

## The forms in one paragraph each

- **Singleton** — one contract computes a whole verifier step, graded byte-for-byte
  against `@noble/curves` (and py_ecc). It compiles and runs on the loosened BCH 2026 VM
  but exceeds the per-input limits, so it is the **reference the chunked builds must
  match**, not an on-chain artifact. One self-contained folder per curve under
  [singleton/](singleton/README.md).

- **Chunked** — the same computation split across pieces so **every** chunk fits one BCH
  input (locking+unlocking ≤ 10,000 bytes, op-cost ≤ 8,032,800). State is carried between
  chunks (an NFT `hash256` commitment for the covenant/grouped methods, or a forward
  read of the next input's unlocking bytecode for the intra-tx method). Each chunk's
  result must match the singleton oracle at the corresponding boundary. See
  [chunked/README.md](chunked/README.md) and
  [multi-step-computation.md](multi-step-computation.md).

## The packing methods (chunked)

| method | how state crosses | deployability | folder |
|---|---|---|---|
| **covenant chain** | NFT `hash256` commitment, one chunk per tx | 12 tx for the BN254 quotient frontier; larger historical layouts can approach or exceed the 50-deep mempool edge | `chunked/pairing`, `chunked/bls12-381` |
| **intra-tx linked** | next input's unlocking bytecode (`OP_INPUTBYTECODE` forward-check), one tx | one tx; 86,565 B and standard for the BN254 quotient-torus frontier, larger builds can be non-standard | `chunked/intratx` |
| **grouped** | intra-tx *within* a tx + NFT hand-off *across* txs | **standard-relayable, a handful of <100 KB txs, under the 50-tx limit** | `chunked/grouped` |

The BN254 quotient-torus intra-tx verifier is standard-relayable as one transaction. Grouped remains
the standard-relayable form for larger graphs, including the current BLS12-381 construction, by
splitting them into a handful of transactions within the mempool chain limit.

The **`vk_x`-only** checkpoint (the variable-scalar G1 MSM,
`IC0 + in0·IC1 + in1·IC2`) is factored out and has its own two implementations kept for
comparison: [`chunked/twoloop/`](chunked/twoloop/) (simple, 16 chunks) and
[`chunked/shamir/`](chunked/shamir/) (optimized Shamir/Straus, 2 chunks). GLV `vk_x`
(`gen_vkx_glv.mjs`) is the further-optimized form used inside the residue builds.

## The optimisation variants

- **`minop` singletons** (`groth16_minop.cash` per curve) — the singleton recomputed
  with the op-cost tricks: one batched fused Miller with only the single runtime pair
  on-chain (`e(α,β)` and the `vk_x`/`C` lines baked) and GLV `vk_x`. Both curve builds
  evaluate in their quotient torus, replacing the full residue witness with a six-limb
  root. These are still single-input oracles.

- **`residue` chunked** (`*-intratx-residue`, `*-grouped-residue`) — the same residue
  math packed into a deployable chunk graph. The hard-part final exponentiation
  (dozens of chunks in the plain build) collapses to a short witnessed-residue tail.
  BN254 additionally evaluates the Miller accumulator in `Fp12*/Fp6*`, reducing the
  graph to a standard 11-input transaction; grouped packing remains available for
  constructions whose complete graph exceeds standard transaction policy.

The op-cost win that these share at the *codegen* level — the `rescheduleStacks` compile
mode — is documented separately in
[rescheduling-stacks.md](rescheduling-stacks.md).

## Building and benchmarking

Each verifier is generated/validated in its folder (`gen_*.mjs` to emit `.cash`,
`build_vectors*.mjs` to emit the graded vector JSON). The `bch-*` entries above are
registered in the external verifier-benchmark repo
(`src/implementations/bch-*.ts` + the REGISTRY); run one with
`pnpm benchmark <id-substring>`. See each folder's `README.md` for the exact regenerate
commands.

## See also

- [singleton/README.md](singleton/README.md) — the oracle verifiers, one folder per curve.
- [chunked/README.md](chunked/README.md) — the deployable multi-tx verifiers.
- [multi-step-computation.md](multi-step-computation.md) — why the work is split across
  transactions and how state is carried.
- [rescheduling-stacks.md](rescheduling-stacks.md) — the codegen op-cost lever.
- [The CashScript Compiler Fork](cashscript-compiler-fork.md) — the compiler these are
  built with.

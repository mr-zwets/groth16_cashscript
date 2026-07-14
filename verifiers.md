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
| `bch-groth16-singleton-minop` | singleton, op-optimized | ~66.5 KB / ~195M op-cost | residue + GLV, still single-input (oracle) |
| `bch-groth16-chunked` | chunked, covenant chain | **48 inputs / 373,256 B / 293.69M op** | NFT-commitment chain |
| `bch-groth16-intratx` | chunked, intra-tx linked | **46 inputs / 368,748 B / 293.54M op** | whole verifier in one (non-standard) tx |
| `bch-groth16-grouped` | chunked, grouped | **46 inputs / 368,664 B / 293.45M op** | standard-relayable |
| `bch-groth16-intratx-residue` | chunked, intra-tx + residue | **26 inputs / 224,875 B / 179.64M op** | smallest single-tx BN254 verifier |
| **`bch-groth16-grouped-residue`** | **chunked, grouped + residue** | **26 inputs / 224,830 B / 179.59M op — flagship** | standard-relayable in 3 txs |
| `bch-groth16-intratx-residue-large` | chunked, intra-tx + residue, **`bch-spec`** | **4 inputs / 187,792 B / 177.33M op** | targets the proposed `bch-spec` upgrade, not current BCH; structural (fewest UTXOs), own leaderboard category — see [Target VM](#target-vm-bch-spec) |
| `bch-pairing-chunked` | chunked pairing-only, covenant | score **217,562** | Miller + final-exp milestone |
| `bch-pairing-intratx` | chunked pairing-only, intra-tx | score **215,429** | |
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
| `bch-groth16-bls12381-singleton-minop` | singleton, op-optimized | 67,163 B / **256.6M op-cost** | residue (`λ=p+|x|`, μ₂₇A witness) + GLV; fused G2 ψ-check; A/C on-curve (G1 subgroup checks omitted) |
| `bch-pairing-bls12381-singleton` | singleton, pairing-only | ~19.8 KB / ~1.38B op-cost | the pairing verdict milestone (`verify.cash`) |
| `bch-groth16-bls12381-grouped-residue` | chunked, grouped + residue | **39 inputs / 5 standard txs / 324,267 B / 256.72M op** | the deployable BLS verifier; GLV `vk_x` + fused Miller + μ₂₇A residue tail |
| `bch-groth16-bls12381-intratx-residue-large` | chunked, intra-tx + residue, **`bch-spec`** | **5 inputs / 270,713 B / 250.65M op** | BLS counterpart of the spec build; targets the proposed `bch-spec` upgrade — see [Target VM](#target-vm-bch-spec) |

The BLS chunked pairing/Miller/final-exp families also exist in
[chunked/bls12-381/](chunked/bls12-381/) (plain and residue generators); the
grouped-residue packing above is the assembled full-verifier deployment.

## Target VM (`bch-spec`)

Most entries target **current BCH** (libauth `createVirtualMachineBch2026`, 10 kB scripts). Two —
`bch-groth16-intratx-residue-large` and `bch-groth16-bls12381-intratx-residue-large` — instead target
the **proposed `bch-spec` upgrade** (`createVirtualMachineBchSpec`). The harness marks them
`vm: 'bch-spec'` and files them in their own leaderboard category, so a spec entry cannot be compared
against, or hijack, the current-BCH frontier. `bch-spec` = `{ ...ConsensusBch2026, ...overrides }`; the
overrides raise the script / stack-item / big-int size caps 10 kB → 100 kB, raise the density-control
base 41 → 10,000, and add two opcodes (`OP_EVAL`, `OP_POW`, unused so far).

Extra considerations for spec-targeting verifiers (full detail in
[chunked/intratx/README.md → Large scripts](chunked/intratx/README.md#large-scripts-targeting-the-proposed-bch-spec-vm)):

- **No op is cheaper.** Every op-cost coefficient (base 100, sig-check 26,000, hashing, arithmetic,
  1/byte stack push) and the 800 byte→budget rate are unchanged. A script spends the same op-cost on
  spec as on current BCH; only the size limits and the per-input budget floor grow.
- **The freebie ⇒ input-count vs bytes.** Each input gets `10,000 × 800 = 8,000,000` op for free, so
  *more* inputs = *fewer* pad bytes. A large-script build minimizes **input count** (structural: one
  fat tx), not bytes — the 10 kB build is byte-lighter. Fusing inputs (`FUSE_TAIL` / `FUSE_FINAL`)
  costs ~10 kB of pad per dropped freebie.
- **Intra-tx introspection is ~free.** Reading a sibling's unlocking costs the reader 1 op/byte while
  those bytes grant the sibling 800 op of budget (800 : 1); pad is serialized once, so it is not
  double-counted in the score.
- **Non-standard.** A 100 kB input makes the tx exceed the 100 kB standard size, so it is mined
  directly (the intra-tx bundle was already non-standard).

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
| **covenant chain** | NFT `hash256` commitment, one chunk per tx | ~54–87 tx chain (at the 50-deep mempool edge) | `chunked/pairing`, `chunked/bls12-381` |
| **intra-tx linked** | next input's unlocking bytecode (`OP_INPUTBYTECODE` forward-check), one tx | a single ~0.25–0.7 MB non-standard tx | `chunked/intratx` |
| **grouped** | intra-tx *within* a tx + NFT hand-off *across* txs | **standard-relayable, a handful of <100 KB txs, under the 50-tx limit** | `chunked/grouped` |

Grouped is the only full-verifier form that is **both** standard-relayable **and** within
the mempool chain limit, which is why the flagship deployment is
`bch-groth16-grouped-residue`.

The **`vk_x`-only** checkpoint (the variable-scalar G1 MSM,
`IC0 + in0·IC1 + in1·IC2`) is factored out and has its own two implementations kept for
comparison: [`chunked/twoloop/`](chunked/twoloop/) (simple, 16 chunks) and
[`chunked/shamir/`](chunked/shamir/) (optimized Shamir/Straus, 2 chunks). GLV `vk_x`
(`gen_vkx_glv.mjs`) is the further-optimized form used inside the residue builds.

## The optimisation variants

- **`minop` singletons** (`groth16_minop.cash` per curve) — the singleton recomputed
  with the op-cost tricks: one batched `c^{-|x|}`-fused Miller with only the single
  runtime pair on-chain (`e(α,β)` and the `vk_x`/`C` lines baked), a witnessed-residue
  final exponentiation, and GLV `vk_x`. Bytes go *up* (not their axis) but op-cost drops
  ~70–80 %. These are still single-input oracles.

- **`residue` chunked** (`*-intratx-residue`, `*-grouped-residue`) — the same residue
  math packed into a deployable chunk graph. The hard-part final exponentiation
  (dozens of chunks in the plain build) collapses to a short witnessed-residue tail,
  cutting inputs/bytes/op by roughly a third — which is what turns the multi-transaction
  grouped verifier into the compact flagship.

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

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

Numbers are the benchmark's `results.json` as of 2026-10-17 (zk-verifier-bench `f7f7801`):
score = total on-chain bytes, op = small-proof op-cost summed over all inputs. "Inputs" are
the verifier's steps; "tx" is how many transactions carry them.

**Withdrawals (2026-10-26).** Entries marked **withdrawn** have had their correctness claims
withdrawn by their author ([#32], [bench#49]) or are held as withdrawn because a listed
finding applies to the code they ship. Their rows stay here as history. The current best
non-withdrawn BN254 entries are `bch-groth16-bn254-sound-native` (27,624 B, current-BCH
deployable: 3 inputs in one standard transaction, independently reviewed) and
`bch-groth16-sound-si-gls-single` (21,915 B, proposed `bch-spec` VM, one input, independently
reviewed); the smallest reviewed BN254 singleton (oracle) is `bch-groth16-singleton-genpow` (4,613 B, reviewed 2026-10-27, native op-cost HOLD), and the smallest cashc one is `bch-groth16-singleton-opcode-optimized` (6,237 B, reviewed).
The densless family (`-densless-msm`, `-densless-msm-slim`, `-densless-msm-spec`) is
withdrawn under F6: the Miller slopes are not constrained by the tangent/chord equations and
the terminal compares a value with itself instead of checking the B endpoint ([#28], [#32]);
at the #22 / bench#42 head (`-densless-msm-slim`) line/root values are also not bound to the
committed state. The plain `-pairfold5-densless` baseline is excluded from the author's
withdrawal and is held as withdrawn on our reading (see below).

| entry | form / variant | headline | notes |
|---|---|---|---|
| `bch-groth16-bn254-sound-native` | chunked, intra-tx SI-MX3 (SI-GLS batched torus identity, affine B walk, 3 roles) | **3 inputs / 1 standard tx / 27,624 B / 20.6M op** | **current best deployable BN254 verifier**; **independently reviewed** (2026-10-26); sound by construction: every accept-relevant value is computed, baked, hash-committed before its challenge or exactly checked; inputs, order and sibling code pinned by introspection, state handed over byte-exactly; worst-case liveness margin 6.0% per input; see `chunked/bn254/bn-native-sound` (added 2026-10-27) |
| `bch-groth16-intratx-pairfold5-densless-msm-slim` | chunked, intra-tx PairFold-5 densless + slim vk_x MSM | **5 inputs / 1 standard tx / 35,143 B / 24.9M op** | **withdrawn** ([#32] F6); formerly listed as the current best deployable verifier; the densless-msm construction with claimed inputs as terminal pushes and witness bytes moved out of the carried state; see `chunked/bn254/densless-msm-slim` |
| `bch-groth16-intratx-pairfold5-densless-msm` | chunked, intra-tx PairFold-5 densless + sound vk_x MSM | **5 inputs / 1 standard tx / 35,861 B / 24.3M op** | **withdrawn** ([#32] F6: the densless pairing part); densless base (`chunked/bn254/densless-recovered`) with its dead vk_x predicate sliced out, plus a GLV Straus MSM that binds vk_x to the claimed public inputs; see `chunked/bn254/densless-msm` |
| `bch-groth16-intratx-crown8-rawchain` | chunked, intra-tx, raw Miller-chain records | **8 inputs / 1 standard tx / 77,193 B / 58.3M op** | formerly listed as the current best deployable BN254 verifier (superseded by `bch-groth16-bn254-sound-native`); **unreviewed (no source)**: the generator source is not public, so the shipped bytes cannot be reviewed; source requested from the author; sibling-bytecode-bound Miller chain |
| `bch-groth16-intratx-direct-state-public` | chunked, intra-tx, fixed-deployment profile | **10 inputs / 1 standard tx / 83,294 B / 60.3M op** | **unreviewed (no source)**: generator source not public; binds the complete source-role topology |
| `bch-groth16-intratx-residue` | chunked, intra-tx + quotient-torus residue | **11 inputs / 1 standard tx / 86,950 B / 68.5M op** | **independently reviewed** (2026-10-27): vectors regenerate byte-identically; exact frames on all 11 inputs, successor pins, exact G2 endpoint test, quotient-torus terminal with r | λ; two GLV vk_x inputs feeding nine affine Miller inputs |
| `bch-groth16-chunked-covenant-residue` | chunked, quotient-torus covenant chain | **12 tx / 93,802 B / 69.9M op** | standard-relayable; token-bound state thread; **independently reviewed** (2026-10-27) on two written deployment premises, P1 (category genesis from an index-0 outpoint, only L_0 minting batons, regenerated with the real category) and P2 (an off-chain consumer reads the unspendable empty-commitment verdict NFT through its one-input ancestry; the statement is in0/in1 at pushes 6/5 of the genesis unlocking); see [chunked/pairing/README.md](chunked/pairing/README.md#covenant-residue-composition-what-the-scripts-enforce-and-what-the-deployment-supplies) |
| `bch-groth16-intratx-general` | chunked, intra-tx | **13 inputs / 1 standard tx / 95,201 B / 58.1M op** | **unreviewed (no source)**: generator source not public; general layout of the intra-tx verifier |
| `bch-groth16-grouped-residue` | chunked, grouped + residue | **26 inputs / 3 standard tx / 225,877 B / 179.4M op** | **withdrawn** ([#32] F1: grouped26 frame ownership) |
| `bch-groth16-intratx` | chunked, intra-tx linked | **31 inputs / 1 tx / 234,022 B / 183.0M op** | **withdrawn** ([#32] F1: BN42 public-scalar tail); whole verifier in one non-standard tx |
| `bch-groth16-grouped` | chunked, grouped | **31 inputs / 4 standard tx / 234,301 B / 183.0M op** | **withdrawn** ([#32] F1: grouped42 public-scalar tail) |
| `bch-groth16-chunked` | chunked, covenant chain | **32 tx / 239,773 B / 183.2M op** | NFT-commitment chain |
| `bch-groth16-intratx-authenticated-p2s` | chunked, intra-tx, bare P2S dispatchers | **42 inputs / 1 tx / 330,742 B / 261.8M op** | **withdrawn** ([#32] F1); P2S variant of the older 42-input intra-tx layout |
| `bch-groth16-chunked-covenant` | chunked, covenant chain with transcript thread | **49 tx / 473,475 B / 305.7M op** | non-standard (chain depth) |
| `bch-groth16-intratx-pairfold5-densless-msm-spec` | as densless-msm, **`bch-spec`** | **5 inputs / 33,875 B / 24.0M op** | **withdrawn** ([#32] F6); proposed-VM-only — see [Target VM](#target-vm-bch-spec) |
| `bch-groth16-intratx-residue-large` | chunked, intra-tx + residue, **`bch-spec`** | **4 inputs / 58,460 B / 67.3M op** | **independently reviewed** (2026-10-27); proposed-VM-only; passes its standard-policy model |
| `bch-groth16-sound-si-gls-single` | one input, SI-GLS batched torus identity, **`bch-spec`** | **1 input / 21,915 B / 23.3M op** | **best BN254 `bch-spec` entry** (and the smallest reviewed full verifier on either curve outside the singleton oracles); independently reviewed; every accept-relevant value is computed, baked, hash-committed before its challenge or exactly checked; see `chunked/bn254/sound-si-gls` (added after the 2026-10-17 snapshot) |
| `bch-groth16-singleton-genpow` | singleton, symbolic assembly | **4,613 B / 5.5B op** | **independently reviewed** (2026-10-27) as the corrected successor (4,320 B program, groth16_cashscript#30 / bench#47; the original 4,183 B program was withdrawn under [#32] F4): canonical coordinate and Fr guards, exact curve and ψ G2 checks, complete identity addition; the smallest reviewed BN254 full verifier; native op-cost HOLD; built from `singleton/bn254/genpow-reconstructed`, not cashc; oracle only |
| `bch-groth16-singleton-opcode-optimized` | singleton, baseline + rescheduled/outlined | **6,237 B / 800M op** | the F4 mechanism in `lib/G1.cash` `jacAddG1` (a zero public input dropped IC0), found by maintainer review, is **fixed** (+19 B, zero-input proofs added as tests); coordinate range checks added; **independently reviewed** (2026-10-26); oracle |
| `bch-groth16-singleton` | singleton, baseline | **8,206 B / 771M op** | the F4 mechanism in `lib/G1.cash` `jacAddG1`, found by maintainer review, is **fixed** (+19 B, zero-input proofs added as tests); coordinate range checks added; **independently reviewed** (2026-10-26); correctness oracle; over per-input limits |
| `bch-groth16-singleton-minop` | singleton, op-optimized | **58,073 B / 64.8M op** | **independently reviewed** (2026-10-27): recompiles byte-identically; inputs < r via GLV k ≥ 0, B in G2 by the exact (6x+2)+ψ−ψ²+ψ³ endpoint relation; quotient-torus residue + affine GLV; still single-input (oracle) |
| `bch-pairing-intratx` | chunked pairing-only, intra-tx | **12 inputs / 107,243 B / 84.4M op** | Miller-boundary milestone |
| `bch-pairing-chunked` | chunked pairing-only, covenant | **12 tx / 109,305 B / 84.3M op** | Miller-boundary milestone |
| `bch-pairing-singleton` | singleton pairing-only | **6,640 B / 687M op** | oracle |
| `bch-vkx-chunked-covenant` | chunked `vk_x`-only | **7 tx / 11,351 B / 7.0M op** | the G1 MSM checkpoint (see `chunked/shamir/`, `chunked/twoloop/`) |

**Failing PairFold entries.** `bch-groth16-intratx-pairfold5` (44,968 B), `-pairfold5-densless`
(33,179 B), `-pairfold5-pevalfuse` (36,836 B) and `-pairfold7` (54,483 B) are still registered
but currently **fail** the benchmark: the maintainer red-team accepts a forged public input
(`n0 + 2` with the true vk_x kept), because their vk_x is not bound to the claimed inputs.
All four are also **withdrawn**: pevalfuse under [#32] F9; pairfold5 because its genesis is
byte-identical to pevalfuse's, so F9 applies to it as well; pairfold5-densless **withdrawn**
(held: same `millerEvent`/terminal bytes as F6; the author's withdrawal excludes the
plain-densless baseline); pairfold7 **withdrawn** (held: the same public-statement-binding
class as F9, from the failing red-team verdict, found by maintainer review; not withdrawn by
the author). The
`-densless-msm` entries above were the successors that repaired the vk_x binding, but they
keep the densless pairing part and are withdrawn under F6.

## BLS12-381 verifiers

Same curve as the nChain reference (522,564 B), so these give a true apples-to-apples size
comparison. Per-layer status and build commands are in
[singleton/bls12-381/README.md](singleton/bls12-381/README.md).

**Withdrawals (2026-10-26).** As above, **withdrawn** rows stay as history. The current best
non-withdrawn BLS12-381 deployable entry is `bch-groth16-bls12381-sound-native` (34,229 B, 4 inputs
in one standard transaction, independently reviewed). The best BLS12-381 `bch-spec` entry is
`bch-groth16-bls12381-sound-si-gls-single` (26,484 B, one input, independently reviewed), and the
smallest reviewed BLS12-381 singleton (oracle) is `bch-groth16-bls12381-singleton-genpow` (5,965 B, reviewed 2026-10-27 with a cofactor-equivalent G2 domain, native op-cost HOLD); the smallest cashc one is `bch-groth16-bls12381-singleton-opcode-optimized` (5,999 B, reviewed).

| entry | form / variant | headline | notes |
|---|---|---|---|
| `bch-groth16-bls12381-sound-native` | chunked, intra-tx SI-GLS (batched torus identity, GT-GLS fold), 4 inputs sharing one 81 B redeem | **4 inputs / 1 standard tx / 34,229 B / 24.0M op** | **current best BLS12-381 deployable**; **independently reviewed** (2026-10-26); sound by construction (unconditional apart from the hash-committed SI-GLS challenge, ε ≈ 2^−248); worst-case liveness sample minimum 6.18% standard / 6.42% consensus; see `chunked/bls12-381/bls-native-sound` (added 2026-10-27) |
| `bch-groth16-bls12381-sound-si-gls-single` | one input, SI-GLS batched torus identity, **`bch-spec`** | **1 input / 26,484 B / 26.1M op** | **best BLS12-381 `bch-spec` entry**; **independently reviewed** (2026-10-26); BLS12-381 port of the BN254 `sound-si-gls`; worst forced liveness margin 6.14%; see `chunked/bls12-381/sound-si-gls` (added 2026-10-27) |
| `bch-groth16-bls12381-intratx-fs-fused-coordinator-head` | chunked, Fiat-Shamir PIT, fused coordinator/quotient head | **9 inputs / 1 standard tx / 60,285 B** | formerly listed as the current best BLS12-381 deployable (superseded by `bch-groth16-bls12381-sound-native`); **independently reviewed** (2026-10-27, all 13 fs ids: three-lens review, then the FS-PIT soundness argument in `chunked/bls12-381/README.md` sections 1-6 signed off by two reviews; SHA-256 random-oracle model, A/C cofactor-equivalent); finite ten-fixture coverage, no universal resource certificate; separate security model (one of the bench#43 fs-fused variants, see the benchmark for the others) |
| `bch-groth16-bls12381-intratx-fs-compact` | chunked, compact transcript + **Fiat-Shamir PIT** | **22 inputs / 1 standard tx / 69,947 B / 42.7M op** | formerly listed as the best BLS12-381 deployable (superseded; registry score now 65,696 B); **independently reviewed** (as the fs family above); finite candidate (10 fixtures / 220 source pairs), no universal resource theorem; separate security model — see [Fiat-Shamir model](#security-model-fiat-shamir-pit) |
| `bch-groth16-bls12381-intratx-fs` | chunked, intra-tx + residue + **Fiat-Shamir PIT** | **22 inputs / 1 standard tx / 79,948 B / 53.1M op** | first single-standard-tx full BLS verifier; **independently reviewed** (as the fs family above); built from 77ab0ac; separate security model |
| `bch-groth16-bls12381-intratx-residue` | chunked, intra-tx + quotient-torus residue | **24 inputs / 1 tx / 193,309 B / 151.4M op** | **withdrawn** ([#32] F1: BLS24 frame ownership); current-consensus-valid; non-standard only by total size |
| `bch-groth16-bls12381-grouped-residue` | chunked, grouped + quotient-torus residue | **26 inputs / 3 standard tx / 202,594 B / 158.3M op** | **withdrawn** (2026-10-27 review finding: the tx2/tx3 group roots take their incoming state from an NFT commitment with no pinned token category, so that state is unowned; fix route: pin the category and hold minting in a covenant) |
| `bch-groth16-bls12381-chunked-covenant-residue` | chunked, covenant chain + residue | **27 tx / 211,163 B / 157.0M op** | standard-relayable; **independently reviewed** (2026-10-27) on the same deployment premises P1/P2 as the BN covenant-residue; 27 single-input tx, all 17 isolated invalid-input runs rejected; see [chunked/bls12-381/README.md](chunked/bls12-381/README.md#covenant-residue-composition-and-deployment-premises) |
| `bch-groth16-bls12381-intratx` | chunked, intra-tx linked | **43 inputs / 1 tx / 345,471 B / 270.6M op** | non-standard |
| `bch-groth16-bls12381-grouped` | chunked, grouped | **43 inputs / 5 standard tx / 345,791 B / 270.6M op** | |
| `bch-groth16-bls12381-chunked` | chunked, covenant chain | **43 tx / 357,241 B / 270.5M op** | |
| `bch-groth16-bls12381-chunked-covenant` | chunked, covenant chain with transcript thread | **69 tx / 635,295 B / 420.5M op** | non-standard (chain depth) |
| `bch-groth16-bls12381-intratx-residue-large` | chunked, intra-tx + residue, **`bch-spec`** | **3 inputs / 161,660 B / 146.6M op** | **withdrawn** (held: same F1 generator pattern, no exact-length gate; not confirmed by the author); proposed-VM-only; non-standard by total transaction size — see [Target VM](#target-vm-bch-spec) |
| `bch-groth16-bls12381-singleton-genpow` | singleton, symbolic assembly | **5,965 B / 25.6B op** | **independently reviewed** (2026-10-27) as the corrected successor (5,675 B program, groth16_cashscript#31 / bench#48; the original 3,722 B program was withdrawn under [#32] F5): canonical decoders with exact curve residuals and on-chain r-component projection of every pairing operand. **Cofactor-equivalent domain**: sound by the endpoint argument, but A, B and C are malleable by cofactor torsion and a non-subgroup B is not rejected. The smallest reviewed BLS12-381 full verifier; native op-cost HOLD; built from `singleton/bls12-381/leader-recovered`, not cashc; oracle only |
| `bch-groth16-bls12381-singleton-opcode-optimized` | singleton, baseline + rescheduled/outlined | **5,999 B / 1.0B op** | **reviewed** (independent review 2026-10-26): domain checks (range, curve, G2 subgroup; see [singleton/bls12-381](singleton/bls12-381/README.md#proof-point-validation)) added after a maintainer hold; same source as `-singleton`; oracle |
| `bch-groth16-bls12381-singleton` | singleton, baseline | **7,510 B / 995M op** | **reviewed** (independent review 2026-10-26): domain checks (range, curve, G2 subgroup) added after a maintainer hold |
| `bch-groth16-bls12381-singleton-minop` | singleton, op-optimized | **58,841 B / 145.6M op** | **independently reviewed** (2026-10-27): regenerates and recompiles byte-identically; quotient torus (`λ=p+|x|`, 6-limb root u) + GLV; fused G2 ψ-check; A/C on-curve only (G1 subgroup checks omitted, cofactor malleability only) |
| `bch-groth16-bls12381-singleton-fs` | singleton, **Fiat-Shamir PIT** | **103,861 B / 38.7M op** | **independently reviewed** (2026-10-27) (SHA-256 random-oracle model, A/C cofactor-equivalent); single-script qsplit tail-22 (`chunked/bls12-381/measure_fs_singleton.mjs`); separate security model |
| `bch-groth16-bls12381-singleton-fs-spec` | singleton, **Fiat-Shamir PIT**, P2SH32, **`bch-spec`** | **97,955 B / 56.0M op** | **independently reviewed** (2026-10-27) (random-oracle model); delta lines rebuilt in-script from baked constants by exact affine equations |
| `bch-groth16-bls12381-singleton-fs-spec-shared` | as `-fs-spec`, shared PIC / regular bodies, **`bch-spec`** | **73,536 B / 56.5M op** | **independently reviewed** (2026-10-27) (random-oracle model); shared functions take index, window and root as call-site constants |
| `bch-groth16-bls12381-singleton-fs-spec-zero` | as `-fs-spec-shared`, zero-PIC codec, **`bch-spec`** | **65,218 B / 57.0M op** | **independently reviewed** (2026-10-27) (random-oracle model); the codec only changes the wire encoding (full consumption required) |
| `bch-pairing-bls12381-singleton` | singleton, pairing-only | **6,652 B / 968M op** | the pairing verdict milestone (`verify.cash`) |
| `bch-pairing-bls12381-intratx` / `-chunked` | chunked pairing-only | **38 inputs / 335,614 B** (intra-tx) · **38 tx / 342,331 B** (covenant) | Miller-boundary milestones |
| `bch-vkx-bls12381-chunked-covenant` | chunked `vk_x`-only | **11 tx / 23,700 B / 6.8M op** | **withdrawn** (held: successor locking not pinned, found by maintainer review) |

The BLS chunked pairing/Miller/final-exp families also exist in
[chunked/bls12-381/](chunked/bls12-381/) (plain and residue generators); the
grouped-residue packing above is the assembled full-verifier deployment.

## Security model (Fiat-Shamir PIT)

Every other entry is an **unconditional algebraic certificate**: the script computes the
field arithmetic exactly, so acceptance is equivalent to the Groth16 pairing equation with
no extra assumptions. The `-fs` entries — `bch-groth16-bls12381-intratx-fs` and `-intratx-fs-compact` (the deployable
22-input transactions) and `bch-groth16-bls12381-singleton-fs` (the same construction in one
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
  bound `23Nβ/(2^256-1) + 137Nα/2^256 + Adv_bind`. The challenge counters include
  adversarial prequeries and fresh verifier queries; `Adv_bind` separately covers the
  commitment/code hash bindings. If both challenge counts are at most q, the degree
  contribution is at most `q·160/(2^256-1)`; an adversary-only q does not also bound
  all Merkle/preprocessing hash work. The argument and query convention are in
  [chunked/bls12-381/README.md](chunked/bls12-381/README.md), sections 1-6 (reviewed 2026-10-27) — STARK-class, but a **new assumption** the
  unconditional entries do not make. It is therefore filed under this separate name
  rather than as a successor to `-intratx-residue` / `-grouped-residue`.
- A and C are graded **cofactor-equivalent**: on-curve is enforced and the pairing verdict
  binds their prime-order projections; as in `-singleton-minop` (which has the ψ G2 check only), alternate cofactor encodings of the same valid proof also spend. No
  unique-G1-encoding grade is claimed.
- The `e(vk_x, γ)` pair is served from a **2,097,152-entry public-VK-derived GT table**
  (window-8 over the two public-input byte pairs), Merkle-committed in the locking
  programs; per-VK preprocessing regenerates ~1.2 GB of table data
  (`chunked/bls12-381/prove_gt_window_preimage.mjs`, deterministic, VK points only).

## Target VM (`bch-spec`)

Most entries target **current BCH** (libauth `createVirtualMachineBch2026`, 10 kB scripts). Three —
`bch-groth16-intratx-residue-large`, `bch-groth16-bls12381-intratx-residue-large` and
`bch-groth16-intratx-pairfold5-densless-msm-spec` (now withdrawn, [#32] F6) — instead target
the **proposed `bch-spec` upgrade** (`createVirtualMachineBchSpec`). The harness marks them
`vm: 'bch-spec'` and files them in their own leaderboard category, separate from the
current-BCH frontier. Two reviewed one-input builds also target it: `bch-groth16-sound-si-gls-single`
(BN254, 21,915 B) and `bch-groth16-bls12381-sound-si-gls-single` (BLS12-381, 26,484 B).
`bch-spec` = `{ ...ConsensusBch2026, ...overrides }`; the
overrides raise the script / stack-item / big-int size caps 10 kB → 100 kB, raise the density-control
base 41 → 10,000, and add two opcodes (`OP_EVAL`, `OP_POW`, unused so far).

Extra considerations for spec-targeting verifiers (full detail in
[chunked/intratx/README.md → Large scripts](chunked/intratx/README.md#large-scripts-targeting-the-proposed-bch-spec-vm)):

- **No op is cheaper.** Every op-cost coefficient (base 100, sig-check 26,000, hashing, arithmetic,
  1/byte stack push) and the 800 byte→budget rate are unchanged. A script spends the same op-cost on
  spec as on current BCH; only the size limits and the per-input budget floor grow.
- **The freebie ⇒ input-count vs bytes.** Holding the arithmetic and layout fixed, each additional
  input gets `10,000 × 800 = 8,000,000` op for free and can remove about 10 kB of pad. The
  four-input BN254 `residue-large` spec build beats the 11-input current-BCH residue build because it
  also uses a different scalar schedule and flatter verifier layout; that result is a construction
  win in the separate spec category, not a claim that larger scripts make operations cheaper. The
  densless-msm spec build saves under 2 kB over its current-BCH twin, since that construction
  already needs no pad (both densless-msm builds are now withdrawn, [#32] F6).
- **Intra-tx introspection is ~free.** Reading a sibling's unlocking costs the reader 1 op/byte while
  those bytes grant the sibling 800 op of budget (800 : 1); pad is serialized once, so it is not
  double-counted in the score.
- **Standardness is measured per entry.** Both BN254 spec transactions (58,460 B and 33,875 B
  score; the 33,875 B one is now withdrawn) pass the proposed VM's standard-policy checks; the BLS12-381 one does not. A build that actually approaches a 100 kB input can still
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
| **covenant chain** | NFT `hash256` commitment, one chunk per tx | 12 tx for the BN254 quotient-torus build; larger layouts approach or exceed the 50-deep mempool edge | `chunked/pairing`, `chunked/bls12-381` |
| **intra-tx linked** | next input's unlocking bytecode (`OP_INPUTBYTECODE` forward-check), one tx | one tx; 77,193 B and standard for the current BN254 frontier (crown8-rawchain, 8 inputs; the withdrawn 5-input densless-msm-slim was 35,143 B), larger builds can be non-standard | `chunked/intratx`, `chunked/bn254` |
| **grouped** | intra-tx *within* a tx + NFT hand-off *across* txs | **standard-relayable, a handful of <100 KB txs, under the 50-tx limit** | `chunked/grouped` |

The BN254 frontier and the BLS12-381 Fiat-Shamir builds are standard-relayable as one transaction.
Grouped remains the standard-relayable form for larger graphs, including the unconditional
BLS12-381 residue construction, by splitting them into a handful of transactions within the
mempool chain limit.

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
  graph to a standard 11-input transaction (the PairFold-5 densless-msm builds took
  this to 5 inputs but are withdrawn, [#32] F6); grouped packing remains available for
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

[#28]: https://github.com/mr-zwets/groth16_cashscript/issues/28
[#32]: https://github.com/mr-zwets/groth16_cashscript/issues/32
[bench#49]: https://github.com/mr-zwets/zk-verifier-bench/issues/49

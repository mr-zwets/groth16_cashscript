# Sound Schwartz–Zippel designs for a single-input BN254 Groth16 verifier

**Status:** design record. This directory holds three protocol designs and the kernel
prototypes used to cost them. It is **not** a verifier, it has no locking script or
spending transaction, and it is **not** a zk-verifier-bench entry. Every score below is a
measured-kernel estimate, not a built artifact.

**Target:** one BCH input under the proposed bch-spec VM rules: per-script cap 100,000 B,
per-input op budget `(10,000 + unlockingLen) × 800`, benchmark score
`≈ max(bytes, op/800 − 10,000) + ~100 B` of transaction overhead.

## Why

The single-input BN254 draft (densless-msm-spec-single, 28,433 B; draft PRs
groth16_cashscript#29 and zk-verifier-bench#46) inherits the densless polynomial folding. In
densless, the prover supplies the fixed-table words and the per-checkpoint evaluations at the
Fiat–Shamir point `z` *after* `z` is known, and only a linear fingerprint of each committed
state is hashed. When this design work started, whether that freedom is exploitable was open
(groth16_cashscript#28).

**Update (2026-10-26):** the densless author has since withdrawn the full-verifier soundness
claims for the submitted densless constructions
([#28 reply](https://github.com/mr-zwets/groth16_cashscript/issues/28),
[#32 F6](https://github.com/mr-zwets/groth16_cashscript/issues/32),
[zk-verifier-bench#49](https://github.com/mr-zwets/zk-verifier-bench/issues/49)). The reasons given are:

- the shared `millerEvent` consumes prover-supplied slopes without the tangent/chord
  equations, so the group-law recurrence for the B walk is not established;
- the terminal's carried-R predicate compares a modular value with itself, so there is no
  B endpoint equality;
- supplied line values and root copies are not bound to their actual evaluations or to the
  committed state. At the #22 head this covers interior line products, the initial fixed-pair
  lines, final line operands and local/genesis root copies.

The author reports this as missing constraints found by review. No end-to-end false
acceptance was executed. The single-input draft shares the densless folding, so it has no
soundness argument either. The designs below are therefore the sound alternative to
densless, not a hedge against #28: each closes exactly these gaps (slopes and the B endpoint
are checked by exact equations, every line value is computed on-chain, and every state is
hash-committed before the challenge it meets).

The sound reference points are:

| Verifier | Inputs | Score | Soundness |
|---|---|---|---|
| densless-msm-spec-single (draft) | 1 | 28,433 B | none: densless claims withdrawn (#28, #32 F6) |
| intratx-residue-large | 4 | 58,460 B | exact arithmetic, no open finding (not independently reviewed) |
| singleton-minop, moved to one bch-spec input | 1 | ~71–81 kB (estimate) | exact arithmetic, no open finding (not independently reviewed) |

## The soundness requirement

Each design is built so that **every value the accept decision depends on** is one of:

1. **computed on-chain** from other values in this list (lines, the B trajectory, Frobenius
   images, every evaluation at `±z`, the challenges themselves);
2. a **baked VK constant** (fixed-line data, GT constants, Frobenius and ψ constants),
   regenerated from the VK with noble and checked at build time;
3. **committed before the challenge it meets**: hashed into the transcript before that
   challenge is derived, with an injective (fixed-width, length-checked) encoding;
4. **checked by an exact field equation** (curve membership, slope equations, the
   B endpoint, the GLS/GT binding mod r, the final batched equation).

No prover-supplied evaluation at `z` exists in any of the three designs. The identities are
polynomial identities in `Fp12 = Fp[X]/M`, `M = X¹² − 18X⁶ + 82`, between objects that are all
fixed before the challenge, so the Schwartz–Zippel argument applies directly. The shared
skeleton is:

- Work in the quotient group `Fp12*/Fp6*` (cyclic, order `p⁶+1`). `Fp6` is the even
  polynomials; conjugation is `X ↦ −X`. A class is committed as a 6-word representative.
- Run the optimal-ate Miller loop as a chain of checkpoint classes. Each chunk's claim
  "`[P_k] = [S_{k+1}]`" is the polynomial identity `P_k(X)S_{k+1}(−X) − P_k(−X)S_{k+1}(X) ≡ 0
  (mod M)`. The left side is odd, so its quotient by `M` is odd.
- Batch all chunk identities with a challenge `ρ`/`g`, then check the batch against one
  committed odd quotient `Q` at a second challenge `z`, using values at `+z` and `−z` only.
- Close with a residue argument: the chain proves `[f] = [c]^λ`, `λ = 6x+2+p−p²+p³ = m·r`,
  which forces the final exponentiation of `f` to be 1.
- Bind B to G2 through the exact endpoint `[6x+2]B + ψ(B) − ψ²(B) = −ψ³(B)` of the
  on-chain B walk.

`facts.mjs` checks the number-theoretic facts this uses (λ ≡ 0 mod r, `gcd(λ, (p⁶+1)/r) = 1`,
the ψ-endomorphism norm, irreducibility of `M`, the hash-to-field bias). It also checks
`3 ∤ p⁶+1`, which is context only (no cubic-residue selector is needed). Soundness of the
residue argument uses only `λ ≡ 0 (mod r)` and `r | p⁶+1`, so that `(p⁶−1) | (p¹²−1)/r`.
Completeness (a root exists) uses `gcd(λ/r, (p⁶+1)/r) = 1`; `r ∤ (p⁶+1)/r` is additionally
needed only for the closed-form prover root `c = 1 + conj(u^{λ⁻¹ mod (p⁶+1)/r})`. `facts.mjs`
asserts both separately (both also follow from `gcd(λ, (p⁶+1)/r) = 1` and `r | λ`).

## The three designs

| | [single-identity](single-identity/) (SI-GLS) | [commit-all](commit-all/) | [hybrid-direct](hybrid-direct/) (HD-τSZ) |
|---|---|---|---|
| Class representative | monic degree-6 `X⁶ + Σ s_j X^j` | `m(X) + X`, `m` even | torus `1 + X·g(X²)` |
| Chunking | fixed, 2 events, 33 states | prover mask (hashed), ~32 states | fixed, 36 segments |
| vk_x | folded into GT (GLS sub-scalars, binding mod r) | folded into GT (NAF digits, binding mod r) | msm-single on-chain MSM |
| γ Miller loop | none | none | yes (baked λ) |
| B walk | projective, no witness | projective, no witness | affine prefix (16 events, witnessed slopes), projective after |
| Residue | `[f'] = [c]^λ`; terminal is a separate ρ-batched identity (K = 34) | `[f] = [c]^λ`; terminal merged into the last chunk | exact minop torus verdict |
| **Measured score** (fixture 0 / fixture 4, the worst) | **22,711 / 22,970 B** at 66 B tx overhead; 22,745 / 23,004 B at 100 B | **22,900 / 22,971 B** (100 B tx; plan 23.4–23.6 kB) | **36,603 B** |
| Op vs budget | 22.32M / 26.12M (85%), fixture 0 | 26.30M / 26.26M (100.2%, covered by 51 B of padding in the score), fixture 4 and densest digits | 36.18M / 37.20M (97%), typical proof |
| Liveness headroom (worst witness) | 16% (22.41M / 26.74M at the Q cap of 132 words) | none at the balance point; ~0.4–0.6 kB padding needed | 0.4% (37.04M / 37.20M, forced-128 MSM) |
| Score is bound by | bytes | balanced | balanced |
| Review verdict | sound; 1 major, 5 minor | sound if 7 spec rules are adopted; 3 major, 4 minor | sound; 2 major, 5 minor |
| Changed after review (not re-reviewed) | GLS witness as nibble strings + sign byte; grouped 16-entry tables; Q cap 128 → 132 words | swapped ĉ at −1 digits; L_MAX = 4 and Q ≤ 160 odd coefficients chosen here (bound 1,930) | no change to the reviewed identities; format and completeness choices: `WITHIN [1, p)` limb check, zero top Q coefficients dropped (nQ 80/77), projective formulas written, K = 16 / F1-at-64 mix |
| Measurement | each kernel run in the VM, outputs checked; sum + 5% glue (`total.mjs`) | Miller section end-to-end in the VM (one fixture); GT, pipeline, setup in the VM separately; sum + balance search (`total.mjs`) | hot section end-to-end in the VM on all 5 fixtures; MSM and terminal verdict standalone in the VM; +300 B / 0.05M integration estimate |
| Confidence | medium | medium | medium |

All "major" review issues are specification gaps, not flaws in the identities; each design
README folds the fixes into a "Required spec rules" section and the measured numbers include
their cost. The post-review changes listed in the table need another review before a build.
The Q cap change follows a later math review: the 128-word cap, which the measurement step
chose when implementing the first review's request for a cap, was below the honest worst case
for SI's fixed 2-event chunks (see the SI README, Degrees).

Every number in the table can be re-derived from this directory after `pnpm install`, except
the MSM (3,816 B / 11.19M op) and terminal-verdict (1,590 B / 0.44M op) figures inside the
hybrid-direct score, which need the single-input-spec branch and the cashscript-zk compiler
fork (see the hybrid-direct README, Reproduce).

The scores depend on the proof through the quotient (and, for commit-all, the chunking). The
fixture-4 figures are the worst of the 5 fixtures for both SI and commit-all; compare them like
for like.

## Recommendation

**Build single-identity first.**

- Its measured score is 22.7–23.0 kB (fixture 0 to fixture 4), about 5.4–5.7 kB under the
  densless single-input draft at 28,433 B, whose soundness claims were withdrawn (#28, #32 F6).
  The built entry is `chunked/bn254/sound-si-gls` (21,915 B, bench id
  `bch-groth16-sound-si-gls-single`).
- It is byte-bound with 16% op headroom on the worst witness, so op under-estimates (glue,
  stack layout) do not move the score: with 10% or 15% glue the score stays 22,711 B (fixture 0)
  and the worst case reaches 88% / 92% of budget.
- Its control flow is fixed: 2-event chunks, a deterministic GT-GLS loop (two table lookups per
  event, no data-dependent branches), a Q length capped at 132 words.
- Its one major review issue (transcript injectivity) is a pure encoding rule.

The ordering of SI and commit-all on raw score is within the stated uncertainty. On the same
fixture and the same 100 B tx overhead the balance-point scores are 22,745 B against 22,900 B on
fixture 0 (SI 0.16 kB lower) and 23,004 B against 22,971 B on fixture 4 (commit-all 0.03 kB
lower). Commit-all's figures are at a balance point that is already 45–51 B-equivalent over the
op budget and has no liveness margin; against its 23.4–23.6 kB planning figure SI is 0.4–0.6 kB
lower on fixture 4. All of these gaps are smaller than SI's estimated, unbuilt parts (900 + 500 B
of setup/terminal/schedule code, the 494 B layout allowance, the 0.25M setup op) and commit-all's
±1 kB driver/pipeline estimate. The case for SI rests on its byte-bound op margin and fixed
control flow, not on the score.

**Keep commit-all as the fallback.** It shares most of the machinery (Fp6-class states,
`±z` evaluation, ρ-batched odd quotient, vk_x in GT, projective B), lands within 0.2 kB of SI
at the balance point (0.4–0.6 kB above it once padded for liveness), and its Miller section was
measured end-to-end in the VM rather than per kernel. It is weaker on two counts: its best mix
is slightly over the op budget (no liveness margin without ~0.5 kB of padding or a rebalance), and its prover-chosen chunk mask needs data-dependent control flow plus a
chunk-length cap. If single-identity's glue costs turn out much higher than the 5–15% modelled,
commit-all's end-to-end figures are the better guide.

**Hybrid-direct is not recommended for the score** (36.6 kB), but it is the most conservative
of the three: it keeps the on-chain vk_x MSM unchanged and reuses the minop terminal verdict,
adapted to a 6-limb state, and it is the only one whose hot section ran end-to-end on all
fixtures. If the benchmark does not accept folding `e(vk_x, γ)` into GT factors, the choice is
between hybrid-direct (36.6 kB, measured) and SI with msm-single (~34–37.5 kB, modelled with the
measured 10.34M msm-single cost but not built or re-measured); hybrid-direct is preferred there
because it is measured and conservative.

**Open decision for the benchmark owner.** SI and commit-all bind the public inputs through
committed sub-scalars and an exact congruence mod r instead of computing vk_x as a point. The
binding is exact (see each README), but it changes the statement encoding relative to the
other entries. Without it, the design-phase models give ~34–37.5 kB for SI with msm-single
(OPT 0.8–1.0) and ~30.6 kB for commit-all with msm-single; neither was re-measured. The
commit-all figure assumed a 5.1M MSM, while hybrid-direct measured msm-single at 10.3–11.2M, so
its real figure would be several kB higher.

## Layout

```
facts.mjs                      number-theoretic facts used by all three soundness arguments
single-identity/README.md      SI-GLS spec, review fixes, measured kernels, totals
single-identity/prototypes/    protocol reference (proto.mjs) and VM kernel measurements
commit-all/README.md           commit-all spec, review fixes, measured kernels, totals
commit-all/prototypes/         protocol reference (reference.mjs) and VM measurements
hybrid-direct/README.md        HD-τSZ spec, review fixes, measured kernels, totals
hybrid-direct/prototypes/      protocol reference (ref.mjs), end-to-end hot-section prototype
```

All prototypes import `@bitauth/libauth` 3.1.0-next.8 and `@noble/curves` 2.2.0 from the
repository's `node_modules`, and the public fixtures from
`chunked/bn254/densless-recovered/public-fixtures.json`. Run them from the repository root
after `pnpm install`:

```sh
node research/sound-sz-bn254/facts.mjs
```

Each design README has its own Reproduce section.

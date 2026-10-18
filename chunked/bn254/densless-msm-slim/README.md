# BN254 PairFold-5 densless with a sound vk_x: slim MSM state

This is a variant of [`../densless-msm`](../densless-msm), with the merged upstream compiler update retained. This variant keeps the same pairing programs and the same GLV Straus vk_x MSM. It only changes where the MSM state lives. Bench entry id: `bch-groth16-intratx-pairfold5-densless-msm-slim`.

In `../densless-msm`, every stage ends with a 224-byte state push (X, Y, Z, n0, n1, w). n0, n1 and w are copied through all four stages, so 128 bytes are paid four times.

Here:

- **The public inputs are terminal pushes.** The claimed n0, n1 are the terminal's own number pushes, just below zInv and its state push. The terminal range-checks them (`0 <= n < r`) and checks the GLV decomposition of w against them. Genesis no longer carries n0, n1. The bench `publicInputs` are input 4, pushes 53 (n0) and 52 (n1).
- **w lives only in the terminal state.** The terminal's state push is w, X, Y, Z (160 bytes), and the terminal requires that exact length. It is the last push before the terminal redeem, whose length is fixed by the locking's hash. So the 160 bytes that end `back` bytes before the end of input 4's unlocking are exactly that push. Genesis reads its configured witness prefix from this window (33 bytes for floating,27 for the orbit profiles). Each executor reads its own range from it.
- **Executor state pushes are X, Y, Z only** (96 bytes). As before, each stage pins the next stage's push from the end of the receiver's unlocking: input 0 → 1 → 2 → 4, and genesis → input 0.
- **Soundness argument** (same shape as the parent). All stages consume one w. The terminal binds that w to its claimed n0, n1 mod r. The X, Y, Z chain is pinned stage to stage. The terminal checks the final affine point against the genesis vk_x, which the Miller loop consumes. So a proof verifies only for the claimed inputs.
- **Rebalance.** Full MADD prime caching shrinks the genesis unlocking script and its op budget. The default Straus split is 31 (genesis runs positions 63..31), with witness-byte cuts 33,43,54,60. Four positions move from genesis to the executors, two each to exec0 and exec1. Global and stage padding remain zero. The two 96-byte derived states at the first two stage boundaries move from seams 37/45 to 33/43; proof, public input, quotient and auxiliary values stay fixed.

**Malleability pins** (`malleability-pins.mjs`, default `SLIM_PINS=full`): prepended once to the densless half of the terminal redeem. They pin PUSHDATA2 lengths on the terminal header/quot and each executor quot, enforce non-decreasing order on terminal limbs 2..11, and require fixed-table sign bits clear on all three executors. The order reader follows actual minimally encoded VM-number pushes, including OP_0, small integer opcodes and 31/32-byte payloads. Its helper key 151 is disjoint from sign helper 150 and the existing base/MSM namespaces. The builder and witness producer share `PIN_MODE`, so an unset environment reproduces explicit `full` output. Modes remain `0`, `lenonly`, `orderonly`, `lensign`, `lenorder`, `full`.

## Current stack cleanup

Every cache profile uses the checked executor cleanup and terminal inverse-copy identities. The executor replaces `DROP 4 ROLL DROP 4 ROLL DROP 4 ROLL DROP` with `7 ROLL 2DROP 2ROT 2DROP`; both consume eight owned raw words and retain words3..6. The terminal replaces `6 PICK 7 PICK` with `6 PICK DUP`, copying the same arbitrary raw word twice with seven owned words. Both preserve lower main/ALT/function-table prefixes. The existing unique whole-block fingerprints and instruction-boundary checks guard each transform.

Floating, raw-dbl, raw-madd, direct orbit and retained orbit each save16 primary bytes and2,049 native units in both modes. All72 paired archived mode contexts per profile have those deltas. Raw-both already used both rules and retains its programs at explicit27 and default31 schedules. The cache-profile API, full-pin default and zero-padding defaults are unchanged.

| profile / split | primary score (bytes) | native consensus | native standard | minimum sampled native input margin |
|---|---:|---:|---:|---:|
| floating (default31) | 35,109 | 24,840,184 | 24,908,408 | 86,670 |
| raw-dbl31 | 35,266 | 24,828,520 | 24,897,128 | 88,287 |
| raw-madd31 | 35,480 | 24,688,942 | 24,757,934 | 113,592 |
| orbit37 | 34,685 | 25,263,604 | 25,331,060 | 104,025 |
| orbit-retained37 | 34,631 | 25,317,261 | 25,384,589 | 93,286 |
| raw-both27 / cuts37,43,51,52 | 35,636 | 24,669,602 | 24,738,978 | 61,094 |
| raw-both31 / cuts33,43,54,60 | 35,636 | 24,670,766 | 24,740,142 | 116,228 |

The first three profiles default to split31/cuts33,43,54,60; the two orbit profiles default to37/cuts27,36,47,55. Explicit overrides remain available. Each executor redeem is five bytes shorter and the terminal is one byte shorter for the five changed profiles. Their helper bodies, registry, shared/loader programs and every Straus/Horner body/control remain exact per prior profile. Current readers, same-width tail literals, namespaces and worker commitments are checked against the prior code. Local executor savings are500/500/507 and the inverse-copy saving101; native whole-transaction measurements own the2,049 aggregate saving.

All36 fixed core/short/dense proofs pass both actualVM and pinned-native modes before and after each changed profile, with all reached budgets and DEFINE comparisons retained. Every pre-redeem proof/witness/scalar/XYZ/header/root/quotient/auxiliary/challenge byte remains fixed per prior schedule. Source-generated vectors retain all44 attack cases. The public release gate additionally requires actual owning invalid/binding/public-input/type/G2/parent-spec checks and fresh reconstruction. These are finite, conditional results; no whole-MSM/input/native envelope, universal producer/resource fit, full pairing/PIT/EIP197/subgroup mathematics, exceptional/physical-alias completeness, memory or admission claim follows.

## Earlier qualification snapshots

The byte/native figures below record earlier compiler, cache and orbit milestones. Current build metrics are in the table above.

The primary archived fixture with full pins uses **34,890 script bytes / 35,125 score**, including 235 bytes of transaction overhead. Co8 saves **18 bytes** and **124,441 native units in both modes** from the merged 35,143 revision. Minimal-number encodings make sizes vary across proofs; the five core fixtures score 35,067–35,126. Primary corrected-native cost is **24,842,233 consensus / 24,910,457 standard**. Every mathematical proof, public input, witness, quotient, auxiliary, challenge, header and derived-state byte stays fixed in this update.

**Size and copy-cost reductions.** The slim-only `genesis-slice.mjs` removes eleven unused neutral function registrations, with exact input and body hashes guarding the reviewed omission. Witness and state readers split at the start of the needed window before taking its length. Terminal pins combine fixed skips, consume checked push headers directly, and bound the copied order-reader prefix to the fixed pushes plus 33 bytes per canonical nonnegative number. All length/order/sign checks remain enabled by default. The common reader retains its previous expression for non-slim callers; the parent slicer is unchanged. The hash-guarded `prime-cache.mjs` pass applies fixed, independently checked instruction edits to the original compiler helpers. Each recipe retains one field prime at its first selected literal, lets it move within the owned stack frame, and consumes it at its last selected use. The result hash is checked as well as the original body hash. DBL caches six selected prime sites and shrinks from 269 to **262 bytes**; MADD caches all 13 sites and shrinks from 241 to **235 bytes**. Independent canonical-field interval ceilings fall from 33,533 to **32,792 VM units** for DBL and from 47,681 to **46,980** for MADD. Real helper samples save 741 units per DBL call; accepted MADD savings vary from 574 to 701 with word width. The cap reduction is not a uniform per-call saving. Original outputs, ordered guards and caller main/ALT frames are preserved under the inherited field and resource premises. Full pins, split 31, cuts 33,43,54,60 and zero padding stay fixed.

**Cache profiles.** `SLIM_CACHE` selects the byte/native-cost tradeoff for builder and producer. Unset or `floating` retains the 35,125-byte default; unknown names fail immediately. All profiles retain full pins, zero padding and helper-body hash guards. `raw-dbl` uses DBL419 with floating MADD235; `raw-madd` uses floating DBL262 with MADD605. `raw-both` uses DBL418, MADD605 and the reviewed terminal-copy and executor-cleanup identities. Parameters still default to split31/cuts33,43,54,60. The benchmark raw-both entry uses explicit `MSM_SPLIT=27 MSM_CUTS=37,43,51,52`.

| SLIM_CACHE / schedule | primary score (bytes) | native consensus | native standard | minimum sampled dense native input margin |
|---|---:|---:|---:|---:|
| floating (default) | 35,125 | 24,842,233 | 24,910,457 | 88,315 |
| raw-dbl | 35,282 | 24,830,569 | 24,899,177 | 91,689 |
| raw-madd | 35,496 | 24,690,991 | 24,759,983 | 116,994 |
| raw-both, source default split31 / cuts33,43,54,60 | 35,636 | 24,670,766 | 24,740,142 | 116,228 |
| raw-both, benchmark split27 / cuts37,43,51,52 | 35,636 | 24,669,602 | 24,738,978 | 61,094 |

For example, `SLIM_CACHE=raw-both MSM_SPLIT=27 MSM_CUTS=37,43,51,52 VERIFIER_DIR=<benchmark checkout> node export.mjs vectors.json` trades 511 additional bytes for 172,631 fewer consensus and 171,479 fewer standard native units than floating on the primary fixture. The benchmark retains the default entry and companions `-raw-dbl`, `-raw-madd` and `-raw-both`. Floating/raw-dbl/raw-madd programs and vectors remain unchanged.

Raw-both retains the hash-guarded DBL418 body (`2 PICK 3 PICK` -> `2 PICK DUP`), cap32,388 VM units and peak8. Its helper registry is3023 bytes, registration4203; MADD605 and both986-byte tables remain exact. The prior terminal identity `6 PICK 7 PICK` -> `6 PICK DUP` also remains: at the checked inverse frame both copy zInv. Its guarded313-byte middle, local cap130,359, actual peak16 and conservative17 are unchanged in this update. No DBL or terminal-middle saving is subtracted again.

The executor cleanup changes `DROP 4 ROLL DROP 4 ROLL DROP 4 ROLL DROP` to `7 ROLL 2DROP 2ROT 2DROP`. Both consume an eight-word frame and retain its zero-indexed words3..6, preserving arbitrary lower main/ALT/function-table prefixes. The source transform requires a unique complete ten-byte fingerprint at instruction boundaries and emits the independently checked five-byte replacement. It uses the existing exported cache-profile owner and applies only to raw-both. Its fingerprint excludes physical-tail literals so fixed-point construction can rebind actual lengths.

The executor stage shrinks269->264, redeem351->346/push354->349. Each of three executor inputs saves five bytes, for15 total. The executor prelude literal354->349 and genesis serializer450->445 track the new tail; namespaces, worker roots, redeems and locking commitments rebind. Terminal848, helpers, registry, loaders and every Straus/Horner body/control byte remain exact. Only executor loop offsets shift5. Independent Python/JavaScript readers and branch-aware word/cost checks preserve all unaffected steps, output frames, guards and state equalities. The two skipped branches save500 each and the active branch507; prologue peaks stay11/11/13 within the prior stage peak15. At both schedules, every72 matched archived mode records saves15 bytes and1927 native units. Local1507 is proved; remaining420 VM units are finite observations of current readers/copying.

Removing five unlocking bytes also lowers each executor's native budget by4,000 units. At default31, standard dense11 executor0 remains the limiting input: its cost falls595 but its margin falls119,633->116,228. All72 contexts still pass. The explicit27 measured minimum remains61,094. These margins come from actual per-input budgets and costs, rather than the whole-transaction saving.

All five core proofs, the short-number proof and30 archived dense proofs pass both VM/native modes for explicit27 and default31. Explicit27 qualification has19 original and19 fresh successful bounded jobs:323 source files and the owning benchmark reconstruct from frozen owners without compiler build or copying from the first candidate.26 scientific artifacts match exactly, plus one independently checked configuration-SHA difference from remapped paths. One preparer path error stopped before any plan or scientific job; a versioned preparer pins actual native stdout. Owning checks pass4/4 distinct proofs,5/5 invalids rejected,44/44 refreshed attacks rejected, four binding seams closed, nine public-input mutations rejected, isolated G2/native and TypeScript checks. Default31 has current code/reader/frame/namespace/root checks, all36 archived proofs, source44-attack regressions, native DEFINE accounting and a fresh nine-job replay.

Every complete pre-redeem prefix remains fixed against its preceding same-schedule configuration, including proof/public/VK/witness/XYZ/header/root/quotient/auxiliary/challenge values. Each schedule compares360 complete prefixes and6768 raw pushes per check. Prior statement, scalar and field-state bindings transfer by exact value and caller identity without selecting new witnesses or repeating field trajectories. These are finite conditional source/configuration qualifications. Current whole-MSM numeric caps require composition with the new readers and cleanup; prior totals do not transfer unchanged. Full pairing/PIT/EIP197/subgroup mathematics, exceptional completeness, arbitrary accepted aliases, universal producer/resource/memory fit and admission remain open. Cuts51/50 and genesis38 are not advanced because archived stress proofs exceeded operation-cost limits.

**Orbit table companion.** `SLIM_CACHE=orbit` retains floating DBL262/MADD235 and replaces both986-byte literal lookup bodies with774-byte direct-orbit lookups. It defaults to split37/cuts27,36,47,55. Existing unset/floating/raw-dbl/raw-madd/raw-both profiles and their defaults remain byte-exact. The benchmark adds `bch-groth16-intratx-pairfold5-densless-msm-slim-orbit`; all previous entries and vectors remain unchanged.

| profile | primary score (bytes) | native consensus | native standard | minimum sampled native input margin |
|---|---:|---:|---:|---:|
| orbit, split37 / cuts27,36,47,55 | 34,701 | 25,265,653 | 25,333,109 | 107,427 |

Run `SLIM_CACHE=orbit VERIFIER_DIR=<benchmark checkout> node export.mjs vectors.json`. This saves424bytes against floating while adding423,420 consensus /422,652 standard native units on the primary fixture. Raw-both remains the lower-cost companion. Full pins, five P2SH32 inputs, zero padding and the fixed public statement remain. Helpers are262/774/235/774, registry2072bytes, registration3253VM units.

The source-owned emitter packs nine of15 public points per table. Indices1,2,3 and4,8,12 and5,10,15 reconstruct using the fixed field endomorphism and Y negation. It verifies all15 restored byte pairs against the original public table before emitting bytecode, with fixed helper hashes and unique201/203 identifiers. No proof-specific secret or new witness/scalar choice enters this transform. Lookup ABI and protected lower main/ALT/function-table prefixes are checked under the retained canonical-input, authenticated-helper and successful-resource premises.

Independent Python/JavaScript source contracts classify13 numeric caller rebindings, preserve Straus/Horner body bytes, and check the new helper typed costs, readers, frames, namespaces, worker roots, redeems and lockings. Four interpreter passes each cover16,384 current counter/byte cases. Current per-position intervals are0..27 /27..36 /36..47 /47..55 /55..64. Changed intermediate XYZ states are source-derived from the same proof/witness/scalars and independently bound to all64 field steps and the final affine result. Existing raw-both numeric resource caps do not apply to orbit.

Finite qualification covers five core, one short-number and30 archived dense proofs in both actualVM and pinned-native modes, plus owning4proof/5invalid/44attack/4binding/9public/type/nativeDEFINE, archived off-curveG2 and unchanged parent/spec exports. Original17/fresh17 jobs pass with325 reconstructed source files and173 owning files;24 scientific artifacts match exactly plus one authenticated configuration-path hash difference. Public integration is checked separately against that exact compiled source. These are finite conditional results; full pairing/PIT/EIP197/subgroup mathematics, exceptional completeness, arbitrary accepted aliases, universal producer/resource/memory fit and admission remain open.

**Retained-prime table companion.** `SLIM_CACHE=orbit-retained` keeps one field-prime value within each lookup's owned frame. It emits747-byte tables instead of the direct orbit's774-byte tables, saving54 primary bytes at higher native cost. It defaults to split37/cuts27,36,47,55. `SLIM_CACHE=orbit` and every earlier profile/default remain byte-exact. The source-owned table transform accepts a validated boolean retained option; the existing cache-profile owner selects it.

| profile | primary score (bytes) | native consensus | native standard | minimum sampled native input margin |
|---|---:|---:|---:|---:|
| orbit | 34,701 | 25,265,653 | 25,333,109 | 107,427 |
| orbit-retained | 34,647 | 25,319,310 | 25,386,638 | 96,688 |

Run `SLIM_CACHE=orbit-retained VERIFIER_DIR=<benchmark checkout> node export.mjs vectors.json`. Explicit `MSM_SPLIT=37 MSM_CUTS=27,36,47,55` produces the same programs. The benchmark adds `bch-groth16-intratx-pairfold5-densless-msm-slim-orbit-retained`. Against direct orbit, this adds53,657 consensus /53,529 standard native units. Against floating, it saves478bytes and adds477,077 /476,181 native units. Raw-both remains the lower-cost companion. Full pins, zero padding and the fixed public statement remain.

Helpers are262/747/235/747, registry2018bytes and registration3199VM units. The two retained lookup bodies match the independently checked fixed-table prototypes and return all15 original public points. Arithmetic helpers, cuts and every Straus/Horner body stay exact. Python and independent JavaScript recompute all16,384 current counter/byte typed costs and frames, plus current readers, guards, namespaces, roots and terminal segments; no direct774 numeric cost table or whole-MSM envelope transfers unchanged.

All five core, one short-number and30 archived dense proofs pass both actualVM and pinned-native modes. Every pre-redeem value, including all XYZ states, witness/scalars/header/root/quotient/auxiliary/challenge values, matches the direct-orbit anchors exactly; existing finite field-state bindings transfer by identity. No new proof, witness, scalar choice or field trajectory is selected.

Finite source qualification has17 original and17 freshly reconstructed jobs:325 source files and173 private owning benchmark files,24 exact artifacts plus one authenticated configuration-path hash difference. Actual owning4proof/5invalid/44attack/4binding/9public/type/nativeDEFINE, archived off-curveG2 and parent/spec checks pass. Public integration is separately checked against those exact programs while preserving all earlier public profiles. These remain conditional finite results; full pairing/PIT/EIP197/subgroup mathematics, exceptional completeness, arbitrary accepted aliases, universal producer/resource/memory fit and admission remain open.

**Dense-witness resource sample.** `sweep.mjs` deterministically generates 30 proofs under the fixture VK using seed `densless-msm-slim-v1`. Each public-input pair is selected by a 20,000-candidate search for few zero Straus nibbles. These samples have 5–7 zero nibbles; no global structural minimum or universal resource bound is claimed. Every input must pass `stateSuccess`, and every complete transaction must pass standard BCH2026 `verify()`; a failure exits nonzero. All 30 pass. Peak standard-VM budget percentages (input order 0..4):

| exec0 | exec1 | exec2 | genesis | terminal |
|---|---|---|---|---|
| 98.1% | 95.7% | 90.2% | 98.3% | 83.8% |

`sweep-results.txt` records the earlier 36,008-byte run and seed. The table above comes from re-encoding those same 30 archived proofs with the current source, without regenerating any proof or public input. All 30 also pass consensus VM and corrected-native checks in both modes. The minimum dense-sample native input margin is **88,315 cost units**. The rebalanced schedule recovers dense-witness headroom after the cache saving shrinks the genesis budget. `SWEEP_JSON` optionally saves exact proofs, public inputs and outcomes for independent replay. These finite measurements do not establish universal resource fit, producer completeness or full statement soundness. Independent compiled reader/frame/partition checks and field-state trajectories cover the declared re-encoding; their canonical physical-tail, canonical field-state, carrier and inherited arithmetic premises remain explicit. Full pairing/PIT/EIP197/subgroup and exceptional completeness, arbitrary accepted wire aliases, universal memory/resource bounds and admission remain open.

**Regression and attack coverage.** `regression.mjs` checks default/full byte identity, all five archived fixtures, the independently pairing-checked `short-number-fixture.json`, and the public order-pin contract over zero, small integer opcodes and 31/32-byte values in both consensus and standard modes. It also refreshes the original 36 attack cases against the new code and adds all eight issue-39 cases (44 total). The first 26 originate in `redteam.mjs` as submitter suggestions; the next ten retain the upstream maintainer cases. The refresh is attributed to GPT-6.1 Sol at Kallisti's request and remains subject to upstream maintainer review. It does not claim fresh independent maintainer authorship.

The original suggested attacks retain their documented limitations: the lengthened terminal-state attack uses an honest claim, the genesis pad-shift attack is partly vacuous for this layout, and executor n0/w tampers became Y/Z tampers. The additional issue-39 cases directly check quotient/header trailers, terminal limb permutations and the fixed-table sign bit.

The original, unpinned slim and spec entries accept the eight issue-39 mutations under their respective VMs (BCH2026 / BCH_SPEC), with accepting baselines. Full-pinned slim rejects all eight. These are alternate witnesses for already-valid statements, not a demonstrated false-statement exploit.

Use a fresh output directory for each regression run:

```sh
VERIFIER_DIR=<zk-verifier-bench checkout> node export.mjs vectors.json
VERIFIER_DIR=<zk-verifier-bench checkout> node regression.mjs /tmp/slim-regression
VERIFIER_DIR=<zk-verifier-bench checkout> SWEEP_N=30 SWEEP_SEED=densless-msm-slim-v1 SWEEP_JSON=/tmp/slim-sweep.json node sweep.mjs
```

The source is qualified against [compiler-optimizations-8 commit `dab3f89fb7483372459714d262cbf0ee3debb85d`](https://github.com/mr-zwets/cashscript/commit/dab3f89fb7483372459714d262cbf0ee3debb85d). A fresh build from all 834 compiler source files reproduces all 153 emitted compiler/utils files exactly. The strict MADD recipe accepts the co8 raw-body hash `e50879bb…`, whose only difference from the prior raw helper is a removed redundant `SWAP SWAP`, and emits the same checked 235-byte cached body. All four helper bodies and their 2,496-byte registry remain exact.

Co8 inverts the fixed genesis, terminal Straus and Horner loop controls. The unchanged iteration bodies retain their typed field/frame contracts. The default fixed loops use the checked initial ranges `0<33`, `60<64` and `0<64`. Explicit schedules require their corresponding positive ranges. The dynamic executor retains an entry condition and its empty-range behavior. Independent control, reader, namespace and root checks pass. The isolated VM control checks use an explicit `t++` body projection; they are separate from whole-verifier fixture and native tests. Full MSM resource totals from the preceding compiler are not transferred unchanged.

Both 321-file source profiles reconstruct independently from the merged source plus the fixed recipe bridge and qualified pin module. Original and fresh pipelines pass the full core/dense/short/negative/attack/binding/public-input/type/G2/native checks. Thirty-six scientific outputs reproduce exactly; two corpus summaries differ only in verified source-path configuration hashes. Parent/spec exports match the upstream co8 vectors exactly. Newly pulled benchmark results and score history are preserved.

Original malleability pins: **Grothy (Grok Bot AI assistant), operated by kzKallisti**. Follow-up fixes, optimizations and validation: **GPT-6.1 Sol**, at Kallisti's request.

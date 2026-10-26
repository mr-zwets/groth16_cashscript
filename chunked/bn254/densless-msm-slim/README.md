# BN254 PairFold-5 densless with a sound vk_x: slim MSM state

> **Withdrawn (2026-10-26).** The densless author has withdrawn the full-verifier soundness
> claims for the submitted densless constructions ([#28 reply](https://github.com/mr-zwets/groth16_cashscript/issues/28), [#32](https://github.com/mr-zwets/groth16_cashscript/issues/32) F6,
> [zk-verifier-bench#49](https://github.com/mr-zwets/zk-verifier-bench/issues/49)): the shared `millerEvent` consumes slopes without the
> tangent/chord equations, the terminal's carried-R predicate compares a value with itself
> instead of checking the B endpoint, and line/root values are not bound to the committed state.
> No end-to-end false acceptance is claimed. Do not treat this verifier as sound. For a sound
> BN254 design see [`../sound-si-gls`](../sound-si-gls/README.md).

> The "soundness argument" below covers the vk_x MSM only, not the densless pairing part.

This is a variant of [`../densless-msm`](../densless-msm), with the merged upstream compiler update retained. This variant keeps the same pairing programs and the same GLV Straus vk_x MSM. It only changes where the MSM state lives. Bench entry id: `bch-groth16-intratx-pairfold5-densless-msm-slim`.

In `../densless-msm`, every stage ends with a 224-byte state push (X, Y, Z, n0, n1, w). n0, n1 and w are copied through all four stages, so 128 bytes are paid four times.

Here:

- **The public inputs are terminal pushes.** The claimed n0, n1 are the terminal's own number pushes, just below zInv and its state push. The terminal range-checks them (`0 <= n < r`) and checks the GLV decomposition of w against them. Genesis no longer carries n0, n1. The bench `publicInputs` are input 4, pushes 53 (n0) and 52 (n1).
- **w lives only in the terminal state.** The terminal's state push is w, X, Y, Z (160 bytes), and the terminal requires that exact length. It is the last push before the terminal redeem, whose length is fixed by the locking's hash. So the 160 bytes that end `back` bytes before the end of input 4's unlocking are exactly that push. Genesis reads its 33 witness bytes from this window. Each executor reads its own range from it.
- **Executor state pushes are X, Y, Z only** (96 bytes). As before, each stage pins the next stage's push from the end of the receiver's unlocking: input 0 → 1 → 2 → 4, and genesis → input 0.
- **Soundness argument** (same shape as the parent). All stages consume one w. The terminal binds that w to its claimed n0, n1 mod r. The X, Y, Z chain is pinned stage to stage. The terminal checks the final affine point against the genesis vk_x, which the Miller loop consumes. So a proof verifies only for the claimed inputs.
- **Rebalance.** Full MADD prime caching shrinks the genesis unlocking script and its op budget. The default Straus split is 31 (genesis runs positions 63..31), with witness-byte cuts 33,43,54,60. Four positions move from genesis to the executors, two each to exec0 and exec1. Global and stage padding remain zero. The two 96-byte derived states at the first two stage boundaries move from seams 37/45 to 33/43; proof, public input, quotient and auxiliary values stay fixed.

**Malleability pins** (`malleability-pins.mjs`, default `SLIM_PINS=full`): prepended once to the densless half of the terminal redeem. They pin PUSHDATA2 lengths on the terminal header/quot and each executor quot, enforce non-decreasing order on terminal limbs 2..11, and require fixed-table sign bits clear on all three executors. The order reader follows actual minimally encoded VM-number pushes, including OP_0, small integer opcodes and 31/32-byte payloads. Its helper key 151 is disjoint from sign helper 150 and the existing base/MSM namespaces. The builder and witness producer share `PIN_MODE`, so an unset environment reproduces explicit `full` output. Modes remain `0`, `lenonly`, `orderonly`, `lensign`, `lenorder`, `full`.

The primary archived fixture with full pins uses **34,908 script bytes / 35,143 score**, including 235 bytes of transaction overhead. It saves **13 bytes** and **126,624 consensus / 126,752 standard native units** from the preceding 35,156 revision. Minimal-number encodings make sizes vary across proofs; the five core fixtures score 35,085–35,144. Primary corrected-native cost is **24,966,674 consensus / 25,034,898 standard**. Every mathematical proof, public input, witness, quotient, auxiliary, challenge, header and derived-state byte stays fixed in this update.

**Size and copy-cost reductions.** The slim-only `genesis-slice.mjs` removes eleven unused neutral function registrations, with exact input and body hashes guarding the reviewed omission. Witness and state readers split at the start of the needed window before taking its length. Terminal pins combine fixed skips, consume checked push headers directly, and bound the copied order-reader prefix to the fixed pushes plus 33 bytes per canonical nonnegative number. All length/order/sign checks remain enabled by default. The common reader retains its previous expression for non-slim callers; the parent slicer is unchanged. The hash-guarded `prime-cache.mjs` pass applies fixed, independently checked instruction edits to the original compiler helpers. Each recipe retains one field prime at its first selected literal, lets it move within the owned stack frame, and consumes it at its last selected use. The result hash is checked as well as the original body hash. DBL caches six selected prime sites and shrinks from 269 to **262 bytes**; MADD caches all 13 sites and shrinks from 241 to **235 bytes**. Independent canonical-field interval ceilings fall from 33,533 to **32,792 VM units** for DBL and from 47,681 to **46,980** for MADD. Real helper samples save 741 units per DBL call; accepted MADD savings vary from 574 to 701 with word width. The cap reduction is not a uniform per-call saving. Original outputs, ordered guards and caller main/ALT frames are preserved under the inherited field and resource premises. Full pins, split 31, cuts 33,43,54,60 and zero padding stay fixed.

**Dense-witness resource sample.** `sweep.mjs` deterministically generates 30 proofs under the fixture VK using seed `densless-msm-slim-v1`. Each public-input pair is selected by a 20,000-candidate search for few zero Straus nibbles. These samples have 5–7 zero nibbles; no global structural minimum or universal resource bound is claimed. Every input must pass `stateSuccess`, and every complete transaction must pass standard BCH2026 `verify()`; a failure exits nonzero. All 30 pass. Peak standard-VM budget percentages (input order 0..4):

| exec0 | exec1 | exec2 | genesis | terminal |
|---|---|---|---|---|
| 98.3% | 95.9% | 90.4% | 98.8% | 84.5% |

`sweep-results.txt` records the earlier 36,008-byte run and seed. The table above comes from re-encoding those same 30 archived proofs with the current source, without regenerating any proof or public input. All 30 also pass consensus VM and corrected-native checks in both modes. The minimum dense-sample native input margin is **65,573 cost units**. The rebalanced schedule recovers dense-witness headroom after the cache saving shrinks the genesis budget. `SWEEP_JSON` optionally saves exact proofs, public inputs and outcomes for independent replay. These finite measurements do not establish universal resource fit, producer completeness or full statement soundness. Independent compiled reader/frame/partition checks and field-state trajectories cover the declared re-encoding; their canonical physical-tail, canonical field-state, carrier and inherited arithmetic premises remain explicit. Full pairing/PIT/EIP197/subgroup and exceptional completeness, arbitrary accepted wire aliases, universal memory/resource bounds and admission remain open.

**Regression and attack coverage.** `regression.mjs` checks default/full byte identity, all five archived fixtures, the independently pairing-checked `short-number-fixture.json`, and the public order-pin contract over zero, small integer opcodes and 31/32-byte values in both consensus and standard modes. It also refreshes the original 36 attack cases against the new code and adds all eight issue-39 cases (44 total). The first 26 originate in `redteam.mjs` as submitter suggestions; the next ten retain the upstream maintainer cases. The refresh is attributed to GPT-6.1 Sol at Kallisti's request and remains subject to upstream maintainer review. It does not claim fresh independent maintainer authorship.

The original suggested attacks retain their documented limitations: the lengthened terminal-state attack uses an honest claim, the genesis pad-shift attack is partly vacuous for this layout, and executor n0/w tampers became Y/Z tampers. The additional issue-39 cases directly check quotient/header trailers, terminal limb permutations and the fixed-table sign bit.

The original, unpinned slim and spec entries accept the eight issue-39 mutations under their respective VMs (BCH2026 / BCH_SPEC), with accepting baselines. Full-pinned slim rejects all eight. These are alternate witnesses for already-valid statements, not a demonstrated false-statement exploit.

Use a fresh output directory for each regression run:

```sh
VERIFIER_DIR=<zk-verifier-bench checkout> node export.mjs vectors.json
VERIFIER_DIR=<zk-verifier-bench checkout> node regression.mjs /tmp/slim-regression
VERIFIER_DIR=<zk-verifier-bench checkout> SWEEP_N=30 SWEEP_SEED=densless-msm-slim-v1 SWEEP_JSON=/tmp/slim-sweep.json node sweep.mjs
```

The merged upstream compiler-optimizations-8 source changes and recompiled parent/spec/reference vectors are preserved. Slim measurements use the pinned compiler/runtime from the preceding slim revision; original and emitted helper-body hashes guard compiler drift. The upstream compiler upgrade is not a co8 requalification of these slim recipes. Original malleability pins: **Grothy (Grok Bot AI assistant), operated by kzKallisti**. Follow-up fixes, optimizations and validation: **GPT-6.1 Sol**, at Kallisti's request.

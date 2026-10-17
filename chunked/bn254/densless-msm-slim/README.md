# BN254 PairFold-5 densless with a sound vk_x: slim MSM state

This is a variant of [`../densless-msm`](../densless-msm), which stays byte-for-byte unchanged and still reproduces its bench vectors. This variant keeps the same pairing programs and the same GLV Straus vk_x MSM. It only changes where the MSM state lives. Bench entry id: `bch-groth16-intratx-pairfold5-densless-msm-slim`.

In `../densless-msm`, every stage ends with a 224-byte state push (X, Y, Z, n0, n1, w). n0, n1 and w are copied through all four stages, so 128 bytes are paid four times.

Here:

- **The public inputs are terminal pushes.** The claimed n0, n1 are the terminal's own number pushes, just below zInv and its state push. The terminal range-checks them (`0 <= n < r`) and checks the GLV decomposition of w against them. Genesis no longer carries n0, n1. The bench `publicInputs` are input 4, pushes 53 (n0) and 52 (n1).
- **w lives only in the terminal state.** The terminal's state push is w, X, Y, Z (160 bytes), and the terminal requires that exact length. It is the last push before the terminal redeem, whose length is fixed by the locking's hash. So the 160 bytes that end `back` bytes before the end of input 4's unlocking are exactly that push. Genesis reads its 37 witness bytes from this window. Each executor reads its own range from it.
- **Executor state pushes are X, Y, Z only** (96 bytes). As before, each stage pins the next stage's push from the end of the receiver's unlocking: input 0 → 1 → 2 → 4, and genesis → input 0.
- **Soundness argument** (same shape as the parent). All stages consume one w. The terminal binds that w to its claimed n0, n1 mod r. The X, Y, Z chain is pinned stage to stage. The terminal checks the final affine point against the genesis vk_x, which the Miller loop consumes. So a proof verifies only for the claimed inputs.
- **Rebalance.** The genesis unlocking, and with it the genesis op budget, shrank by 189 bytes. The Straus split moves 26 → 27 (genesis runs positions 63..27), and the cuts become 37,45,54,60.

**Malleability pins** (`malleability-pins.mjs`, default `SLIM_PINS=full`): prepended once to the densless half of the terminal redeem. They pin PUSHDATA2 lengths on the terminal header/quot and each executor quot, enforce non-decreasing order on terminal limbs 2..11, and require fixed-table sign bits clear on all three executors. The order reader follows actual minimally encoded VM-number pushes, including OP_0, small integer opcodes and 31/32-byte payloads. Its helper key 151 is disjoint from sign helper 150 and the existing base/MSM namespaces. The builder and witness producer share `PIN_MODE`, so an unset environment reproduces explicit `full` output. Modes remain `0`, `lenonly`, `orderonly`, `lensign`, `lenorder`, `full`.

The five archived fixtures with full pins use **35,438 script bytes / 35,673 score**, including 235 bytes of transaction overhead. This saves 335 bytes from the previous 36,008 pinned revision, and is 314 above unpinned slim (35,359) / 208 below the original densless-msm entry (35,881). The five archived mathematical proofs and public inputs are unchanged. Primary corrected-native cost is **24,825,908 consensus / 24,895,284 standard**, down 310,340 / 310,980 units from that pinned revision.

**Size and copy-cost reductions.** The slim-only `genesis-slice.mjs` removes eleven unused neutral function registrations, with exact input and body hashes guarding the reviewed omission. Witness and state readers split at the start of the needed window before taking its length. Terminal pins combine fixed skips, consume checked push headers directly, and bound the copied order-reader prefix to the fixed pushes plus 33 bytes per canonical nonnegative number. All length/order/sign checks remain enabled by default. The common reader retains its previous expression for non-slim callers; the parent slicer is unchanged.

**Dense-witness resource sample.** `sweep.mjs` deterministically generates 30 proofs under the fixture VK using seed `densless-msm-slim-v1`. Each public-input pair is selected by a 20,000-candidate search for few zero Straus nibbles. These samples have 5–7 zero nibbles; no global structural minimum or universal resource bound is claimed. Every input must pass `stateSuccess`, and every complete transaction must pass standard BCH2026 `verify()`; a failure exits nonzero. All 30 pass. Peak standard-VM budget percentages (input order 0..4):

| exec0 | exec1 | exec2 | genesis | terminal |
|---|---|---|---|---|
| 92.3% | 89.6% | 90.1% | 99.6% | 84.4% |

`sweep-results.txt` records the earlier 36,008-byte run and seed. The table above comes from re-encoding those same 30 archived proofs with the current source, without regenerating any proof or public input. All 30 also pass consensus VM and corrected-native checks in both modes. The minimum dense-sample native input margin is **19,961 cost units**; genesis has less budget headroom after shrinking its unlocking script. `SWEEP_JSON` optionally saves exact proofs, public inputs and outcomes for independent replay. These finite measurements do not establish universal resource fit, producer completeness or full statement soundness.

**Regression and attack coverage.** `regression.mjs` checks default/full byte identity, all five archived fixtures, the independently pairing-checked `short-number-fixture.json`, and the public order-pin contract over zero, small integer opcodes and 31/32-byte values in both consensus and standard modes. It also refreshes the original 36 attack cases against the new code and adds all eight issue-39 cases (44 total). The first 26 originate in `redteam.mjs` as submitter suggestions; the next ten retain the upstream maintainer cases. The refresh is attributed to GPT-6.1 Sol at Kallisti's request and remains subject to upstream maintainer review. It does not claim fresh independent maintainer authorship.

The original suggested attacks retain their documented limitations: the lengthened terminal-state attack uses an honest claim, the genesis pad-shift attack is partly vacuous for this layout, and executor n0/w tampers became Y/Z tampers. The additional issue-39 cases directly check quotient/header trailers, terminal limb permutations and the fixed-table sign bit.

The original, unpinned slim and spec entries accept the eight issue-39 mutations under their respective VMs (BCH2026 / BCH_SPEC), with accepting baselines. Full-pinned slim rejects all eight. These are alternate witnesses for already-valid statements, not a demonstrated false-statement exploit.

Use a fresh output directory for each regression run:

```sh
VERIFIER_DIR=<zk-verifier-bench checkout> node export.mjs vectors.json
VERIFIER_DIR=<zk-verifier-bench checkout> node regression.mjs /tmp/slim-regression
VERIFIER_DIR=<zk-verifier-bench checkout> SWEEP_N=30 SWEEP_SEED=densless-msm-slim-v1 SWEEP_JSON=/tmp/slim-sweep.json node sweep.mjs
```

Parent `densless-msm` and `densless-msm-spec` source and vector outputs remain unchanged. Original malleability pins: **Grothy (Grok Bot AI assistant), operated by kzKallisti**. Follow-up fixes, optimizations and validation: **GPT-6.1 Sol**, at Kallisti's request.

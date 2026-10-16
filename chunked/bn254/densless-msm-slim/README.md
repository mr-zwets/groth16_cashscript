# BN254 PairFold-5 densless with a sound vk_x: slim MSM state

This is a variant of [`../densless-msm`](../densless-msm), which stays byte-for-byte unchanged and still reproduces its bench vectors. This variant keeps the same pairing programs and the same GLV Straus vk_x MSM. It only changes where the MSM state lives. Bench entry id: `bch-groth16-intratx-pairfold5-densless-msm-slim`.

In `../densless-msm`, every stage ends with a 224-byte state push (X, Y, Z, n0, n1, w). n0, n1 and w are copied through all four stages, so 128 bytes are paid four times.

Here:

- **The public inputs are terminal pushes.** The claimed n0, n1 are the terminal's own number pushes, just below zInv and its state push. The terminal range-checks them (`0 <= n < r`) and checks the GLV decomposition of w against them. Genesis no longer carries n0, n1. The bench `publicInputs` are input 4, pushes 53 (n0) and 52 (n1).
- **w lives only in the terminal state.** The terminal's state push is w, X, Y, Z (160 bytes), and the terminal requires that exact length. It is the last push before the terminal redeem, whose length is fixed by the locking's hash. So the 160 bytes that end `back` bytes before the end of input 4's unlocking are exactly that push. Genesis reads its 37 witness bytes from this window. Each executor reads its own range from it.
- **Executor state pushes are X, Y, Z only** (96 bytes). As before, each stage pins the next stage's push from the end of the receiver's unlocking: input 0 → 1 → 2 → 4, and genesis → input 0.
- **Soundness argument** (same shape as the parent). All stages consume one w. The terminal binds that w to its claimed n0, n1 mod r. The X, Y, Z chain is pinned stage to stage. The terminal checks the final affine point against the genesis vk_x, which the Miller loop consumes. So a proof verifies only for the claimed inputs.
- **Rebalance.** The genesis unlocking, and with it the genesis op budget, shrank by 189 bytes. The Straus split moves 26 → 27 (genesis runs positions 63..27), and the cuts become 37,45,54,60.

**Malleability pins** (`malleability-pins.mjs`, default `SLIM_PINS=full`): prepended once to the densless half of the terminal redeem. They pin PUSHDATA2 lengths on the terminal header/quot and each executor quot, enforce non-decreasing order on terminal witness limbs 2..11, and require fixed-table sign bits clear on all three executors. This closes eight witness-malleability findings that also affect the parent entry (none allow a false statement). Modes: `0`, `lenonly`, `orderonly`, `lensign`, `lenorder`, `full`.

Result on the official fixtures with `SLIM_PINS=full`: 35,804 script bytes (bench score 36,039). Unpinned slim was 35,124 script / 35,359 score; parent is 35,646 script / 35,881 score. The +680 vs unpinned slim / +158 vs parent pays for closing the eight malleability holes.

**Worst-case op-cost** (`sweep.mjs`, results in `sweep-results.txt`): 30 fresh proofs under the fixture VK, with public inputs chosen for the densest GLV witnesses (6–7 zero nibbles out of 128, the structural minimum), evaluated in one transaction on the standard BCH 2026 VM. All 30 are accepted. Peak use of each input's budget:

| | exec0 | exec1 | exec2 | genesis | terminal |
|---|---|---|---|---|---|
| slim (SLIM_PINS=full) | 92.6% | 90.0% | 90.4% | 95.9% | 86.4% |
| parent, same sweep | 90.3% | 84.7% | 87.9% | 96.1% | 86.9% |

The parent row matches the README figures for `../densless-msm`.

**Red-team.** `redteam.mjs` here is a **submitter suggestion**. It is not maintainer-authored. It adapts the parent's 26 runs to this layout. These runs change or weaken relative to the parent:

- the "lengthened state push" run now lengthens the terminal push, without a forged claim;
- the "pad-shift" run is partly vacuous, because genesis no longer reads witness bytes from its own pushes;
- the n0 and w tamper runs on executor states became Y and Z tampers.

The maintainers should author attacks for the new terminal-window read.

```sh
VERIFIER_DIR=<zk-verifier-bench checkout> node export.mjs vectors.json
VERIFIER_DIR=<zk-verifier-bench checkout> SWEEP_N=30 node sweep.mjs
```

The changes to `../pairfold5-msm/vkx-msm.mjs` are behind a new `pinN` option of `sourceA`. With the option off (the parent and densless-msm-spec), the output is byte-identical.

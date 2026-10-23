# BN254 PairFold-5 densless with on-chain vk_x: one input (bch-spec)

Single-input variant of [`../densless-msm-spec`](../densless-msm-spec) for the proposed bch-spec
VM (100,000-byte scripts, per-input op-cost budget `(10,000 + unlocking length) * 800`). Bench
entry id: `bch-groth16-pairfold5-densless-msm-spec-single`.

The 5-input spec entry only splits the verifier because bch-2026 caps scripts at 10,000 bytes.
Here the same five programs (genesis, three executors running kallisti's shared program,
terminal) and the same GLV Straus vk_x MSM run one after another in ONE P2SH32 redeem, on one
stack. The statement is unchanged: full Groth16 under the fixed VK of the locking, with vk_x
recomputed on-chain from the claimed public inputs n0, n1 (the last two pushes before the redeem,
55 and 54).

## What changed, and why it is sound

`build.mjs` takes the spec entry's programs byte for byte (`sources.mjs`: the symbolic shared and
terminal programs, the sliced genesis) and applies a short list of edits, each asserted to match
exactly once:

- **Stage hand-off instead of re-checked pushes.** Genesis built header 0 and required it to equal
  input 0's header push; each executor built the next header and required it to equal the next
  input's header push. Those equalities become hand-offs (the built value goes on the altstack and
  the next stage takes it), so headers 0..3 are no longer pushed. The next stage starts from the
  exact value the original equality forced.
- **No input-index dispatch.** The shared program selected its per-input constants with
  `OP_INPUTINDEX`; each stage call now pushes the same constants (`STAGE_CONSTANTS`).
- **Reads that were introspection become stack values.** Each executor's fixed table moves to the
  altstack before its stage. The quotient is one push holding the same concatenation the terminal
  hashed. The selector opcode byte is byte 0 of the unlocking (the selector is the first push).
  The terminal's c and c^-1 values are decoded from a copy of genesis push 18, which holds the same
  24 field elements and whose length genesis checks. Restricting the terminal to those values
  admits no witness the original accepted for a different statement.
- **MSM returns vk_x** (`msm-single.mjs`, the same math as `../pairfold5-msm/vkx-msm.mjs`
  sourceFull). It no longer compares against bytes 131..195 of genesis push 0. The glue splices it
  into that block (pushed without vk_x), requires the block to be exactly 448 bytes and defines
  function `G`, a single push of the block. Genesis, the executors and the terminal call `G` where
  they read genesis push 0. The length check is what makes `G` a pure push: a longer block would
  run its tail as code.
- **Straus tables built on-chain** from IC1, IC2, [2^64]IC1, [2^64]IC2 and beta, with 22 mixed
  adds and a batch normalization whose final inverse is a per-half constant. This is
  input-independent: the JS reference is asserted equal to `GLV_SPLIT_TABLE_HEX` and every fixture
  exercises all entries.
- **Removed:** the 5-input structure/worker-locking pins, the executor loader and fragment hash
  (the shared program is now part of the redeem), and the input-dispatch checks.
- **Size passes** (`optimize.mjs`, semantics-preserving): repeated constants become functions,
  functions whose fully inlined instruction streams are identical are merged, inlining where it is
  cheaper, and 1-byte identifiers go to the most-referenced functions.

**Stage isolation is checked, not assumed** (`stack-audit.mjs`, run by every build). It abstractly
interprets the whole redeem over a stack whose initial items are labelled by owning stage. Calls
are inlined, loop counters and depths are constant-folded, both arms of witness-dependent branches
are explored, and every branch must rejoin at the same height. The build fails if any stage
touches another stage's item or value outside the explicit hand-off list (`allowed` in
`build.mjs`), if any PICK/ROLL depth is not a constant, or if the redeem does not end with exactly
one item. The push count is pinned by consensus clean-stack (exactly one item on exit): extra
pushes stay on the stack, and missing ones underflow.

**Malleability pins** (`SINGLE_PINS`, default on, 48 bytes) cover the issue-39 classes that survive
the merge. The terminal's ten boundary-line evaluations must be in ascending order, since any
permutation was accepted. Every fixed-table limb must be canonical (0 <= x < p), which covers both
the sign bit and +p.

## Results (fixture 0)

| | 5-input spec | single |
|---|---|---|
| redeem bytes | 3 x 79 + 6,462 + 3,354 | 9,411 |
| script bytes (locking + unlocking) | 33,640 | 28,370 |
| tx overhead | 235 | 63 |
| **score** (harness) | **33,875** | **28,433** |
| op-cost (fixture 0, consensus) | 24.05M over 5 budgets | 25.70M of 30.67M |

Liveness sweep (`sweep.mjs`, bch-spec consensus and standard) over the five fixtures, the
constructed case n0 = 40988...880, n1 = 0, forced witnesses making all 128 Straus additions (an
upper bound for any GLV witness), random proofs and dense-searched proofs, all minted under the
fixture VK.

- **Current build** (`SWEEP_N=100 SWEEP_DENSE=0 SWEEP_FORCED=20`): 126 cases, all accepted in both
  modes. The worst case is a forced 128-addition witness, with a minimum margin of **3,897,402
  standard / 3,945,402 consensus** (87.3% of budget). Random proofs peak at 26.29M. The
  constructed case uses 22.79M (margin 7.85M standard).
- **Co-8 MSM, superseded** (`SWEEP_N=400 SWEEP_DENSE=40 SWEEP_FORCED=20`): an identical program
  apart from the compiler of the MSM. All 466 cases were accepted, with a minimum margin of
  3,856,913 standard.

## Reproduce

**Compiler.** cashc from [`mr-zwets/cashscript`](https://github.com/mr-zwets/cashscript), branch
`zk-language`, commit `efc6ab8` ("zk-language milestone 1"). It compiles the only cashc code in
this build: the MSM in `msm-single.mjs`. It is expected as a built checkout named `cashscript-zk`
next to this repository; set `CASHC_ZK=<path to its packages/cashc/dist/index.js>` to use another
location. The compiled MSM is hash-guarded (`MSM_SHA256`), so any other compiler fails the build.
The shared, genesis and terminal programs are assembled by `assemble.mjs`, a verbatim copy of the
spec entry's assembler. `../../pairing/_millermath.mjs` (the VK and GLV constants) still imports
the repository's default `cashc` link, but nothing in this build compiles through it.

```sh
# compiler (once), next to this repository
git -C <cashscript clone> worktree add --detach ../cashscript-zk efc6ab8   # or clone mr-zwets/cashscript into cashscript-zk and check out efc6ab8
cd ../cashscript-zk && npx -y yarn@1.22.22 install --ignore-scripts --frozen-lockfile
(cd packages/utils && npx tsc -p tsconfig.build.json) && (cd packages/cashc && npx tsc -p tsconfig.build.json)

# from this directory, with the repository's own dependencies installed (pnpm install)
export VERIFIER_DIR=<zk-verifier-bench checkout>
node build.mjs                                   # redeem 9,411 B, sha256 c80cfcee...c4f5; runs the stack audit
node export.mjs vectors.json                     # bench vectors, byte-exact (sha256 231412ed...5e91)
node redteam.mjs vectors.json redteam.json       # 98 runs, each checked rejected (sha256 b51cda36...1d9e)
SWEEP_N=100 SWEEP_DENSE=0 SWEEP_FORCED=20 node sweep.mjs sweep.json   # SWEEP_SHARD=k/n to split
```

In zk-verifier-bench: copy `vectors.json` to
`src/bch/groth16-pairfold5-densless-msm-spec-single-vectors.json` and `redteam.json` to
`src/bch/redteam/bch-groth16-pairfold5-densless-msm-spec-single.json`, then run
`pnpm benchmark densless-msm-spec` (gates) and `pnpm benchmark:json` (score).

## Open risks (inherited, not introduced here)

- **The running B point is not used by the accept decision.** The B-line slopes (executor witness
  limbs and genesis pushes 4 and 5) only feed the B coordinates in the stage headers, and the
  terminal accepts any B coordinates in header 3. The 5-input spec entry behaves the same way: it
  accepts a changed slope once the downstream header pushes are rewritten to match. These
  limbs are therefore excluded from the red-team tamper set. Whether this freedom matters for
  soundness depends on how the protocol binds the B-line evaluations in the fixed tables. That
  needs a protocol-level review of the densless design and was not established here. The open
  question (what binds the fixed-table words and the B-point headers) is tracked in
  [#28](https://github.com/mr-zwets/groth16_cashscript/issues/28).
- **Field-element aliasing.** Numeric witnesses used only mod p (terminal values, genesis pushes
  2..17, zInv, executor witness limbs) still accept +-p aliases, as in the spec and slim entries.
  These are alternate witnesses for the same statement.

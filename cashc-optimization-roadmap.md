# cashc optimization roadmap (upstream-mergeable)

Goal: an optimized compiler for big, advanced contracts (heavy on-stack cryptography: ZK
verifiers, post-quantum constructions), mergeable into mainline CashScript. Byte savings on
stack juggling/scheduling are the headline target, op-cost second.

Admission rule for language constructs: new syntax is allowed when the win justifies the
surface area. Calibration anchors already on the branches: the `unused` modifier (tiny
surface, niche op win) and tuple-destructure-into-existing-variables (small grammar delta,
measured -16% finalexp / -6% verify in loops). Candidates are judged win-per-unit-of-surface
against those two. Out of scope regardless: a chunking backend (stays project-side tooling).

Provenance: three rounds of adversarial review against the actual code of both repos (this
repo and the cashscript fork, branch `compiler-optimizations`), claims checked against
code and measurement docs, followed by applied A/B measurement of every project-side item
(2026-07-08). Corrections to earlier premises are recorded so the numbers stay honest.
Calibration lesson from those measurements: static sizing was wrong in both directions
(outlining's "under 1-2%" prior was off by 10x low, the unroll's "~2-4%" census sizing had
the wrong sign), so on this stack only applied, end-to-end-verified A/Bs settle a lever.

## Ground truth (already banked or already settled, do not re-plan)

- `rescheduleStacks` is landed and opt-in: per-block min(original, rescheduled), wholesale
  fallback on invariant violation, and the dead-computation soundness hole is closed
  fail-closed (`stack-rescheduling.ts:683-730` keeps such blocks verbatim; adversarial tests
  at `test/stack-rescheduling.test.ts:100-166`). Measured: -37.7% bytes on the plain BN254
  singleton, -4.9..-6.7% op-cost on chunked families. Restriction: single-function
  contracts only (`compiler.ts:188`).
- The multi-item peephole fusions (OVER OVER to 2DUP, 3-PICK pairs to 2OVER, 3-ROLL pairs
  to 2SWAP, 5-ROLL pairs to 2ROT) already exist upstream (`utils/src/optimisations.ts:15-22,37`).
- Right-to-left liveness-aware argument staging and zero-op frame cleanup when the frame is
  clean are already implemented in the fork (`GenerateTargetTraversal.ts:817-839, 269-276`).
- Loop seam/boundary solving was censused and is a non-starter on op-bound builds: only
  ~0.3-0.5M op of real per-boundary seam overhead against a ~181.5M flagship
  (`chunked/rescheduler/README.md:43-48`).
- The project-side harvest is done (2026-07-06): the BLS12-381 chunk builds and the shamir
  vk_x build compile through rescheduleStacks (groth16_contract commits 518f0f6 and
  a991f1b; verifier rebuild 1636d98). Measured: BLS chunked -1.8..-2.4% (more
  arithmetic-bound than BN254's -4.9..-6.7% class), vk_x family -8..-23%. The "not yet
  ported" line in `chunked/rescheduler/README.md` is stale.
- The calling-convention residual is resolved (measured 2026-07-08): the ~5M op estimate
  was already fully recovered by the right-to-left staging fix (commit 1772656), before the
  rescheduler even runs. On the miller_00 window, executed instructions per window-op: old
  convention 2,113, current plain compile 2,111, rescheduled 1,926 (8.9% below old); the
  production vectors sit 14.7M op below the old-convention baseline on miller+finalexp. No
  fork-side recovery is left to book. The upstream case is unaffected: upstream `next`
  still ships the expensive convention, and the staging fix is the thing to PR (item 1).
- The census spike ran (2026-07-08, tool `singleton/bn254/recompiler/outline_spike.mjs`)
  and closed both remaining scheduling levers. Depth layout is dead: on the 8,385 B golfed
  singleton the 16-hot greedy oracle grosses 397 B against ~408 B of demotion risk plus
  ~800 B of relayout cost across 15 regions, net decisively negative vs the 300 B build
  threshold (plain BN254 366 B gross and BLS 406 B gross look the same);
  cashc-stack-optimization.md carries the dated closing note. No unroll pass either:
  g2check is already straight-line, only the vk_x families survive rolled, their ~5%
  per-iteration scaffold cannot be recovered (full unroll blows the byte caps at ~330 B
  per iteration; partial unroll was then MEASURED 2026-07-08 as an op regression, not a
  win — see item 7 for the numbers and the mechanism the census sizing missed).
- Structs monomorphized to flat slots save approximately zero bytes: signatures have no
  bytecode representation, calls are already 2 bytes, and the scheduler is DAG-based and
  type-blind (`arrays.md` reaches the same conclusion for compile-time-indexed locals).
  Purely an ergonomics feature; if upstream wants it, that is a DX decision outside this
  roadmap's win axis.
- Runtime-indexed tables are already at the O(1) floor in pure CashScript: the blob plus
  runtime-`split` idiom hits 1,228,236 op vs the 1,202,812 floor for the 128-lookup select
  loop (`chunked/pairing/select16-blob-table.md:63-77`), and `select16` is the only
  runtime-indexed table in the codebase (Miller line coefficients are consumed
  sequentially).
- Post-golf byte floor on the singleton: 54% of remaining bytes are ROLL/PICK addressing
  (32% depth-arg pushes, 22% opcodes), 25% irreducible constant data
  (`cashc-stack-optimization.md`). The addressing tax is inherent to the stack VM as
  EXECUTED cost; as STATIC bytes it turned out ~23% compressible, because the golf
  scheduler emits the same relayout runs at many boundaries (see item 6, measured
  2026-07-08). Only a VM change removes the executed tax (see strategic addendum).

## Roadmap

Status: the COMPILER-side track is complete. Items 6 and 7 are built/closed, and with them
every compiler-level lever for this project's scores is either banked or measured dead, on
both axes (bytes: outlining shipped, depth layout dead; op: scheduling within ~0.04% of
solver-optimal, unrolling a regression, convention recovered, seams a non-starter). The
outstanding project-side work moved to the BUILDERS: the compounding slack-trim/replan
sweep in item 7's addendum, expected to dwarf the closed scheduling results. Items 0-5 are
the upstream merge track and have not started. Remaining headroom beyond both is
math/advice-level (see the sweep note in item 7).

### 0. Merge gate: correctness and test infrastructure (before any optimization PR)

A conservative maintainer will not discuss optimization or language PRs while
funds-relevant bugs are open on the same branch. Sequencing, not polish.

- Burn down the known checking-layer bugs: destructuring into constants/function names,
  duplicate tuple targets, the `insideTupleAssignmentRhs` silent discard
  (`branch-review.md:35-48`), the constant-folding div-by-zero compiler crash
  (`branch-review.md:40`, also a prerequisite for item 4), locktime memo poisoning, and
  the debug-frame/bytecode consistency invariant (`next-review.md`).
- Shared differential-testing and fuzzing harness as a first-class deliverable:
  grammar-driven random contracts covering the full AST surface, random witnesses and tx
  contexts, plain-vs-optimized accept/reject and final-stack equality. Every item below
  needs it, and it is the artifact that makes upstream relax.
- Compile-time CI benchmark. Nothing today measures what `rescheduleStacks` or
  compile-both-and-keep-smaller costs in seconds; that is the first maintainer question.
- Two-line fix now: record `rescheduleStacks` in the compilation artifact for
  reproducibility, as already done for `optimizeFor` (commit c0657c8).

### 1. Upstream PR during the 0.14.0-next cycle: calling convention + inliner

The 0.14.0 pre-releases explicitly reserve the right to change compiler output between
`-next` versions, which makes this cycle the designed moment to improve the
OP_DEFINE/OP_INVOKE convention introduced in #413 (~+4.8% executed instructions per call
from staging plus frame cleanup, +1.3..2.3% op on op-bound builds,
`cashc-next-op-regression.md` section 7). Once 0.14.0 final ships, the convention becomes
stable output that tooling and fixtures build on, so the natural deadline is the end of the
pre-release series, not any particular day. The fork's right-to-left liveness-aware staging
and the byte-exact inliner (`isWorthInlining`) are done and measured; they are also the
foundation the item-2 language PRs assume, which is why this goes first. Pitch the PR on
upstream's measured per-call regression; do not book any fork-side recovery, which the
2026-07-08 measurement showed is already fully banked (see ground truth).

### 2. Language-construct PR train: the existing fork features

Under the admission rule these are upstream arguments to make, not fork-forever features.
Order within the train, by dependency and case strength:

1. Multi-returns + tuple-reassign-into-existing-variables as one package (tuple-reassign
   is meaningless without multi-returns, and they share the grammar family). The case:
   tuple-reassign answers upstream issue #136 with the measured -16% finalexp / -6% verify
   loop wins, and multi-returns is the enabler the calling-convention PR's staging design
   assumes. Evidence package: the loop measurements, the gate-0 semantic-hardening fixes
   (the PR dies in review without them), mocknet execution tests, and the convention doc
   (`docs/function-call-convention.md`).
2. Top-level constants: trivial surface, universal DX precedent, byte-neutral. Easy
   accept; can ride with the calling-convention PR.
3. `unused` last, weakest case. Expect the maintainer counter-proposal of a `_` wildcard
   in destructuring positions instead of a new reserved word (which breaks contracts using
   `unused` as an identifier). Prepare both designs; concede the wildcard if pushed.

### 3. Cost diagnostics + per-path lazy defines (one PR train)

Diagnostics: per-function byte and op-cost table in the compilation artifact, warnings near
the 10,000-byte standardness cap. Cheapest genuine upstream goodwill on the list; the
op-cost meter already exists inside the rescheduler. Design constraints: loops without
constant bounds report per-iteration cost, not a total; report minimum unlocking bytes
required rather than a pass/fail budget verdict (the budget depends on unlocking length the
compiler cannot know); the meter must match the VM's exactly and carry a VM-version tag.

Lazy defines: today all OP_DEFINE bodies are emitted in the preamble before the selector
(`defineGlobalFunctions`, `GenerateTargetTraversal.ts:167-181`), so every spend path pays
~300 + bodyBytes op-cost for every helper, including helpers only other paths use. Sink
each define into the unique selector arm that uses it (dominator placement); shared helpers
stay in the preamble. Never-worse on both axes: locking bytes identical (elements move, not
duplicate), op-cost strictly better on paths that skip the define. VM-legal: libauth
BCH2026 wraps OP_DEFINE in conditionallyEvaluate, and same-id defines in mutually exclusive
arms are fine. Honest pricing: ~350-500 op per skipped helper per spend, negligible for
ordinary contracts, real for op-bound multi-path covenants. Note this repo gains exactly
nothing: every groth16 contract has a single spend function (no selector arms, so no
helper belongs to "another path", and dead-code elimination already strips uninvoked
helpers). This is purely an upstream-users item, justified as goodwill alongside the
diagnostics, not by project scores. About two days. Duplicating shared helpers into
multiple arms is a locking-size regression; do not lead with it.

### 4. Interprocedural constant folding (whitelist v1)

Fold user-function calls whose arguments are all compile-time constants by evaluating the
body in the compiler on bigints. Zero new syntax; the infrastructure exists
(`inlineConstants`, `constant-folding.ts`). Whitelist v1: pure int arithmetic only (JS
BigInt semantics match the VM's truncated div/mod exactly), refuse to fold on any
abort-possible evaluation (div/mod by zero, operand-size limits), no bytes ops, no folding
through loops or branches on non-constant conditions. Win class: bytes, small but universal
for mainline users. For this repo it is mostly maintainability: the generators already fold
in JS, so do not claim project score wins. Prerequisite: the gate-0 div-by-zero crash fix
lives on the same code path.

### 5. Rescheduler v2: productization toward default-on

Rescoped from "fix the soundness hole" (already closed fail-closed) to three upgrades:

- Effect anchoring: reschedule dead-computation blocks instead of bailing, by emitting
  every effectful or abort-capable node as an anchored root (no ordering edges needed
  among anchors: accept/reject is order-independent among failures; DROP dead results).
  The whole risk is completeness of the abort-capability table: derive it from libauth
  instruction metadata and fail closed on unknown opcodes; keep the hasDeadComputation
  guard as belt and suspenders. Expected byte win on this codebase: near zero
  (VERIFY-family ops are already block boundaries); the value is generality for upstream.
- Multi-function support via per-selector-arm regions (each top-level IF arm has a
  deterministic entry depth given the selector shape). Without this, default-on is a
  misleading no-op for nearly every mainline user.
- Published compile-time benchmarks, with a size cutoff that degrades to plain compile
  rather than slow compile (precedent: OPTIMISATION_CROSS_CHECK_MAX_OPS).

Differential testing remains a smoke alarm, not the soundness argument: random-vector
testing silently loses coverage on guard-heavy bodies whose reference run fails on random
inputs. The soundness story is the fail-closed structure.

Graduation criteria to default-on under optimizeFor (the exit condition from opt-in):

1. Two minor releases (or ~6 months) opt-in with zero soundness reports, including
   third-party use.
2. Grammar-driven fuzz corpus (loops, branches, functions, multi-returns, void guards,
   `unused`) times random witnesses/tx contexts; on the order of 10^5 plain-vs-rescheduled
   pairs nightly with zero divergences; full fixture corpus compiled both ways with
   semantic-equivalence checks.
3. Abort table generated from libauth metadata, unknown opcodes treated as effectful,
   wholesale identity fallback retained.
4. Never-worse asserted in CI per block on the fixture corpus, both objectives.
5. Compile time at most 1.5x baseline p95 on the corpus, big-contract benchmark published.
6. Debug parity: element-aligned source map, re-anchored requires, console.log blocks
   untouched, SDK debugger runs end-to-end on rescheduled artifacts, and the
   frame-to-bytecode consistency invariant landed first.
7. Deterministic, byte-identical output across platforms and Node versions.
8. Multi-function support landed.
9. Flag recorded in the artifact, CLI escape hatch exists.
10. Instruction-set version pinned with a documented per-VM-year upgrade procedure.

### 6. Auto-outlining: BUILT project-side 2026-07-08 (prior was wrong by an order of magnitude)

The spike flipped this item and the project-side pass shipped the same day:
`singleton/bn254/recompiler/outline.mjs`. Mechanism: byte-exact factoring of repeated
instruction subsequences (>= 5 B, balanced control flow, no
OP_DEFINE/OP_ACTIVEBYTECODE/BEGIN/UNTIL inside) into new OP_DEFINE bodies, greedy per
pass, iterated to a fixpoint so outlined bodies are themselves scanned; every rewrite
batch is verified accept-valid/reject-tampered on the loose VM with per-rewrite isolation
on failure, and the full multiproof battery gates the vectors.

Entry taxonomy (settled 2026-07-09): outlining lives in the OPTIMIZED entries only. The
plain singleton entries stay unprocessed compiler output so each curve keeps both ends of
the bytesize-vs-opcost tradeoff on the board (outlining trades a few percent op for ~25%
bytes). The BLS optimized build (`singleton/bls12-381/build_vectors_optimized.mjs`)
A/Bs the golf recompile against the rescheduled compile, outlines both, and keeps the
smaller verified artifact; the golf recompiler proved curve-agnostic out of the box (only
the diff-test input range is parameterized, `setTestInputRange`).

| entry | locking | op-cost | role |
|---|---:|---:|---|
| bch-groth16-singleton | 8,515 B | 746.9M | plain compiler output (BN254) |
| bch-groth16-singleton-opcode-optimized | 6,314 B | 795.9M | golf recompile + outline |
| bch-groth16-bls12381-singleton | 9,219 B | 1,035.3M | plain compiler output (BLS) |
| bch-groth16-bls12381-singleton-opcode-optimized | 6,428 B | 1,058.1M | golf recompile + outline |

Fixpoint iteration beat the single-pass spike numbers (BN254 3 passes: 67+14+2 sequences;
BLS golf 3 passes: 79+22+1). The "sources are already factored into functions" prior
missed that the savings are not source-level: they are repeated ROLL/PICK relayout runs
the schedulers emit at block boundaries, plus repeated PICK fans and `<32B prime> MOD`
pairs. Remaining upside, unbooked: smarter-than-greedy selection. Upstream as a
size-objective compiler pass only after the project-side pass has soaked; under opcost it
stays exactly what collectLoopExcludedFunctions exists to prevent, and debug info for
synthetic frames must be answered before any upstream PR.

### 7. Op-over-bytes experiments for the chunked families (measured 2026-07-08, both closed)

The exchange rate that governs every tradeoff here: at the standard limits, op budget
scales with unlocking length at ~800 op per byte, so 800 op saved is worth ~1 B of padding
score, while a locking byte costs score 1:1. Chunks are packed to the ~8,032,800 ceiling
(the maximum budget at the 10,000 B input cap), so op savings pay off primarily by growing
chunk windows and eliminating whole inputs. REPRICED by the 2026-07-09 accounting harness:
an eliminated fused-miller chunk is worth ~3.9 kB of re-baked constants plus its padding
share plus envelope, roughly 50x the ~76 B envelope figure the levers below originally
assumed, which makes chunk-count reduction the main prize of the sweep.

Already settled op-optimally, do not re-chase: in-loop inlining (measured ~2.8x op
regression: the VM charges per stepped opcode even in untaken branches, so a body spliced
into a loop is stepped every iteration while a skipped OP_INVOKE site costs 2 opcodes;
rationale and measurements at `GenerateTargetTraversal.ts:1189-1205`, branch-aware variant
measured +-0 and rejected), define-vs-inline economics generally (define bodies are pushed
as data, not stepped, so keeping shared helpers defined wins on both axes for multi-use
bodies), seam solving (censused), and the calling convention (fully recovered).

Both experiments ran end-to-end on the BN254 pairing family (2026-07-08) and both CLOSE
NEGATIVE. Baselines: pairing 169,808,742 op / full groth16 294,811,516 / standalone vkx
7,982,162, reproduced byte-identical before each A/B.

- Scheduler effort scaling / superoptimize the hot bodies: CLOSED, the tiny beam is
  already within ~0.04% of solver-grade. The beam constants are now env-tunable
  (`CASHC_BEAM_WIDTH`/`CASHC_BEAM_EXPAND`, default 4/3). Beam 32/8: pairing -0.001%,
  groth16 -0.007%, vkx -0.2%. Beam 256/16: -0.041% / -0.043% / -0.245%, compile 44 s ->
  2m36s, zero chunk-count changes. Exhaustive per-block enumeration (branch-and-bound
  over ALL topo orders with the pass's operand-fetch policy, `exhaustiveBlock` +
  `gap-probe.mjs` in the fork; also wired as an opt-in measured-selected body strategy
  via `CASHC_EXHAUSTIVE`): the hot small tower bodies (fp2Mul, fp2Sqr, fp2Sub, mulFp,
  subFp, fp2MulXi, cycSqr, selectPoint) are EXACTLY optimal already; residual static
  gaps live only in big cold bodies (fp12Sqr -956, jacAdd -652, pointDouble -415,
  line -406, fp12Mul -323 static op/exec) and realize end-to-end as pairing -0.039% /
  groth16 -0.036% / vkx -0.166% — same magnitude as beam 256/16, ~130 padding bytes
  across a whole family, no chunk-count change. The syrup/GASOL analogy fails here
  because the per-block min already captures the enumerable space; what remains is
  intrinsic arithmetic, not scheduling.
- Partial x4 unroll of the vk_x rolled loops: CLOSED, measured a REGRESSION in both
  emission styles, refuting the census's ~2-4% sizing. Reassignment style (i/b0/b1
  rebound across copies): vkx 7,982,162 -> 8,755,056 (+9.7%), full groth16 +0.26%.
  SSA/declaration style (fresh temps per copy): 8,635,575 (+8.2%). The plain-compile
  planner agrees (worst-case dense-input totals: rolled 53.8M, unrolled 55.3M/58.2M;
  windows shrink 37/35 -> 34/33 iters). Mechanism the census sizing missed: each
  unrolled iteration crosses 8 control boundaries (2 ifs per bit-step x 4) carrying
  MORE live locals, and block-boundary slot discipline makes the compiler pay either
  emitReplace park/restore bubbles (reassignment) or dead-slot-deepened relayouts
  (SSA) at every boundary — more than the ~1-decl+1-incr+1-compare per-bit scaffold
  the unroll removes. Conclusion transfers to the shamir entry (same loop shape).
  The variant generator was discarded after measurement: failed experiments are
  recorded here (numbers + mechanism), not kept in the live generators.

Addendum (2026-07-08): the experiments surfaced four BUILDER-side levers that compound;
together they are the outstanding project-side work, expected to exceed everything the
closed compiler experiments measured. Run them as ONE combined sweep per family (replan ->
repack -> tune pads -> verify worst-case + tampered-reject -> regenerate vectors), not
sequentially, since replanning changes boundaries and pad sizes anyway:

1. Padding-slack trim (MEASURED on the pairing family): every builder tunes each input's
   zero-pad as ceil(opCost/800) - 41 + 96, but the formula without the +96 is already
   exact and the tuner re-evaluates with a retry loop, so the margin defends nothing in
   the per-proof vector flow. Slack 1: bch-pairing-chunked unlocking -2,280 B (~-1.05%
   score), bch-groth16-chunked -4,085 B; flagship residue builder estimated -4-4.5k score
   (~-1.8%, unmeasured). The +96 appears at 13 tuning sites (intratx, grouped, BLS,
   flagship). Env-gated as TUNE_SLACK (default 96) in the pairing builder. Caveat before
   flipping defaults: op-cost varies with witness values (operand byte lengths), which is
   plausibly what the 96 silently insured; per-proof tuning with retry makes small slack
   (1-8) safe for vector builders, but pads must never be reused across proofs without
   re-tuning.
2. Stale manifests (MEASURED for vkx): a fresh replan under the current fork packs
   standalone vkx into 8 chunks instead of 9, one free input (~76 B + one preamble). The
   other families' manifests date from the same older compiler states; sweep miller,
   finalexp, g2check, shamir, and the BLS families.
3. Planner-vs-artifact cost mismatch (structural; vk_x instances MEASURED, floors
   certified, NOT yet shipped): planners under-fill chunks from THREE stacked sources:
   (a) sizing against the plain compile while shipped chunks run rescheduled at 5-6% less
   op; (b) the OP_TARGET headroom (7.7M vs 8,032,800, ~4%); (c) sizing with the WRONG
   DEPLOYMENT MODEL — `gen_vkx_glv.mjs`/`gen_vkx.mjs` plan with `measureCovenant` (which
   hash256's the state limbs per chunk) but the intratx/grouped transforms deploy
   hash-free. Certified safe floors (2026-07-09, density-worst-case-validated, see item
   5's sweep note for full numbers): GLV vk_x 5 -> 4 windows (-1 input on intratx-residue
   AND grouped-residue; 3 windows REJECTED at 99.8% budget under a max-density proof),
   Shamir vk_x 8 -> 6 (-2 inputs on intratx-plain AND grouped-plain; wcp verified to BE
   the density worst case there). Two rules now proven: every planner must measure with
   the cost model of its actual deployment transform, and MSM windows must be sized
   against the density worst case in the representation the loop iterates (GLV
   sub-scalars, not the near-r "worst-case proof" vector, whose decomposition randomizes
   sub-scalar bits). Miller/g2check/finalexp replan against sources (a)+(b) remains
   unmeasured; BLS families deferred pending a dense-worst-case harness in their builds.
4. Free crumbs: building committed artifacts with CASHC_BEAM_WIDTH=32/CASHC_BEAM_EXPAND=8
   or CASHC_EXHAUSTIVE=1 banks the measured 0.02-0.04% per family, never-worse by
   construction; the only cost is compile seconds.
5. Empirical deployment-overhead accounting (the method for finding anything further):
   diff each chunked entry against its flat singleton oracle, attributing overhead to
   buckets (math bodies, boundary/forward-check, preamble defines, padding push, shuffle).
   Measurability boundary (verified 2026-07-09; tooling lives in the sibling `verifier`
   repo's `harness/vm.ts` + this repo's `recompiler/asm.mjs`): BYTE buckets are fully
   attributable per-opcode statically (`asm.mjs parse` + `recompiler.mjs dissect` split the
   OP_DEFINE table from main; `benchmark.ts zeroPadBytes` isolates padding), so the +121.8kB
   structural story is precisely decomposable. OP buckets are only STAGE-granular: libauth
   exposes cumulative `state.metrics.operationCost` per whole-script evaluation (no
   per-opcode meter exists), and the intratx-residue vectors persist only the aggregate, so
   per-input/per-stage op must be recomputed by re-executing each step through
   `createLoosenedVm()`. That granularity does cover the worst-case-spread question (run
   every input incl. `worstCaseProof`, diff stage totals), but sub-step op attribution
   (math vs forward-check vs define-push vs shuffle within one input) needs a libauth
   instrument, not the vectors. BUILT + RUN 2026-07-09: `verifier/src/harness/bucket-
   accounting.ts` (`npx tsx`), reconciles to the vector aggregates byte-exact (240,079 B /
   181,512,304 op). It also CORRECTED the earlier eyeballed breakdown of this same pair,
   which had mis-attributed the structural bytes to the locking and to forward-checks:

   OP: chunking costs +1.875M op (+1.0%) on the small proof — confirmed lean. The +14.9M
   worst-case spread (+8.2%) is NOT diffuse "operand-length spread": it is ~entirely the
   GLV vk_x stage (+14.94M, +267% of that stage's own 5.6M), while Miller — 83.5% of all op
   — is flat across proofs (+14k, 0.0%) and g2check/tail are flat too. Mechanism: vk_x is
   the MSM over the PUBLIC-INPUT scalars, whose GLV sub-scalar width varies proof-to-proof;
   Miller/g2check/tail operate on always-full-width proof points and baked constants, hence
   flat. IMPORTANT correction (probe `verifier/src/harness/vkx-variance-probe.ts`,
   2026-07-09): this variance does NOT drive the SCORED (small-proof) padding — an earlier
   draft of this note claimed it did and was wrong. On the small proof the vk_x window
   chunks are essentially UNPADDED (pad 3 B; op ~0.85M, and their redeem+witness bytes
   already buy ~2M budget), so the scored 51.1 kB pad is g2check (19.8 kB, op-bound, 98.7%
   budget util, flat) + Miller (30.1 kB, the bulk) + vk_x only 1.2 kB. vk_x variance is
   worst-case HEADROOM, not a scored-pad lever. The real vk_x lever is CHUNK COUNT via the
   item-3 cost mismatch, now measured: the GLV manifest (`gen_vkx_glv.mjs`, regenerated
   2026-07-09 — not stale) sizes windows with `measureCovenant` (covenant model: hash256 of
   9×40-B state limbs/chunk) to OP_TARGET 7.7M, giving 5 chunks of ~35-38 iters. But the
   intratx-residue family deploys those same windows through a forward-check transform with
   NO hashing (~2 introspection ops/chunk, zero hash ops), so worst-case intratx vk_x runs
   at only ~5.9M op = 73% of the 8.03M input budget. REPLANNED + MEASURED end-to-end
   2026-07-09 (`chunked/intratx/replan_vkx_candidate.mjs` regenerates windows via the now-
   exported `genCash`; the real builds measure the transformed hash-free redeem, tune pads,
   gate on tamper-reject; a temporary `WC_IN0/WC_IN1` hook in the intratx build +
   `check_worstcase_vkx.mjs` measure vk_x op under INJECTED max-density inputs):
     • 5 chunks (baseline, covenant-planned): 33 inputs, scored 240,079 B.
     • 4 chunks [0,34)[34,68)[68,101)[101,128)F: 32 inputs (−1), scored 238,288 B (−1,791);
       vk_x maxes at 6,343,678 = 79% of budget under a MAX-DENSITY proof. SAFE floor.
     • 3 chunks: 31 inputs, but UNSAFE. Against the vectors' worst-case PROOF it looks fine
       (7.14M = 89% budget), but that proof is NOT the density worst case for GLV: the raw
       inputs are decomposed into 4 ~127-bit sub-scalars, and the MSM per-iteration add fires
       unless all four bits are 0, so max op comes from a proof whose sub-scalars jointly
       cover all 128 positions — not from near-r inputs. wcp covers only [34,29,35]/window;
       a searched max-density proof (127/128) pushes the tightest 3-window to 8,016,756 =
       99.8% of the 8,032,800 budget with the pad already pinned at the 10,000 B unlock cap,
       and the absolute-max (128/128) tips it over. So 3 is at the cliff and rejected.
   KEY LESSON (corrects an earlier draft of this note that reported 5→3): size MSM chunks
   against the density worst case in the representation the loop ITERATES — the raw scalar for
   Shamir, the GLV sub-scalars for GLV — NOT against the "worst-case proof" vector, which is
   near-r and is maximal for Shamir but NOT for GLV (its decomposition randomizes the
   sub-scalar bits). Measured safe drop: 5→4 (−1 input), for BOTH the intratx-residue and
   grouped-residue families (they share manifest_vkxglv; grouped-residue 33→32 inputs, groups
   13/11/8, worst group 97.4 kB < 100 kB cap). The op spread itself is not otherwise reducible
   without cheaper MSM math, and does not need to be.

   SWEEP of the other vk_x families (2026-07-09), same cost-mismatch lever:
     • BN254 Shamir plain (manifest_vkx, 254-iter 2-scalar, shared by intratx + grouped):
       8→6 chunks, SAFE (−2 inputs). Unlike GLV, the loop iterates the RAW inputs, and wcp is
       near-all-ones (in0,in1 popcount 253/254) so its binding windows are 100% add-covered —
       verified worst case (50k-sample max add-coverage ≤ wcp in every window). 6-window vk_x
       tops at 7,664,635 = 95.4% of budget (stable: operands are reduced mod P every op, so
       ≤32 B, and wcp already hits that width). intratx-plain groth16: 49→47 inputs, 375,853
       →373,485 B; grouped-plain groth16: 49→47 inputs, 5 groups, worst group 89.6 kB < 100
       kB cap. 5 windows is impossible (51-iter × ~178 K op/iter > budget).
     • BLS12-381 families (GLV manifest 6 chunks, Shamir manifest 12 chunks; each shared by
       intratx + grouped): the same under-fill mechanism applies, BUT their builds carry NO
       dense worst-case proof (only committed+proof1), and — per the GLV lesson — GLV sizing
       needs a max-density SUB-SCALAR check the builds can't do today. So BLS floors are NOT
       certified here; safe sizing first needs a dense/max-density worst-case harness added to
       the BLS builds (and a BLS `genCash` export). Deferred, not dismissed.

   BYTES (P2SH32, so the program is the redeem script in the scriptSig, NOT the 35 B
   locking — the prior "+121.8 kB in the locking / define tables / forward-checks" was
   wrong on all three counts). Score delta chunked − oracle = +172.9 kB, three ~equal
   buckets: (a) program +68.2 kB (134.1 kB of redeem across 33 inputs vs 65.9 kB flat), of
   which +61.3 kB is DUPLICATED BAKED CONSTANTS — each of the 23 fused-Miller chunks re-
   embeds ~66 32-byte field constants + coefficient blobs (~3.9 kB/chunk); forward-check
   surface is negligible (62 introspection opcodes total, ~2/chunk) and the chunks carry NO
   define table at all (oracle: 4.5 kB); (b) witness/state re-supply +52.3 kB (53.6 kB vs
   the oracle's 1.2 kB — proof + inter-chunk state fed to each input); (c) padding +51.1 kB
   (21.3% of score). Threading a constant per-chunk via the forward-check blob is a wash
   (bytes move redeem→witness at no score change, plus op), so within the current
   architecture the reducer is FEWER, FATTER chunks: every eliminated fused-Miller chunk
   drops ~3.9 kB constants + its padding + its 35 B envelope, a far bigger win per chunk
   than the "~76 B/input" the builder levers assumed. This directly reinforces items 2-3
   (stale manifests / planner margin) and localizes the op lever to vk_x variance (item
   6). But "inherent" is only proven for per-chunk threading, not cross-input sharing
   (item 7). No other large unexplained bucket remains.
6. vk_x worst-case flattening: REFUTED (probe `verifier/src/harness/vkx-variance-probe.ts`,
   2026-07-09) — this item's premise ("pads price the worst case") was wrong for the
   scored entries: pads are tuned per proof, and on the small proof the vk_x window
   chunks are essentially unpadded (3 B; ~0.85M op against ~2M of budget their own bytes
   already buy). The scored 51.1 kB pad is g2check (19.8 kB, 98.7% util, flat) + Miller
   (30.1 kB) + vk_x only 1.2 kB, so a branchless/flat vk_x would buy worst-case headroom,
   not score. The variance mechanism is confirmed (public-input GLV sub-scalar widths
   vary per proof; everything else runs full-width) but the actionable vk_x lever is
   chunk count via item 3(c), already measured at ~2 inputs. Do not build flattening.
7. Shared-carrier dedup (HYPOTHESIS, challenges item 5's "inherent" verdict): intratx
   chunks already read sibling inputs' unlocking bytecode for forward-checks, so ONE
   carrier input can hold the shared constants once and each chunk slices what it needs
   from `tx.inputs[carrier].unlockingBytecode` — 23 copies to 1 is a dedup, not a move.
   Op price is roughly the pushed blob size per reading chunk (~6-10 kB push = ~6-10k op,
   x23 chunks = ~0.2M op, a few hundred padding-bytes equivalent) against tens of kB of
   score IF the shared fraction of the 61.3 kB is large: the ~66 field constants
   (primes, Frobenius, curve params) are presumably identical across chunks and dedupe
   fully; per-window line-coefficient blobs are chunk-unique and do not. The same
   mechanism may dedupe repeated proof elements inside the 52.3 kB witness bucket.
   Applies to the intratx and grouped families (one carrier per tx); the NFT-covenant
   family spans txs and cannot share. Measure the shared fraction first; per the
   calibration lesson, do not book until an applied A/B lands.

Beyond these, remaining op headroom for the chunked families is at the math/advice level,
where all the large historical wins came from (residue witness, GLV, fused subgroup
checks, witness inverses). One systematic sweep worth doing: since op-bound chunks must
pad their unlocking data anyway, advice bytes are score-free up to the padding
requirement, so any remaining site where verifying a witnessed value is cheaper than
computing it (divisions, exponentiations, decompositions not yet witnessed) is free
op-cost. The compiler cannot find those; a manual pass over the chunk sources can.

## Cut, with reasons

- Computed-index arrays (table[i] as computed-depth OP_PICK): the repo's own measurement
  kills it. The blob-plus-runtime-split idiom already sits on the O(1) floor
  (`select16-blob-table.md:63-77`, capturing 74.2 of 74.8 available points); the residual
  is ~0.01% of the residue build, and select16 is the only runtime-indexed table in the
  codebase. Surface would be grammar + typechecker + codegen + a rescheduler bail path
  (computed depths break the DAG lift, blanking rescheduling in exactly the hot blocks).
  Revisit only if a runtime-computed-value table (not baked constants) appears in a real
  build. Writes are worse still: computed ROLL + reinsert reintroduces the emitReplace
  bubble at a runtime depth.
- Range-annotation redundant-mod elimination: both designs fail. A trusted annotation is
  an unsafe escape hatch (a wrong range claim silently changes arithmetic results,
  funds-loss grade, categorically unlike the semantically inert `unused`); a verified
  annotation requires interval propagation through loop-carried dataflow, the exact
  framework already cut, plus syntax on top. The hand-written lazy towers also do more
  than elision (per-call-site k*p bias threading, restructured arities), so an elision
  pass would not reproduce their measured win anyway. Keep the two-tower cost at source
  level.
- Structs: byte-identical output to hand-threaded locals; purely ergonomic. A legitimate
  DX discussion for upstream, but zero on this roadmap's win axis.
- Portfolio compilation framework: the compile-both-keep-smaller pattern already exists in
  all three places it pays (def-sinking, per-block min, per-chunk redeem selection).
  Generalizing buys no bytes, multiplies unmeasured compile time, and squares the test
  matrix. Keep the discipline (every pass never-worse by construction), not the framework.
- Peephole completeness: already upstream. Residual afternoon task: confirm the
  rescheduler's internal peephole applies the same rules and cashproof covers them.
- In-compiler redundant-modulo elimination via full inference: (a%p + b%p)%p is not
  (a+b)%p under BCH's truncated-sign semantics for mixed-sign operands; sound elision
  needs interval/sign analysis plus an operand-width cost model, for one constituency that
  already hand-writes the lazy variants.
- Codegen rewrite of the emitReplace altstack park/restore (fixing the baseline instead of
  post-passing): rejected for now on verification asymmetry (a codegen rewrite has no
  baseline to diff against, no per-block min safety net), debug-info co-requisites (fixed
  homes are what make the source map precise), and window discipline (one bytecode-shape
  change per stabilization window). Revisit clause resolved by the 2026-07-08 census (see
  ground truth): the depth/layout lever is net negative, so there is no material win left
  for a codegen rewrite to capture either, and the byte headroom that did remain was
  captured by outlining as a post-pass (item 6). The rejection is final.

## Strategic addendum: VM CHIP for addressable locals

Recalibrated after the 2026-07-08 outlining result: the old headline ("54% of the
optimized singleton is addressing bytes only a VM change removes") is no longer the right
claim, since ~23% of those static bytes turned out compressible by outlining the repeated
relayout runs. What outlining cannot touch is the EXECUTED tax: it compresses bytes
precisely by re-executing the same shuffles through OP_INVOKE (+5.9% op), and every
ROLL/PICK execution plus its depth push remains a per-evaluation cost that only VM-level
indexed locals (JVM/WASM-style) remove; OP_DEFINE functions are a step in that direction.
So the CHIP case should be argued on executed op-cost and on the bytes that remain after
every compiler-level lever is exhausted, with the composition re-measured on post-outline
artifacts before writing, so the document leads with numbers that survive this project's
own optimizers. Still about a week of writing and still plausibly the highest-leverage
deliverable here. It also strengthens the upstream story:
the compiler work above is what makes the case credible.

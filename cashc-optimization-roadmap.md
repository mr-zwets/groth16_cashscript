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
chunk windows: fewer inputs at ~76 B score each, plus one less preamble execution.

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
3. Planner-vs-artifact cost mismatch (structural, UNMEASURED): planners size windows
   against the plain compile while shipped chunks run rescheduled at 5-6% less op, on top
   of the OP_TARGET headroom (7.7M vs 8,032,800, ~4%), so chunks under-fill by roughly
   10%: potentially 2-4 whole inputs on the 24- and 50-step families. Size the residual
   margin empirically from witness-to-witness op variance over random proofs, not a round
   number; BLS families (near byte caps, deferred selection) go last.
4. Free crumbs: building committed artifacts with CASHC_BEAM_WIDTH=32/CASHC_BEAM_EXPAND=8
   or CASHC_EXHAUSTIVE=1 banks the measured 0.02-0.04% per family, never-worse by
   construction; the only cost is compile seconds.
5. Empirical deployment-overhead accounting (the method for finding anything further):
   diff each chunked entry against its flat singleton oracle, attributing every op and
   byte to a bucket (math bodies, boundary/forward-check, preamble defines, padding push,
   shuffle) via VM execution traces. The BN254 intratx-residue vs minop-singleton pair
   already brackets it: chunking costs only +1.88M op (+1.0%) on the small proof, but
   +14.9M (+8.2%) at worst case (witness-dependent operand-length spread, which is what
   the pads are sized against, so reducing the spread cuts padding directly), and
   +121.8kB of structural script (3.7kB/input of forward-checks, boundary staging, and
   define tables) plus 51.1kB padding (21% of that entry's score). Mine the buckets that
   are large and unexplained (the worst-case spread and the per-input structure first);
   everything small or explained is confirmed irreducible and closes the search.

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

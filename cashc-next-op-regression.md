# Why some benchmark scores increased after the cashc-next alignment

After porting the contracts to the upstream-rebased compiler (`feat/multi-returns`, see
[cashscript-compiler-fork.md](cashscript-compiler-fork.md)), most benchmark entries improved,
but the **BN254 op-bound multi-input families got worse**. This note pins down where those
bytes come from, with measurements, and what is (and is not) responsible.

## 1. What moved

Scores before the alignment (verifier commit `29c18a8`) vs after the final state (compiler
`d0353f4`, contracts `b564531`):

| entry | before | after | Δ |
|---|---:|---:|---:|
| bch-groth16-singleton | 15,000 | 14,447 | **−3.7 %** |
| bch-groth16-singleton-opcode-optimized | 9,135 | 8,782 | **−3.9 %** |
| bch-groth16-bls12381-singleton | 15,399 | 14,844 | −3.6 % |
| bch-pairing-singleton (both curves) | 11,907 / 12,044 | 11,379 / 11,459 | −4.4 / −4.9 % |
| bch-vkx-chunked-shamir | 19,673 | 17,950 | −8.8 % |
| bch-groth16-bls12381-chunked | 713,761 | 712,606 | −0.2 % |
| **bch-pairing-chunked** | 228,952 | 234,239 | **+2.3 %** |
| **bch-groth16-chunked** | 408,196 | 414,943 | **+1.7 %** |
| **bch-groth16-intratx / -grouped** | ~405,900 | ~413,000 | **+1.8 %** |
| **bch-groth16-\*-residue** | ~257,900 | ~261,200 | **+1.3 %** |

Only the BN254 chunked/intratx/grouped families increased. Everything byte-scored improved,
and the BLS chunked family is net flat-to-better.

## 2. Why op-cost is priced in bytes for these families

These families are **op-bound**: every input's unlocking script is zero-padded until the
per-input budget covers its chunk's op-cost (`budget = (41 + unlockingLength) × 800`, so
`unlockingLength ≥ opCost/800 − 41`). Two consequences:

- the score is essentially `totalOpCost / 800` plus fixed per-input overhead;
- **locking-byte savings are free** — a smaller redeem script just means more zero padding
  for the same total length — while **any op-cost increase converts directly into score**.

So for these entries the question "why did the bytes go up" is really "why did the op-cost
go up".

## 3. Where the op-cost went, per stage

The old vectors (still in git at `29c18a8`) carry per-step `operationCost`, so the regression
can be split by pipeline stage. Both compilers cover the *identical* flattened op-DAGs (413
Miller ops, 294 final-exp ops, 254 vk_x iterations, 63 G2-check bits), so these are
like-for-like:

| stage (BN254 groth16-chunked) | old | new | Δ |
|---|---:|---:|---:|
| g2check (loops, reduced tower) | 25.45 M | 24.84 M | **−2.4 %** |
| vk_x (loops, self-contained prologue) | 11.65 M | 11.56 M | −0.8 % |
| **miller (unrolled, lazy tower)** | 178.93 M | 182.98 M | **+2.3 %** |
| **finalexp (unrolled, lazy tower)** | 100.77 M | 102.42 M | **+1.6 %** |
| total | 316.80 M | 321.80 M | +1.6 % |

The residue pipeline shows the same shape (195.6 M → 198.5 M, +1.5 %). For BLS12-381 the
per-stage picture is mixed and nets out slightly *better* than the old compiler (its miller
chunks each improved ~0.4 %, finalexp regressed ~0.3 %, g2check/vk_x improved).

The pattern: **loop-shaped stages improved, unrolled call-dense stages regressed.**

## 4. What it is *not*

- **Not the constant hoisting.** That trade-off (~+2 ops per call for ~−30 B per duplicate)
  is now the compiler's `optimizeFor: 'size'` objective (default `'opcost'`) and is off for every op-bound
  build. After turning it off, shamir/twoloop/g2check/vk_x op-costs match their pre-hoist
  values exactly (e.g. shamir 11.84 M, twoloop 80.98 M).
- **Not the new inlining.** Measured directly on `miller_00.cash`: the default compile
  executes ~2,218 instructions per Miller window-op; compiling the same chunk with
  `disableInlining` executes ~2,409. Inlining *recovers* part of the gap; without it the
  regression would be ~+14 % instead of ~+3 %. (The loop-exclusion rule is also why the
  loop-shaped g2check/vk_x stages now beat the old compiler.)
- **Not the re-planning.** Window boundaries shifted (24→25 miller chunks etc.), but the
  stage totals above sum over the same underlying work, and re-planning per se only moves
  op between chunks.

## 5. What it is: the upstream function-call convention

Disassembling the same Miller chunk under both compilers (old redeem recovered from the
`29c18a8` vectors, expansion of every `OP_INVOKE` into its `OP_DEFINE`d body):

| | old fork (`feat/library-support`) | new (`feat/multi-returns`) |
|---|---:|---:|
| redeem bytes | 5,574 | 5,149 |
| OP_DEFINE'd bodies | 20 | 18 |
| executed instructions / window-op | ~2,116 | ~2,218 (+4.8 %) |
| measured op-cost / window-op | 423 k | 435 k (+2.9 %) |

The new compiler emits *smaller* bytecode but *executes more instructions*: upstream's
user-defined-function codegen (#413) stages call arguments and cleans up function frames
differently from the old fork's `internal function` implementation, costing a few extra
stack-manipulation instructions per call. The BN254 lazy tower is the worst case for this —
its chunk bodies are fully unrolled sequences of many small multi-return calls (`fp2Sub`,
`fp2Mul`, `mul034`, … with extra lazy-bias arguments), so per-call overhead multiplies by
the call count. Loop-shaped bodies (few call sites, executed many times with the loop-carried
state in place) don't see it, and byte-scored contracts benefit from the same codegen's
smaller output.

## 6. Net assessment

The alignment traded ~+1.3–2.3 % on the BN254 op-bound chunked families for:

- upstream convergence (user functions, imports, DCE now come from `next`, not a private fork),
- −3.6…−4.9 % on every byte-scored singleton (flagship opcode-optimized 9,135 → 8,782),
- improvements on the loop-shaped chunked stages and the BLS chunked family,
- and per-build control of the size/op trade-off (`optimizeFor: 'size' | 'opcost'`).

## 7. Follow-up (open)

The remaining lever is the per-call overhead itself: diff the emitted call-site sequence and
body prologue/epilogue (argument staging, `cleanFunctionBodyStack`) between the two branches
on one small multi-return function, and see whether the old convention's cheaper sequence can
be restored in the fork (it would also benefit upstream). Estimated recovery: most of the
~5 M op on `bch-groth16-chunked`, ~2.9 M on the residue flagship.

---

*Methodology: old numbers from `zk-verifier-bench` commit `29c18a8` (per-step `operationCost`
and full unlocking hex in the vector JSONs); new numbers from the regenerated working-tree
vectors. Chunk disassembly via `singleton/bn254/recompiler/asm.mjs`; executed-instruction
counts expand `OP_INVOKE` recursively through the `OP_DEFINE`d bodies. Op-cost per
instruction averages ~200 (base 100 + operand-size costs), so instruction counts and measured
op-costs track each other closely.*

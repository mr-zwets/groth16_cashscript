# chunked/pairing/ — BCH-native multi-transaction Groth16 pairing

The BN254 pairing split across transactions so **every step fits one BCH input**
(op-cost ≤ 8,032,800, locking+unlocking ≤ 10,000 B). This is the BCH-compatible
counterpart of the `singleton/bn254/` oracle (which is correct but needs ~151
inputs' worth of op-cost in one go).

Two benchmark entries (in the verifier repo) are produced from here:

- **`bch-pairing-chunked`** — the **Miller boundary** `e(-A,B)·e(α,β)·e(vk_x,γ)·e(C,δ)`
  (checkpoint #2) as one prepared, batched optimal-ate loop. It shares each `fp12Sqr`
  across the three runtime-dependent pairs, omits the fixed `e(α,β)` pair, then multiplies
  its precomputed raw Miller value into `f` once. The exact four-pair boundary takes 20 inputs.
- **`bch-groth16-chunked`** — the **complete verifier** (checkpoint #3): G2 input
  validation → vk_x (computed on-chain from the public inputs) → the prepared Miller
  chunks → final exponentiation → a final step asserting the product == Fp12 ONE. 44 inputs.

Every chunk is validated on the real BCH 2026 VM.

## Optimizations

- **Lazy reduction** — `addFp`/`subFp` defer the `% p` with per-call-site bias (option-B;
  see the build memos). `mulFp` and the committed state stay reduced.
- **Prepared batched Miller** — one loop squares `f` once per NAF step and folds the
  runtime-dependent pairs' lines into the shared `f`. The fixed `e(α,β)` pair contributes
  a VK-only raw Miller value, so its 87 op objects (88 line folds) are removed and replaced
  by one terminal `fp12Mul`. Fixed-G2 line coefficients are baked, leaving on-chain G2
  arithmetic only for `e(-A,B)`. The folded `f` is the exact four-pair boundary — no
  combine step. The flat trace falls from 413 to 327 ops and the pairing from 24 to 20
  inputs, saving 38,678 bytes and 30,872,282 op-cost in the covenant deployment.

## How it works

Each chunk carries its state — `f` (Fp12, 12 limbs) + the runtime pair's G2 point `R0`
(6 limbs) for the prepared Miller; the live Fp12 values for final-exp — committed
as `hash256` of the 40-byte little-endian limbs, re-supplied in the witness and
verified on entry and exit (the same stateful-covenant pattern as the chunked
vk_x in `../shamir`). Within a chunk the ops are **unrolled straight-line with fresh
SSA variables** (no runtime loop / masks), so the body compiles once and **op-cost
binds, not size** — chunks are ~5 KB. The per-step math is noble's (which the CashScript fp2/fp6/fp12 ops
match bit-for-bit), so the carried limbs equal what the contract computes and the
baked hash commitments line up. Window sizes are chosen by measuring real-VM
op-cost.

## Regenerating (everything in `generated/` is git-ignored)

The 44 full-verifier chunk contracts + manifests are reproducible artifacts, so they are
**not committed** — only the generators are. Regenerate them (and the benchmark
vectors) with one command:

```
node generate.mjs
```

This runs (several minutes):

1. `gen_miller.mjs` → `generated/miller_NN.cash` + `manifest_miller.json`
   — the prepared batched Miller loop as a flat op list, chunked at any op boundary.
2. `gen_finalexp.mjs` → `generated/finalexp_NN.cash` + `manifest_finalexp.json`
   — the final exponentiation `f^((p¹²−1)/r)` traced as an SSA op-DAG (the 3
   cyclotomic-exp ladders chunked like the Miller loop; liveness carries only the
   live Fp12 values as committed state); the last chunk asserts result == ONE.
3. `gen_vkx.mjs` → `generated/vkx_NN.cash` + `manifest_vkx.json`
   — vk_x = IC0 + in0·IC1 + in1·IC2 for the pairing instance (Shamir/Straus,
   public inputs at runtime), asserting it == the point the pairing bakes.
4. `gen_g2check.mjs` → `generated/g2check_NN.cash` + `manifest_g2check.json`
   — on-curve checks plus the fast-endomorphism G2 subgroup check.
5. `build_vectors.mjs` → three files in `../../verifier/src/bch/`:
   `pairing-chunked-vectors.json` (boundary, for `bch-pairing-chunked`) and
   `groth16-chunked-vectors.json` (vk_x → pairing → final-exp → verdict, for
   `bch-groth16-chunked`), plus `vkx-chunked-covenant-vectors.json`.

### Why it takes a few minutes

The runtime is **not** the cryptography — it's the chunk *planner*. There is no
formula for "how many steps fit one BCH input", so each chunk is sized empirically:
the generator grows a window one step at a time and, for every candidate, **shells
out to the custom `cashc` to compile the contract and then evaluates it on the real
BCH 2026 VM to measure its exact op-cost**, stopping when the next step would exceed
the per-input budget. That's a few compile+measure iterations per chunk × 44
chunks ≈ several hundred `cashc` subprocess invocations and VM runs. `build_vectors`
then compiles, pads, and evaluates every one of the 44 chunks **twice** (the valid
witness and a tampered one) on the real VM. So the cost is dominated by hundreds of
compiler launches + VM evaluations, not the field/pairing math (which is fast). The
result is fully deterministic, so it only needs to run when the instance or the
chunking changes.

Run a single piece directly if needed: `node gen_miller.mjs`, `node gen_finalexp.mjs`,
`node gen_vkx.mjs`, etc. Fast probes (no planner): `node gen_miller.mjs probe`,
`node gen_finalexp.mjs probe`.

## Files

| file | role | committed |
|------|------|:--------:|
| `_millermath.mjs` | shared reference math (noble), serialization, instance pairs, real-VM measurer | ✅ |
| `gen_miller.mjs` | plan + emit the prepared batched Miller chunks (flat-op) | ✅ |
| `gen_finalexp.mjs` | trace + chunk the final exponentiation (op-DAG + liveness) | ✅ |
| `gen_vkx.mjs` | chunk vk_x for the pairing instance (Shamir/Straus) | ✅ |
| `gen_g2check.mjs` | chunk G2 on-curve and subgroup validation | ✅ |
| `build_vectors.mjs` | assemble all chunks → the pairing, full-verifier, and vk_x vectors | ✅ |
| `generate.mjs` | one-command orchestrator (runs all of the above) | ✅ |
| `generated/` | the 44 full-verifier `.cash` chunks + manifests (derived) | ❌ git-ignored |

The committed instance lives in the verifier repo
(`src/checkpoints/pairing-vectors.json`); the singleton oracle is `../../singleton/bn254/`.

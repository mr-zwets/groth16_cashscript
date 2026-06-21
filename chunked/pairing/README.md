# chunked/pairing/ — BCH-native multi-transaction Groth16 pairing

The BN254 pairing split across transactions so **every step fits one BCH input**
(op-cost ≤ 8,032,800, locking+unlocking ≤ 10,000 B). This is the BCH-compatible
counterpart of the `singleton/bn254/` oracle (which is correct but needs ~151
inputs' worth of op-cost in one go).

Two benchmark entries (in the verifier repo) are produced from here:

- **`bch-pairing-chunked`** — the **Miller boundary** `e(-A,B)·e(α,β)·e(vk_x,γ)·e(C,δ)`
  (checkpoint #2) as ONE **batched 4-pair optimal-ate Miller loop** (a shared `fp12Sqr`
  per NAF step; the folded `f` is the boundary, so there is no separate combine). 59 chunks.
- **`bch-groth16-chunked`** — the **complete verifier** (checkpoint #3): the vk_x
  chunks (computed on-chain from the public inputs) → the batched Miller chunks → the
  final-exponentiation chunks → a final step asserting the product == Fp12 ONE. 93 chunks.

Every chunk is validated on the real BCH 2026 VM.

## Optimizations

- **Lazy reduction** — `addFp`/`subFp` defer the `% p` with per-call-site bias (option-B;
  see the build memos). `mulFp` and the committed state stay reduced.
- **Batched 4-pair Miller** — instead of four independent single-pair chains (each
  squaring `f` every step), ONE loop squares `f` once per NAF step and folds all four
  pairs' lines into the shared `f` (each pair's `R` evolves independently), then the
  Q1/Q2 (psi) postPrecompute per pair. Eliminates 3 of every 4 `fp12Sqr`, and the folded
  `f` IS the boundary — **no combine step**. A batched step is ~8 `mul034` (too coarse for
  one input), so the loop is chunked as a FLAT op list (sqr / double-line / add-line /
  postPrecompute) at any op boundary, carrying `f + 4 R + points`. Cut the full verifier
  from 116 to 93 chunks and ~754M to ~612M op-cost (the BLS12-381 sibling got the same
  treatment — see `../bls12-381/`).

## How it works

Each chunk carries its state — `f` (Fp12, 12 limbs) + the 4 running G2 points `R`
(6 limbs each) for the batched Miller; the live Fp12 values for final-exp — committed
as `hash256` of the 40-byte little-endian limbs, re-supplied in the witness and
verified on entry and exit (the same stateful-covenant pattern as the chunked
vk_x in `../shamir`). Within a chunk the ops are **unrolled straight-line with fresh
SSA variables** (no runtime loop / masks), so the body compiles once and **op-cost
binds, not size** — chunks are ~5 KB. The per-step math is noble's (which the CashScript fp2/fp6/fp12 ops
match bit-for-bit), so the carried limbs equal what the contract computes and the
baked hash commitments line up. Window sizes are chosen by measuring real-VM
op-cost.

## Regenerating (everything in `generated/` is git-ignored)

The ~93 chunk contracts + manifests are reproducible artifacts, so they are
**not committed** — only the generators are. Regenerate them (and the benchmark
vectors) with one command:

```
node generate.mjs
```

This runs (several minutes):

1. `gen_miller.mjs` → `generated/miller_NN.cash` + `manifest_miller.json`
   — the batched 4-pair Miller loop as a flat op list, chunked at any op boundary.
2. `gen_finalexp.mjs` → `generated/finalexp_NN.cash` + `manifest_finalexp.json`
   — the final exponentiation `f^((p¹²−1)/r)` traced as an SSA op-DAG (the 3
   cyclotomic-exp ladders chunked like the Miller loop; liveness carries only the
   live Fp12 values as committed state); the last chunk asserts result == ONE.
3. `gen_vkx.mjs` → `generated/vkx_NN.cash` + `manifest_vkx.json`
   — vk_x = IC0 + in0·IC1 + in1·IC2 for the pairing instance (Shamir/Straus,
   public inputs at runtime), asserting it == the point the pairing bakes.
4. `build_vectors.mjs` → two files in `../../verifier/src/bch/`:
   `pairing-chunked-vectors.json` (boundary, for `bch-pairing-chunked`) and
   `groth16-chunked-vectors.json` (vk_x → pairing → final-exp → verdict, for
   `bch-groth16-chunked`).

### Why it takes a few minutes

The runtime is **not** the cryptography — it's the chunk *planner*. There is no
formula for "how many steps fit one BCH input", so each chunk is sized empirically:
the generator grows a window one step at a time and, for every candidate, **shells
out to the custom `cashc` to compile the contract and then evaluates it on the real
BCH 2026 VM to measure its exact op-cost**, stopping when the next step would exceed
the per-input budget. That's a few compile+measure iterations per chunk × ~93
chunks ≈ several hundred `cashc` subprocess invocations and VM runs. `build_vectors`
then compiles, pads, and evaluates every one of the ~93 chunks **twice** (the valid
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
| `gen_miller.mjs` | plan + emit the batched 4-pair Miller chunks (flat-op) | ✅ |
| `gen_finalexp.mjs` | trace + chunk the final exponentiation (op-DAG + liveness) | ✅ |
| `gen_vkx.mjs` | chunk vk_x for the pairing instance (Shamir/Straus) | ✅ |
| `build_vectors.mjs` | assemble all chunks → the two verifier benchmark vector files | ✅ |
| `generate.mjs` | one-command orchestrator (runs all of the above) | ✅ |
| `generated/` | the ~93 `.cash` chunks + manifests (derived) | ❌ git-ignored |

The committed instance lives in the verifier repo
(`src/checkpoints/pairing-vectors.json`); the singleton oracle is `../../singleton/bn254/`.

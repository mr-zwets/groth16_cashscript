# chunked/pairing/ — BCH-native multi-transaction Groth16 pairing

The BN254 pairing split across transactions so **every step fits one BCH input**
(op-cost ≤ 8,032,800, locking+unlocking ≤ 10,000 B). This is the BCH-compatible
counterpart of the `singleton/pairing/` oracle (which is correct but needs ~151
inputs' worth of op-cost in one go).

Currently computes the **Miller boundary** `e(-A,B)·e(α,β)·e(vk_x,γ)·e(C,δ)`
(checkpoint #2) as **4 single-pair Miller chains + a combine step = 133 chunks**,
each validated on the real BCH 2026 VM. Benchmark entry: `bch-pairing-chunked`
(see the verifier repo). The final exponentiation (verdict) is added on top.

## How it works

Each chunk carries its state — `f` (Fp12, 12 limbs) + the running G2 point `R`
(6 limbs) for Miller chunks; the 4 `f_i` for the combine — committed as
`hash256` of the 40-byte little-endian limbs, re-supplied in the witness and
verified on entry and exit (the same stateful-covenant pattern as the chunked
vk_x in `../shamir`). Within a chunk the NAF steps are **unrolled straight-line
with the NAF digit baked per step** (no runtime loop / masks), so the body
compiles once and **op-cost binds, not size** — chunks are ~5 KB and run ~2–3
steps each. The per-step math is noble's (which the CashScript fp2/fp6/fp12 ops
match bit-for-bit), so the carried limbs equal what the contract computes and the
baked hash commitments line up. Window sizes are chosen by measuring real-VM
op-cost.

## Regenerating (everything in `generated/` is git-ignored)

The 133 chunk contracts + manifests are reproducible artifacts, so they are
**not committed** — only the generators are. Regenerate them (and the benchmark
vectors) with one command:

```
node generate.mjs
```

This runs (a few minutes; the 4 pairs plan concurrently):

1. `gen_miller.mjs 0..3` → `generated/miller_p<i>_NN.cash` + `manifest_p<i>.json`
   — one BCH-native chunk per NAF window of single-pair Miller loop `i`.
2. `gen_combine.mjs` → `generated/combine.cash` + `manifest_combine.json`
   — `boundary = f0·f1·f2·f3`.
3. `build_vectors.mjs` → `../../verifier/src/bch/pairing-chunked-vectors.json`
   — padded (locking, unlocking) per step, measured on the real BCH 2026 VM,
   for the `bch-pairing-chunked` benchmark entry.

Run a single piece directly if needed: `node gen_miller.mjs 2`, etc. A fast size
probe (no planner): `node gen_miller.mjs 0 probe`.

## Files

| file | role | committed |
|------|------|:--------:|
| `_millermath.mjs` | shared reference math (noble), serialization, instance pairs, real-VM measurer | ✅ |
| `gen_miller.mjs` | plan + emit one single-pair Miller chain's chunks | ✅ |
| `gen_combine.mjs` | emit the combine chunk (product of the 4 `f_i`) | ✅ |
| `build_vectors.mjs` | assemble all chunks → verifier benchmark vectors | ✅ |
| `generate.mjs` | one-command orchestrator (runs all of the above) | ✅ |
| `generated/` | the 133 `.cash` chunks + 5 manifests (derived) | ❌ git-ignored |

The committed instance lives in the verifier repo
(`src/checkpoints/pairing-vectors.json`); the singleton oracle is `../../singleton/pairing/`.

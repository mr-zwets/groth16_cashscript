# chunked/pairing/ — BCH-native multi-transaction Groth16 pairing

The BN254 pairing split across transactions so **every step fits one BCH input**
(op-cost ≤ 8,032,800, locking+unlocking ≤ 10,000 B). This is the BCH-compatible
counterpart of the `singleton/bn254/` oracle (which is correct but needs ~151
inputs' worth of op-cost in one go).

Two benchmark entries (in the verifier repo) are produced from here:

- **`bch-pairing-chunked`** — the **Miller boundary** `e(-A,B)·e(α,β)·e(vk_x,γ)·e(C,δ)`
  (checkpoint #2) as **4 single-pair Miller chains + a combine step = 133 chunks**.
- **`bch-groth16-chunked`** — the **complete verifier** (checkpoint #3): the vk_x
  chunks (computed on-chain from the public inputs) → the 133 boundary chunks → the
  final-exponentiation chunks → a final step asserting the product == Fp12 ONE.

Every chunk is validated on the real BCH 2026 VM.

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

This runs (several minutes; the 4 Miller pairs plan concurrently):

1. `gen_miller.mjs 0..3` → `generated/miller_p<i>_NN.cash` + `manifest_p<i>.json`
   — one BCH-native chunk per NAF window of single-pair Miller loop `i`.
2. `gen_combine.mjs` → `generated/combine.cash` + `manifest_combine.json`
   — `boundary = f0·f1·f2·f3`.
3. `gen_finalexp.mjs` → `generated/finalexp_NN.cash` + `manifest_finalexp.json`
   — the final exponentiation `f^((p¹²−1)/r)` traced as an SSA op-DAG (the 3
   cyclotomic-exp ladders chunked like the Miller loop; liveness carries only the
   live Fp12 values as committed state); the last chunk asserts result == ONE.
4. `gen_vkx.mjs` → `generated/vkx_NN.cash` + `manifest_vkx.json`
   — vk_x = IC0 + in0·IC1 + in1·IC2 for the pairing instance (Shamir/Straus,
   public inputs at runtime), asserting it == the point the pairing bakes.
5. `build_vectors.mjs` → two files in `../../verifier/src/bch/`:
   `pairing-chunked-vectors.json` (boundary, for `bch-pairing-chunked`) and
   `groth16-chunked-vectors.json` (vk_x → pairing → final-exp → verdict, for
   `bch-groth16-chunked`).

### Why it takes a few minutes

The runtime is **not** the cryptography — it's the chunk *planner*. There is no
formula for "how many steps fit one BCH input", so each chunk is sized empirically:
the generator grows a window one step at a time and, for every candidate, **shells
out to the custom `cashc` to compile the contract and then evaluates it on the real
BCH 2026 VM to measure its exact op-cost**, stopping when the next step would exceed
the per-input budget. That's a few compile+measure iterations per chunk × ~170
chunks ≈ several hundred `cashc` subprocess invocations and VM runs. `build_vectors`
then compiles, pads, and evaluates every one of the ~170 chunks **twice** (the valid
witness and a tampered one) on the real VM. So the cost is dominated by hundreds of
compiler launches + VM evaluations, not the field/pairing math (which is fast). The
4 Miller pairs are planned concurrently to cut wall-clock; the result is fully
deterministic, so it only needs to run when the instance or the chunking changes.

Run a single piece directly if needed: `node gen_miller.mjs 2`, `node gen_finalexp.mjs`,
`node gen_vkx.mjs`, etc. Fast probes (no planner): `node gen_miller.mjs 0 probe`,
`node gen_finalexp.mjs probe`.

## Files

| file | role | committed |
|------|------|:--------:|
| `_millermath.mjs` | shared reference math (noble), serialization, instance pairs, real-VM measurer | ✅ |
| `gen_miller.mjs` | plan + emit one single-pair Miller chain's chunks | ✅ |
| `gen_combine.mjs` | emit the combine chunk (product of the 4 `f_i`) | ✅ |
| `gen_finalexp.mjs` | trace + chunk the final exponentiation (op-DAG + liveness) | ✅ |
| `gen_vkx.mjs` | chunk vk_x for the pairing instance (Shamir/Straus) | ✅ |
| `build_vectors.mjs` | assemble all chunks → the two verifier benchmark vector files | ✅ |
| `generate.mjs` | one-command orchestrator (runs all of the above) | ✅ |
| `generated/` | the ~170 `.cash` chunks + manifests (derived) | ❌ git-ignored |

The committed instance lives in the verifier repo
(`src/checkpoints/pairing-vectors.json`); the singleton oracle is `../../singleton/bn254/`.

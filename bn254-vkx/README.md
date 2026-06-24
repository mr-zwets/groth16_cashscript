# BN254 vk_x test vectors

Shared test-vector tooling for the BN254 `vk_x = IC0 + input0·IC1 + input1·IC2`
computation (G1 on BN254 / alt_bn128). Consumed by both the singleton and the
chunked BN254 verifiers, which is why it lives at the repo root rather than inside
either method's folder.

```
vkx_ref.mjs  ──writes──▶  vkx_vectors.json  ──read by──▶  vkx_sim.mjs
```

- **`vkx_ref.mjs`** — producer. Picks the IC points (fixed multiples of G1) and the
  public inputs, computes the authoritative `vk_x` via `@noble/curves` bn254, and writes
  `vkx_vectors.json`. This is the provenance of the magic numbers in the vectors.
- **`vkx_vectors.json`** — the data: `p`, `r`, `ic0..ic2`, `input0/1`, the expected
  `vk_x`, and a deliberately-wrong point for reject tests.
- **`vkx_sim.mjs`** — dev cross-check (not part of any build). A JS port of the
  `vkx.cash` Jacobian double-and-add loop, run against the reference `vk_x` to prove the
  contract algorithm matches. Handy as an executable spec when debugging the singleton vk_x.

## Consumers

- `chunked/twoloop/gen_chunks.mjs` — loads `../../bn254-vkx/vkx_vectors.json`
- `chunked/shamir/gen_chunks.mjs` — loads `../../bn254-vkx/vkx_vectors.json`
- `singleton/bn254/build_vectors_vkx.mjs` — hardcodes the same params (kept consistent by hand)

## Regenerating

```sh
node bn254-vkx/vkx_ref.mjs    # rewrites vkx_vectors.json   (npm run gen:vectors)
node bn254-vkx/vkx_sim.mjs    # prints MATCH: true if the contract algorithm agrees (npm run check:vectors)
```

Both scripts anchor to this folder, so they can be run from any working directory.
If you change the IC points or inputs, regenerate the JSON and re-run the two
`gen_chunks.mjs` generators (and update `build_vectors_vkx.mjs` to match).

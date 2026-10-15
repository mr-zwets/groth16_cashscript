# BN254 PairFold-5 densless with a sound vk_x

The PairFold verifiers (pairfold5, pevalfuse, densless, pairfold7) check the public-input
relation with a log-derivative identity on an auxiliary polynomial blob in the genesis
input. That identity holds for arbitrary multiplicities, so it does not bind vk_x to the
claimed public inputs: a real proof with the true vk_x and forged public inputs is
accepted (see `docs/public-input-binding.md` in zk-verifier-bench).

This variant keeps the reconstructed densless verifier unchanged
(`../densless-recovered`, kallisti's public-only source from the withdrawn
groth16_cashscript PR #17) and adds two inputs that recompute vk_x itself:

- input 5 walks the genesis unlocking (push-only under P2SH) to the claimed n1, n0
  (pushes 38, 39), range-checks them, runs Straus positions 63..36 and pins input 6's
  state push (X, Y, Z, n0, n1);
- input 6 finishes positions 35..0, converts to affine with a witnessed Z inverse and
  checks it against its front push vk_x, then checks the GLV split: it rebuilds
  S0 = k10 + lambda*k20 and S1 = k11 + lambda*k21 from both inputs' witness bytes and
  requires S0 = n0 and S1 = n1 (mod r);
- the terminal requires 7 inputs, pins both MSM lockings and requires input 6's vk_x
  push to equal the vk_x in genesis push 0, which the Miller loop consumes.

The MSM is a 4-scalar GLV Straus over {IC1, phi(IC1), IC2, phi(IC2)} in two 64-bit
halves sharing 64 doublings. The witness is one byte per position (both 4-bit table
indices). The accumulator starts at the G1 generator instead of infinity, so the
Jacobian formulas have no infinity branches, and the final step adds the constant
IC0 - [2^64]G; an exceptional mixed add (equal x) is rejected, which only costs
completeness with negligible probability.

The MSM source is CashScript (`../pairfold5-msm/vkx-msm.mjs`) compiled with the
[`mr-zwets/cashscript`](https://github.com/mr-zwets/cashscript) branch
`compiler-optimizations-7`; that branch's loop reassignment codegen is what makes it
competitive. `../pairfold5-msm/vkx-msm-asm.mjs` is a hand-scheduled version with the
same witness layout (`MSM_IMPL=asm`, 483 bytes smaller), kept as a cross-check.
`../pairfold5-msm` also holds the same repair on the pevalfuse base.

Result on the official fixtures: 7 inputs, one standard transaction, 45,447 script
bytes, score 45,768, 29.6M op. Pads cover the worst case where every table index is
nonzero. Forged and adaptively forged public inputs are rejected.

```sh
VERIFIER_DIR=<zk-verifier-bench checkout> node export.mjs vectors.json
```

`VERIFIER_DIR` is needed because the GLV constants come from `../../pairing/gen_vkx_glv.mjs`.

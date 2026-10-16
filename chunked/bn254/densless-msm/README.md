# BN254 PairFold-5 densless with a sound vk_x

The PairFold verifiers (pairfold5, pevalfuse, densless, pairfold7) check the public-input
relation with a log-derivative identity on an auxiliary polynomial blob in the genesis
input. That identity holds for arbitrary multiplicities, so it does not bind vk_x to the
claimed public inputs: a real proof with the true vk_x and forged public inputs is
accepted (see `docs/public-input-binding.md` in zk-verifier-bench).

This variant starts from the reconstructed densless verifier (`../densless-recovered`,
kallisti's public-only source from the withdrawn groth16_cashscript PR #17), removes the dead
predicate from its genesis and recomputes vk_x itself, in the spare op budget of the five inputs
the verifier already has:

- Carriers (`carrier.mjs`): each MSM stage's pushes are appended to its input's unlocking just
  before the redeem, so no byte offset other inputs read moves. The redeem parks them on the
  altstack, runs the input's original program unchanged, verifies its result, restores them and
  runs the stage.
- Genesis (input 3) runs MSM part A: it range-checks the claimed public inputs n0, n1 (genesis
  pushes 22 and 21), runs Straus positions 63..26 and pins the first 199 bytes of input 0's
  state push (X, Y, Z, n0, n1 and its own witness bytes).
- The executors (inputs 0, 1, 2) and the terminal (input 4) continue it (`vkx-stages.mjs`).
  Each ends its unlocking with a 224-byte state push (X, Y, Z, n0, n1 and all 64 witness bytes);
  an executor runs the positions its OP_INPUTINDEX selects (25..18, 17..10, 9..4) and
  requires the next stage's state push (input 1, 2, then 4) to equal its result with n0, n1 and
  the witness bytes copied through. The pinned push is found from the end of the receiver's
  unlocking (its redeem push length is fixed by its locking) and the receiver requires its own
  state push to be exactly 224 bytes, so the pinned bytes are that push.
- The terminal stage runs positions 3..0, adds the constant, converts to affine with a witnessed
  Z inverse and requires the result to equal the vk_x in genesis push 0, which the Miller loop
  consumes. It then checks the GLV split: it rebuilds S0 = k10 + lambda*k20 and
  S1 = k11 + lambda*k21 from the 64 witness bytes and requires S0 = n0 and S1 = n1 (mod r).
- The terminal requires 5 inputs and pins every worker locking, so inputs 0..3 run the redeems
  above. The MSM helpers (doubling, mixed add and the two 960-byte tables) are defined once, in
  genesis; the other stages read that definition block out of the hash-pinned genesis redeem
  (OP_INPUTBYTECODE 3) and run it as a function, so the tables are not repeated. Carried function
  ids are shifted to 200+ (and the loader uses 199), clear of every program's own ids.

The genesis slice (`genesis-slice.mjs`, `genesis-slice.json`) drops the predicate's witness
pushes 19..39 and the code that consumed them, and rewrites 144 PICK/ROLL depths. It was
derived from a shadow-stack taint trace on the official fixtures and checked by an independent
static audit, differential mutation tests and fresh proofs. The removed span also held checks
on proof data: B's canonical and on-curve checks are kept; only vk_x's canonical checks are
dropped, since the MSM pins vk_x exactly. Genesis drops from 5.59M to 0.68M op.

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
same witness layout (`MSM_IMPL=asm`, slightly cheaper), kept as a cross-check.
`../pairfold5-msm` also holds the same repair on the pevalfuse base.

Result on the official fixtures: 5 inputs, one standard transaction, 35,646 script bytes,
24.5M op. Every input fits its op-cost budget with no zero pad at the worst case where every
table index is nonzero (cuts sized from a linear op-cost fit over 37 fresh proofs, then checked
with 30 real worst-case witnesses on minted proofs: peak 90.3, 84.8, 87.9, 97.0 and 86.9% of the
five budgets). Forged and adaptively forged public inputs (the whole MSM chain rebuilt, the
genesis vk_x swapped, a mid-chain witness swap, a lengthened state push, the pad-shift variant
found in review of the 6-input version), tampered state pushes, non-canonical B and off-curve B
are rejected (`redteam.mjs` writes the bench red-team file).

The witness generator in `../densless-recovered` (root-witness.mjs, witness.mjs) now uses
SCALING^2 / xi for residue selector 2, the representative the terminal expects; before, every
selector-2 proof (about 4 in 10) was rejected. The on-chain programs are unchanged by that fix.

```sh
VERIFIER_DIR=<zk-verifier-bench checkout> node export.mjs vectors.json
```

`VERIFIER_DIR` is needed because the GLV constants come from `../../pairing/gen_vkx_glv.mjs`.

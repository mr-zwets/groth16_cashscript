# bn-native-sound-design1 (designer 1 of 2): sound BN254 Groth16 on bch-2026, multi-input, angle = minimize bytes

Worktree: groth16_cashscript (branch wip/bn-native-sound-design1, pushed). Design record:
groth16_cashscript/research/sound-bn254-native/ (README + prototypes/).

## Done
- SI-GLS profile (standard, fixture 0): total 23.38M; loop 20.9M; setup ~0.84M; terminal 0.71M; quotient 0.74M.
- prototypes/kernels.mjs: affine B kernels with witnessed slope (64 B) or witnessed inverse norm (32 B), checked
  against noble in the bch-2026 VM. dbl: proj 123k / slope 81k / inv-norm 101k; add: proj 154k / slope 80k / inv-norm 93k.
- prototypes/loop.mjs: full event loop for any chunk range, real fixture-0 B trajectory (all checks pass):
  whole loop proj 20.67M (SI 20.9M: calibrated), affine-slope 15.40M, affine-invnorm 16.78M.
- prototypes/ranges.json (per-chunk op, all modes) + model.mjs (3/4-input layouts, data placement, 2% margin,
  n_q cap liveness, zero filler): best = all-affine inverse-norm, 3 inputs, score ~26.1k (fill 524).

## Next
- Prototype the per-input setup (library load via OP_INPUTBYTECODE + hash + OP_DEFINE, transcript gather,
  handover) in a real 3-input bch-2026 tx to replace the 0.80M/input estimate.
- Write README: protocol, soundness argument, layout table, risks.

## Commands
node research/sound-bn254-native/prototypes/kernels.mjs
node research/sound-bn254-native/prototypes/loop.mjs affineN 0 65
node research/sound-bn254-native/prototypes/ranges.mjs > research/sound-bn254-native/prototypes/ranges.json
node research/sound-bn254-native/prototypes/model.mjs

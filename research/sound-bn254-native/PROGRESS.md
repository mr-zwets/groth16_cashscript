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

- setup.mjs (v1, everyone hashes everything): 0.41-0.44M/input; setup2.mjs (v2 design: digest list in input 0,
  own delta slices with per-role digests): 0.32-0.36M/input, all 3 inputs VALID in a real bch-2026 3-input tx.
- facts.mjs: no exceptional affine step for B in G2 along the schedule; p = 3 mod 4 (norm anisotropic).
- model.mjs (SPLITLIB=1 CAP=9800): DESIGN = all-affine inverse-norm, 3 inputs, ~26.8k B (bytes-bound, margins >= 2.5%).
  Alternatives: 4 inputs ~28.8k; slope witnesses infeasible/28.9k; hybrids ~27.9k; SI projective 4 inputs ~32.2k.

- Calibrated model (chunk sums corrected to direct range measurements, within 0.2%): DESIGN 26,884 B, op 20.97M,
  3 inputs [0,24) 9,087 B / [24,48) 9,037 B / [48,65) 8,504 B, margins 2.0%.
- README.md written (protocol, soundness argument, layout table, sources of every number, alternatives, liveness, risks).

## Next (if continued)
- Optional: optimize setup2 further; build phase = port SI-GLS build/export/redteam/sweep to 3 inputs.

## Commands
node research/sound-bn254-native/prototypes/kernels.mjs
node research/sound-bn254-native/prototypes/loop.mjs affineN 0 65
node research/sound-bn254-native/prototypes/setup2.mjs
SPLITLIB=1 CAP=9800 node research/sound-bn254-native/prototypes/model.mjs

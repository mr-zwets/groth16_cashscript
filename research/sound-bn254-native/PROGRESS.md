# bn-native-sound-design1 (designer 1 of 2): sound BN254 Groth16 on bch-2026, multi-input, angle = minimize bytes

Worktree: groth16_cashscript (branch wip/bn-native-sound-design1). Design record goes to
groth16_cashscript/research/sound-bn254-native/ (README + prototypes).

## Done
- Read SI-GLS README/script/asm, research/sound-sz-bn254, bench scoring (intra-tx: sum(locking+unlocking) + 43/input + ~12).
- SI-GLS profile (standard, fixture 0): total 23.38M; bdbl 9.31M (143k/event), BADD 3.90M+0.36M term (156k each),
  dstep 3.19M + 1.03M (36k each), gls 1.32M, bnd 1.54M, quotient 0.74M, setup (transcript+parse+powers+tables) ~0.85M.

## Next
- Prototype affine witnessed-slope kernels (dbl/add) with the SI kernel scheduler; measure op.
- Model per-input layout and balance (bytes vs op/800).

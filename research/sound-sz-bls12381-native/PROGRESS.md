# bls-native-sound-design1 — PROGRESS

Task: design (not build) a sound-by-construction BLS12-381 Groth16 verifier for bch-2026 (standard, one tx,
P2SH32 multi-input), angle: minimize total bytes. Designer 1 of 2.
Worktree: work/bls-native-sound-design1/groth16_cashscript (branch wip/bls-native-sound-design1).
Prototype dir: research/sound-sz-bls12381-native/prototypes/

## Done
- math.mjs: BLS tower <-> Fp[X]/(X^12 - 2X^6 + 2) map, eta, Frob, psi, M-type lines, binary |x| schedule
  (63 events, adds at events 1,3,6,15,47), Miller class == noble, residue lambda = p - x, G2 criterion facts
  (gcd(p-x,h2)=1), GLS lattice (|e| < 2^63, u = e + 2^63, 64 bits). All asserted at import.
- asm.mjs: SI-GLS assembler with field length parameter (FIELD.len = 48).

- kernels.mjs + measure.mjs (kernels.json): VM-measured BLS kernels, outputs checked vs DAG and vs math.mjs formulas:
  BDbl proj 233,993 op / 423 B; BAdd proj 329,561 / 585; ADbl affine witnessed slope 148,159 / 262; AAdd 147,866 / 282;
  DStep (slope-only bake) 78,448 / 147; DLine (full bake) 32,752 / 47; EV 28,256 / 46; TM 92,180 / 111; TA 10,647; Bound 15,219.
- protocol.mjs + test-protocol.mjs: honest prover (bench BLS VK), chunking (chunk0 = event 1 with G_0 start, 31 two-event
  chunks, terminal merged), transcript, aggregated odd quotient, value-level verifier split over input chunk ranges.
  fixture0 nq 70 (3,360 B), NQ_MAX 127 (affine) / 130 (projective); WS 16,320 (all-affine) / 9,792 (projective).

## Next
- kernels.mjs + measure.mjs: measure BLS kernels in libauth VM (B dbl/add, delta step, EV, tables, affine-slope variants).
- cost model + input layout (layout.mjs), README design record.

## Commands
- node research/sound-sz-bls12381-native/prototypes/math.mjs   (asserts)

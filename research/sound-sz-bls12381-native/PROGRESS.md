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

- worker.mjs: VM prototype of a Miller input (chunks [j0,j1)), partial sum R_i checked == reference. Measured (fixture 0, std):
  per event: affine dbl+slope decode 152.8k, projective dbl 232.5k, delta step 80.6k, GLS 10.4k (zero nibbles) / 17k (full);
  boundary 57k per chunk; adds affine 154k, projective 332k (+ a delta step); setup: env 117k, tables 630k, S_c 31k, start 35k;
  terminal 176k + endpoint 45k.  (node worker.mjs 4 12 aff ; 24 32 aff ; 0 4 proj)
- glue.mjs: real bch-2026 multi-input tx (standard+consensus valid): loader 19 B, redeem 53 B (<K> <i> LOADER), shared
  program blob loaded by OP_INPUTBYTECODE+SHA256+OP_DEFINE, nested OP_DEFINE + loops OK, every input pins count/order/
  P2SH32(<K><j>LOADER) (no fixed point); reorder and tampered blob rejected. Glue ~33-80k op per input.

- head.mjs: VM prototype of the head (transcript tree over regions + WQ, claims, statement ranges/nibble mask, curve and
  twist checks, binding loop, Horner, final identity over worker partial sums): accepts honest witness. fixture0 op 1.17M
  (transcript 67k, statement 33k, curves 91k, binding 319k, Horner 8k/word, final 98k).
- nq-dist.mjs: random statements n_q 78..124 (median 96); fixture0 / small inputs 70; artificial min 55; max 127.
  -> canonical WQ minimum length N_MIN = 70 (zero-left-pad only below 70).
- layout.mjs: cost model (measured components + EST glue) + exhaustive partition search + data relocation.
  BEST n=4: score 32,786 B, owners [[0,3],[3,14],[14,24],[24,32]], projective from event 48, blob carrier in3,
  margins >= 1.5% std at nq 70 and 127. n=5: 33,663.

- worst.mjs: GLS worst case 34.2k/event (dense nibbles; fixture0 ~10k). Mixed terminal worker validated (proj endpoint 98k).
- lazy-reduction kernels (ADbl2 -2.6%, DStep2 -6%; ~0.57M op total) measured, NOT in the headline.
- FINAL layout (n=4): mixed (proj from event 56) 33,551 B @ >=1.5% margin; all-affine 33,919 B @ >=4.8% margin (recommended).
  Sensitivity: blob +-1 kB -> 34,167 / 32,918; loop glue 8k/event -> 33,781. Files: layout-n4-*.txt

## Next
- kernels.mjs + measure.mjs: measure BLS kernels in libauth VM (B dbl/add, delta step, EV, tables, affine-slope variants).
- cost model + input layout (layout.mjs), README design record.

## Commands
- node research/sound-sz-bls12381-native/prototypes/math.mjs   (asserts)

# native-bls-design2 — PROGRESS

Task (Track 3, design only): ANGLE B (structure: split points / input count / hash-authenticated code sharing / SI-GLS reuse)
for a smaller sound BLS12-381 native verifier (new id, e.g. bch-groth16-bls12381-sound-native-v2).
Deliverable: /home/mrzwets/BCH-projects/verifier.cash/work/native-bls/DESIGN-2.md (copy + model script on this branch).
Worktree: groth16_cashscript on wip/native-bls-design2 (from origin/wip/native-bls-breakdown 954ff9e); node_modules symlinked.

## Log
- 2026-10-27: read BREAKDOWN.md, design record, README, script.mjs, opcat.json; worktree created.
- 2026-10-27: model.mjs (score = max(N, S_op) from opcat.json) + DESIGN-2.md written; copy on branch under
  chunked/bls12-381/bls-native-sound/design2/. STATUS: DONE (design only).
  Result: stage 1 (C1 binding into program, C2 raw challenges, C3 descriptor pins, C4 one read per sibling) -53 B alone,
  -294 B once op slack >= 0.5M; converters C5 P2S (pays from 0.55M) and C6 SI-GLS projective tail (from 1.2M).
  Est. 33,480 at A = 1.0M, 33,265 at 1.5M. Structural alternatives (3/5 inputs, head-only, single carrier, per-role
  loading, table sharing, delta-in-program) evaluated and rejected with numbers.

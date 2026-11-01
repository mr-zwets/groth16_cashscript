#!/usr/bin/env bash
# Track 9 S2, end to end: re-prove the 24 M1 statements on the genesis notes, build the case files, grade, sweep.
#   CARGO_TARGET_DIR=<cache>/target S2_CACHE=<cache>/s2 T8_S7_VEC=<Track 8 S7 cache>/vec T8_S3_CASES=<Track 8 S3 cache>/cases ./gen-s2.sh
# One heavy job at a time: prover under nice with RAYON_NUM_THREADS=4; node one process, nice. About 10 minutes.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
: "${CARGO_TARGET_DIR:?}" "${S2_CACHE:?}" "${T8_S7_VEC:?Track 8 S7 vectors (valid proofs whose ROOT is not in the ring)}" "${T8_S3_CASES:?Track 8 S3 case files}"
export RAYON_NUM_THREADS=4
B=$CARGO_TARGET_DIR/release/pq-pool-prover
(cd "$HERE/../prover" && nice cargo build --release --offline -j4)
# 1. statements: 24 on genesis notes 0..23; second-seed (0, 1) and cap-0 (0, 1) proofs for the mix/other_vk families
nice node "$HERE/gen-statements.mjs" --bin "$B" --outdir "$S2_CACHE/vec" --first 0 --count 24 | tee "$HERE/results/gen-vec.txt"
nice node "$HERE/gen-statements.mjs" --bin "$B" --outdir "$S2_CACHE/ovk" --first 0 --count 2 --seed-base 9900 --suffix -seed2
nice node "$HERE/gen-statements.mjs" --bin "$B" --set Z128 --outdir "$S2_CACHE/ovk" --first 0 --count 2
# 2. case files (Track 8 S3 gen-cases.mjs): full families for statements 0..2, light for the rest
mkdir -p "$S2_CACHE/full" "$S2_CACHE/light"
for i in 0 1 2; do ln -sf ../vec/m1-t9-$i-Z128_cap5.json "$S2_CACHE/full/"; done
for i in $(seq 3 23); do ln -sf ../vec/m1-t9-$i-Z128_cap5.json "$S2_CACHE/light/"; done
rm -rf "$S2_CACHE/cases"
nice node "$HERE/../../pq-stark-batch/verifier/gen-cases.mjs" --out "$S2_CACHE/cases" --light-prefix "$S2_CACHE/light/" --light-prefix "$S2_CACHE/ovk/" \
  "$S2_CACHE"/full/*.json "$S2_CACHE"/light/*.json "$S2_CACHE"/ovk/*.json | tail -1
# 3. grading (2tx+W baseline, 1tx+W measured)
nice node "$HERE/grade-a.mjs" "$S2_CACHE"/vec/*.json > "$S2_CACHE/grade-a.log"
grep '^grade-a\|^   ' "$S2_CACHE/grade-a.log" | tee "$HERE/results/grade-a.txt"
# 4. sweeps: production (2tx + W, S7 families + pool families), harness (1tx, no W, CTX a witness item)
nice node "$HERE/test-a.mjs" --plan 2tx --layout --pool --t8 "$T8_S7_VEC" --out "$HERE/results/test-a-2tx-pool.json" "$S2_CACHE"/cases/*.json > "$S2_CACHE/test-a-2tx.log" 2>&1 || true
nice node "$HERE/test-a.mjs" --plan 1tx --harness --out "$HERE/results/test-a-harness.json" "$T8_S3_CASES"/m1-*Z128_cap5*.json > "$S2_CACHE/test-a-harness.log" 2>&1 || true
grep -h '^test-a\|^FAIL\|no-op\|not run on chain' "$S2_CACHE"/test-a-*.log | tee "$HERE/results/test-a.txt"

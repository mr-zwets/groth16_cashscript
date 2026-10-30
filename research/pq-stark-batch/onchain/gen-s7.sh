#!/usr/bin/env bash
# Track 8 S7: layout a' for M1 (Z128, Merkle cap 5) under today's standard rules, end to end.
#   CARGO_TARGET_DIR=<cache>/target S7_CACHE=<cache>/s7 S4_CACHE=<cache>/s4 S3_CACHE=<cache>/s3 ./gen-s7.sh
# One heavy job at a time: the prover runs under nice with RAYON_NUM_THREADS=4; node is one process, under nice.
# About 30 minutes (prover about 30 s, grading 1 min, sweeps about 25 min). Big artifacts stay in $S7_CACHE.
# Needs S4's cache (the cap-5 and cap-0 proofs of statements 0 and 1: second seed / other VK) and S3's cap-5 case files.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
: "${CARGO_TARGET_DIR:?set CARGO_TARGET_DIR}" "${S7_CACHE:?set S7_CACHE}" "${S4_CACHE:?set S4_CACHE}" "${S3_CACHE:?set S3_CACHE (S3 case files)}"
export RAYON_NUM_THREADS=4
B=$CARGO_TARGET_DIR/release/pq-stark-batch-prover
(cd "$HERE/../prover" && nice cargo build --release --offline -j4)
mkdir -p "$S7_CACHE/vec" "$S7_CACHE/full" "$S7_CACHE/light" "$S7_CACHE/ovk" "$HERE/results"

# 1. 24 transaction-bound statements under Z128 cap 5: the S4 statements (same leaves, nullifier seeds and outputs)
nice node "$HERE/gen-statements.mjs" --bin "$B" --set Z128+cap=5 --outdir "$S7_CACHE/vec" --count 24 --leaves 0,1073741823 --tag s7

# 2. case files (S3 gen-cases.mjs): full families for statements 0..2, light for the rest; S4's cap-5 proofs of
#    statements 0 and 1 are second-seed proofs under the same VK, S4's cap-0 proofs are other-VK proofs
for i in 0 1 2; do ln -sf ../vec/m1-s7-$i-Z128_cap5.json "$S7_CACHE/full/"; done
for i in $(seq 3 23); do ln -sf ../vec/m1-s7-$i-Z128_cap5.json "$S7_CACHE/light/"; done
for i in 0 1; do
  ln -sf "$S4_CACHE/ovk/m1-s4-$i-Z128_cap5.json" "$S7_CACHE/ovk/m1-s7-$i-Z128_cap5-seed2.json"
  ln -sf "$S4_CACHE/vec/m1-s4-$i-Z128.json" "$S7_CACHE/ovk/m1-s7-$i-Z128.json"
done
rm -rf "$S7_CACHE/cases"
nice node "$HERE/../verifier/gen-cases.mjs" --out "$S7_CACHE/cases" --light-prefix "$S7_CACHE/light/" --light-prefix "$S7_CACHE/ovk/" \
  "$S7_CACHE"/full/*.json "$S7_CACHE"/light/*.json "$S7_CACHE"/ovk/*.json | tail -1

# 3. grading (today's rules: every input standard + consensus, whole-tx verify, sizes) and the per-phase profile
nice node "$HERE/grade-a.mjs" "$S7_CACHE"/vec/*.json > "$S7_CACHE/grade-a.log"
grep '^grade-a\|^   ' "$S7_CACHE/grade-a.log" | tee "$HERE/results/grade-a.txt"
nice node "$HERE/profile-a.mjs" "$S7_CACHE/vec/m1-s7-0-Z128_cap5.json" > "$HERE/results/profile-a.txt"

# 4. sweeps: production (CTX from the final transaction) in both plans with the a' layout/thread families; harness
#    (CTX a witness item) on S3's cap-5 case files
nice node "$HERE/test-a.mjs" --plan 1tx --layout --out "$HERE/results/test-a-1tx.json" "$S7_CACHE"/cases/*.json > "$S7_CACHE/test-a-1tx.log" 2>&1 || true
nice node "$HERE/test-a.mjs" --plan 2tx --layout --out "$HERE/results/test-a-2tx.json" "$S7_CACHE"/cases/*.json > "$S7_CACHE/test-a-2tx.log" 2>&1 || true
nice node "$HERE/test-a.mjs" --plan 1tx --harness --out "$HERE/results/test-a-harness.json" "$S3_CACHE"/cases/m1-*Z128_cap5*.json > "$S7_CACHE/test-a-harness.log" 2>&1 || true
grep -h '^test-a\|^FAIL' "$S7_CACHE"/test-a-*.log | tee "$HERE/results/test-a.txt"

# 5. three vectors committed (leaf 0, 2^30 - 1, derived)
mkdir -p "$HERE/../prover/vectors/S7"
for i in 0 1 2; do cp "$S7_CACHE/vec/m1-s7-$i-Z128_cap5.json" "$HERE/../prover/vectors/S7/"; done

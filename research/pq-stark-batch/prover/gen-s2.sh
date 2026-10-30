#!/usr/bin/env bash
# Track 8 S2 (DESIGN-T8 sec. 7, S2): statement AIRs M1 and M2. Regenerates every S2 vector and report.
# One heavy job at a time: nice, RAYON_NUM_THREADS=4, cargo -j4.
#   CARGO_TARGET_DIR  build directory (default ./target, git-ignored)
#   S2_CACHE          scratch for trace dumps and the batch vectors (default ./target/s2-cache)
#   AIR8_REF_DIR      bench research/pq-stark/design-t8 (AIR-SPEC.md, air8_ref.py), for the Python cross-check
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-4}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$HERE/target}"
CACHE="${S2_CACHE:-$CARGO_TARGET_DIR/s2-cache}"
cd "$HERE"
nice cargo build --release --offline -j4
BIN="$CARGO_TARGET_DIR/release/pq-stark-batch-prover"
V="$HERE/vectors/S2"
R="$V/report"
mkdir -p "$V" "$R" "$CACHE/dump" "$CACHE/batch" "$CACHE/bench"

M1=Z128            # M1, 100 KB layouts (cap 0)
M1C=Z128+cap=5     # M1, today's-rules layout (cap 5)
M2=Z128g+cpow=3+lpow=8   # M2 (AIR-SPEC sec. 5: commit PoW 3; lookup PoW 8)
LEAVES="0@1 1073741823@2 723295799@3"   # leaf index @ witness seed: 0, 2^30 - 1, random

# 1. Poseidon2 differential test, honest traces through Plonky3's checkers, bus checks, trace dumps
nice "$BIN" s2 selftest --out "$R/selftest.json" --dump "$CACHE/dump"
if [ -n "${AIR8_REF_DIR:-}" ]; then
  nice python3 "$HERE/s2-crosscheck.py" "$AIR8_REF_DIR" "$CACHE/dump" | tee "$R/crosscheck-air8_ref.txt"
fi
# 2. single-cell mutation completeness
nice "$BIN" s2 mutate --out "$R/mutate.json"
# 3. forced unsatisfying traces are rejected by verify_batch
nice "$BIN" s2 forced --out "$R/forced.json"
# 4. wrong public values and other verifying keys
nice "$BIN" s2 pvs --out "$R/pvs.json"
# 5. depth-30 vectors with the tamper sweep (leaf 0, 2^30 - 1, random), and a second prover seed (ZK)
for lw in $LEAVES; do
  for spec in "m1:$M1" "m1:$M1C" "m2:$M2"; do
    st="${spec%%:*}"; set="${spec#*:}"; tag="$(echo "$set" | tr '+' '_' | tr -d '=')"
    out="$V/$st-${lw%@*}-$tag.json"
    nice "$BIN" prove --case "$st@$lw" --set "$set" --seed 1 --sweep --out "$out"
    nice "$BIN" prove --case "$st@$lw" --set "$set" --seed 2 --out "$CACHE/bench/$st-${lw%@*}-$tag-seed2.json"
  done
done
# 6. many statements: 24 random M1 statements per cap, 8 random M2 statements (vectors kept in the cache)
nice "$BIN" s2 batch --stmt m1 --set "$M1" --count 24 --seed 1000 --outdir "$CACHE/batch" --out "$R/batch-m1-Z128.json"
nice "$BIN" s2 batch --stmt m1 --set "$M1C" --count 24 --seed 2000 --outdir "$CACHE/batch" --out "$R/batch-m1-Z128_cap5.json"
nice "$BIN" s2 batch --stmt m2 --set "$M2" --count 8 --seed 3000 --outdir "$CACHE/batch" --out "$R/batch-m2-Z128g_cpow3_lpow8.json"
# 7. prover time and peak RSS, one fresh process per run, at 4 threads and at 1 thread
for th in 4 1; do
  for spec in "m1:$M1" "m1:$M1C" "m2:$M2"; do
    st="${spec%%:*}"; set="${spec#*:}"; tag="$(echo "$set" | tr '+' '_' | tr -d '=')"
    for k in 1 2 3; do
      RAYON_NUM_THREADS=$th nice "$BIN" prove --case "$st@723295799@3" --set "$set" --seed $((10 + k)) \
        --out "$CACHE/bench/$st-$tag-t$th-$k.json"
    done
  done
done
# 8. independent re-check of the committed vectors (rebuilds each verifying key, every tampered case)
nice "$BIN" check $(ls "$V"/*.json) 2>&1 | tee "$R/rust-check.txt" | tail -1
# 9. summary: sizes against S0's expected values, seed freshness, time and memory
nice python3 "$HERE/s2-summary.py" "$V" "$CACHE" > "$R/summary.json"
python3 -c "import json,sys; s=json.load(open('$R/summary.json')); print(json.dumps(s['acceptance'], indent=1))"

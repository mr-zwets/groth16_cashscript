#!/usr/bin/env bash
# Track 9 S4: re-run the S1-S3 suites that S4 changes touch (R: the W-slot pin; W: the flush branch). S2's vectors and
# case files are reused (a proof does not depend on R or W). Results go to */results/s4rerun/ and
# node/results/<NAME>*; the S0-S3 originals stay as they were.
#   S2_CACHE=<S2 cache: vec/, cases/> T8_S7_VEC=<Track 8 S7 vectors> T8_S3_CASES=<Track 8 S3 case files> \
#   LOGS=<dir> OPCOST_DIR=<datadirs> ./rerun-s4.sh [S3 NODE NAME]
# One heavy job at a time: everything below runs in sequence, under nice.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
: "${S2_CACHE:?}" "${T8_S7_VEC:?}" "${T8_S3_CASES:?}" "${LOGS:?}"
mkdir -p "$HERE/r/results/s4rerun" "$HERE/w/results/s4rerun" "$LOGS"
cd "$HERE/w" && nice node test-w.mjs > "$HERE/w/results/s4rerun/test-w.log" 2>&1 && mv results/s1-w.json results/s4rerun/s1-w.json && git checkout -- results/s1-w.json
cd "$HERE/r"
nice node grade-a.mjs "$S2_CACHE"/vec/*.json > "$LOGS/grade-a.log" && mv results/grade-a.json results/s4rerun/grade-a.json && git checkout -- results/grade-a.json
grep '^grade-a\|^   ' "$LOGS/grade-a.log" > results/s4rerun/grade-a.txt
nice node test-a.mjs --plan 2tx --layout --pool --t8 "$T8_S7_VEC" --out results/s4rerun/test-a-2tx-pool.json "$S2_CACHE"/cases/*.json > "$LOGS/test-a-2tx.log" 2>&1 || true
nice node test-a.mjs --plan 1tx --harness --out results/s4rerun/test-a-harness.json "$T8_S3_CASES"/m1-*Z128_cap5*.json > "$LOGS/test-a-harness.log" 2>&1 || true
grep -h '^test-a\|^FAIL\|no-op\|not run on chain' "$LOGS"/test-a-2tx.log "$LOGS"/test-a-harness.log > results/s4rerun/test-a.txt
if [ -n "${1:-}" ]; then : "${OPCOST_DIR:?}"; S2_VEC="$S2_CACHE/vec" OPCOST_DIR="$OPCOST_DIR" "$HERE/node/run-s3.sh" "$1"; fi

#!/usr/bin/env bash
# Track 8 S8b (fix round): re-run every node step of gen-s4.sh, gen-s5.sh and gen-s7.sh on the cached proofs, after the
# interpreter fix (2p offsets in D_SUB / D_SUBL / D_RSUBL / D_NEG). The proofs, statements and S3/S4/S7 case files are
# unchanged (no prover run); every script, the b2 library hash and every op-cost figure change.
#   S3_CACHE=<cache>/s3 S4_CACHE=<cache>/s4 S5_CACHE=<cache>/s5 S7_CACHE=<cache>/s7 ./rerun-s8b.sh
# One node process at a time, under nice. Logs go to $S8B_LOG (default $S7_CACHE/../s8b).
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
: "${S3_CACHE:?}" "${S4_CACHE:?}" "${S5_CACHE:?}" "${S7_CACHE:?}"
L=${S8B_LOG:-$S7_CACHE/../s8b}
R=$HERE/results
mkdir -p "$L" "$R"
ts() { date '+%H:%M:%S'; }

echo "$(ts) s8-arith"
nice node "$HERE/s8-arith.mjs" > "$L/s8-arith.log" 2>&1
tail -1 "$L/s8-arith.log"

# ---- S4: layout b (gen-s4.sh step 4) ----
echo "$(ts) S4"
nice node "$HERE/test-ctx.mjs" > "$R/test-ctx.txt"
S3M1=$(ls "$S3_CACHE"/cases/m1-*Z128.json "$S3_CACHE"/cases/m1-*Z128-seed*.json "$S3_CACHE"/cases/m1-*Z128~vk*.json)
S4M1=$(ls "$S4_CACHE"/cases/m1-s4-*-Z128.json "$S4_CACHE"/cases/m1-s4-*-Z128-seed2.json)
nice node "$HERE/grade-b.mjs" "$S4_CACHE"/vec/*.json > "$L/grade-b.log" 2>&1 || true
tail -1 "$L/grade-b.log" > "$R/grade-b-summary.txt"
nice node "$HERE/profile-b.mjs" "$S4_CACHE/vec/m1-s4-0-Z128.json" > "$R/profile-b.txt"
nice node "$HERE/test-b.mjs" --wit --out "$R/test-b.json" $S4M1 > "$L/test-b.log" 2>&1 || true
nice node "$HERE/test-b.mjs" --harness --wit --out "$R/test-b-harness.json" $S3M1 > "$L/test-b-harness.log" 2>&1 || true
grep -h '^test-b\|^FAIL\|not run on chain' "$L/test-b.log" "$L/test-b-harness.log" | tee "$R/test-b.txt"

# ---- S5/S6: generalized generator, layout b2 (gen-s5.sh steps 3-6) ----
echo "$(ts) S5/S6"
nice node "$HERE/model-agree-n.mjs" --both $(cat "$S5_CACHE/case-files.txt") > "$L/model-agree-n.log" 2>&1 || true
tail -2 "$L/model-agree-n.log" | tee "$R/model-agree-n.txt"
grep -e '^DIS' -e '^skip' "$L/model-agree-n.log" >> "$R/model-agree-n.txt" || true
nice node "$HERE/test-b2.mjs" --layout --out "$R/test-b2-m2p3.json" $(cat "$S5_CACHE/case-files-m2p3.txt") > "$L/test-b2-m2p3.log" 2>&1 || true
tail -3 "$L/test-b2-m2p3.log"
nice node "$HERE/test-b2.mjs" --layout --out "$R/test-b2-m1.json" $(cat "$S5_CACHE/case-files-m1.txt") > "$L/test-b2-m1.log" 2>&1 || true
tail -3 "$L/test-b2-m1.log"
nice node "$HERE/test-b2.mjs" --prod --layout --out "$R/test-b2-prod.json" "$S5_CACHE"/m1/*.json "$S5_CACHE"/vec/*.json > "$L/test-b2-prod.log" 2>&1 || true
tail -3 "$L/test-b2-prod.log"
nice node "$HERE/grade-b2.mjs" --out "$R/grade-b2.json" $(ls "$S5_CACHE"/m1/m1-s4-*-Z128.json "$S5_CACHE"/vec/m2-s5-?-Z128g_cpow3_lpow8.json) > "$L/grade-b2.log" 2>&1 || true
grep -v '^ \|^{\|^}' "$L/grade-b2.log" > "$R/grade-b2.txt" || true
nice node "$HERE/profile-b2.mjs" "$S5_CACHE/m1/m1-s4-0-Z128.json" "$S5_CACHE/vec/m2-s5-0-Z128g_cpow3_lpow8.json" > "$R/profile-b2.txt" 2>&1 || true

# ---- S7: layout a' (gen-s7.sh steps 3-4) ----
echo "$(ts) S7"
nice node "$HERE/grade-a.mjs" "$S7_CACHE"/vec/*.json > "$L/grade-a.log" 2>&1 || true
grep '^grade-a\|^   ' "$L/grade-a.log" | tee "$R/grade-a.txt"
nice node "$HERE/profile-a.mjs" "$S7_CACHE/vec/m1-s7-0-Z128_cap5.json" > "$R/profile-a.txt"
nice node "$HERE/test-a.mjs" --plan 1tx --layout --out "$R/test-a-1tx.json" "$S7_CACHE"/cases/*.json > "$L/test-a-1tx.log" 2>&1 || true
nice node "$HERE/test-a.mjs" --plan 2tx --layout --out "$R/test-a-2tx.json" "$S7_CACHE"/cases/*.json > "$L/test-a-2tx.log" 2>&1 || true
nice node "$HERE/test-a.mjs" --plan 1tx --harness --out "$R/test-a-harness.json" "$S3_CACHE"/cases/m1-*Z128_cap5*.json > "$L/test-a-harness.log" 2>&1 || true
grep -h '^test-a\|^FAIL\|not run on chain' "$L"/test-a-*.log | tee "$R/test-a.txt"
echo "$(ts) done"

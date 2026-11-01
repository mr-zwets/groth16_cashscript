#!/usr/bin/env bash
# Track 8 S4: layout (b) for M1 (Z128, cap 0), end to end.
#   CARGO_TARGET_DIR=<cache>/target S4_CACHE=<cache>/s4 S3_CACHE=<cache>/s3 ./gen-s4.sh
# One heavy job at a time: the prover runs under nice with RAYON_NUM_THREADS=4; node is one process, under nice.
# About 20 minutes (prover about 1 min, sweeps about 15 min). Big artifacts stay in $S4_CACHE; results go to ./results/.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
: "${CARGO_TARGET_DIR:?set CARGO_TARGET_DIR}" "${S4_CACHE:?set S4_CACHE}" "${S3_CACHE:?set S3_CACHE (S3 case files)}"
export RAYON_NUM_THREADS=4
B=$CARGO_TARGET_DIR/release/pq-stark-batch-prover
(cd "$HERE/../prover" && nice cargo build --release --offline -j4)
mkdir -p "$S4_CACHE/vec" "$S4_CACHE/ovk" "$S4_CACHE/full" "$S4_CACHE/light" "$HERE/results"

# 1. 24 transaction-bound statements (leaf 0, 2^30 - 1, then derived leaves); CTX = hash of each spend's outputs
nice node "$HERE/gen-statements.mjs" --bin "$B" --set Z128 --outdir "$S4_CACHE/vec" --count 24 --leaves 0,1073741823

# 2. the same statements under other verifying keys (cap 5, Z128g, M2) and a second ZK seed (same VK)
for i in 0 1; do
  C=$(node -e "console.log(JSON.parse(require('fs').readFileSync('$S4_CACHE/vec/m1-s4-$i-Z128.json','utf8')).case)")
  nice "$B" prove --case "$C" --set Z128+cap=5 --seed 7$i --out "$S4_CACHE/ovk/m1-s4-$i-Z128_cap5.json"
  nice "$B" prove --case "$C" --set Z128 --seed 9$i --out "$S4_CACHE/ovk/m1-s4-$i-Z128-seed2.json"
  nice "$B" prove --case "$C" --set Z128g --seed 8$i --out "$S4_CACHE/ovk/m1-s4-$i-Z128g.json"
  nice "$B" prove --case "m2@${C#m1@}" --set Z128g+cpow=3+lpow=8 --seed 6$i --out "$S4_CACHE/ovk/m2-s4-$i-Z128g_cpow3_lpow8.json"
  for f in "$S4_CACHE"/ovk/m?-s4-$i-*.json; do
    node -e '
      const fs = require("fs"); const [f, src] = process.argv.slice(1);
      const raw = fs.readFileSync(f, "utf8"); if (raw.includes("\"s4_outputs\"")) process.exit(0);
      const s = JSON.parse(fs.readFileSync(src, "utf8"));
      fs.writeFileSync(f, raw.replace(/\}\s*$/, `,"s4_outputs":${JSON.stringify(s.s4_outputs)},"s4_ctx":"${s.s4_ctx}","s4_leaf":${s.s4_leaf},"s4_wseed":${s.s4_wseed}}\n`));' "$f" "$S4_CACHE/vec/m1-s4-$i-Z128.json"
  done
done

# 3. the DESIGN-T8 §8 case families (S3 gen-cases.mjs): full for statements 0..2, light for the rest
for i in 0 1 2; do ln -sf ../vec/m1-s4-$i-Z128.json "$S4_CACHE/full/"; done
for i in $(seq 3 23); do ln -sf ../vec/m1-s4-$i-Z128.json "$S4_CACHE/light/"; done
rm -rf "$S4_CACHE/cases"
nice node "$HERE/../verifier/gen-cases.mjs" --out "$S4_CACHE/cases" --light-prefix "$S4_CACHE/light/" --light-prefix "$S4_CACHE/ovk/" \
  "$S4_CACHE"/full/*.json "$S4_CACHE"/light/*.json "$S4_CACHE"/ovk/*.json | tail -1

# 4. checks and measurements
nice node "$HERE/test-ctx.mjs" | tee "$HERE/results/test-ctx.txt"
S3M1=$(ls "$S3_CACHE"/cases/m1-*Z128.json "$S3_CACHE"/cases/m1-*Z128-seed*.json "$S3_CACHE"/cases/m1-*Z128~vk*.json)
S4M1=$(ls "$S4_CACHE"/cases/m1-s4-*-Z128.json "$S4_CACHE"/cases/m1-s4-*-Z128-seed2.json)
nice node "$HERE/model-agree.mjs" $S3M1 $S4M1 | grep -v '^ok ' | tee "$HERE/results/model-agree.txt"
nice node "$HERE/grade-b.mjs" "$S4_CACHE"/vec/*.json | tail -1 > "$HERE/results/grade-b-summary.txt"
nice node "$HERE/profile-b.mjs" "$S4_CACHE/vec/m1-s4-0-Z128.json" > "$HERE/results/profile-b.txt"
nice node "$HERE/test-b.mjs" --wit --out "$HERE/results/test-b.json" $S4M1 > "$S4_CACHE/test-b.log" 2>&1 || true
nice node "$HERE/test-b.mjs" --harness --wit --out "$HERE/results/test-b-harness.json" $S3M1 > "$S4_CACHE/test-b-harness.log" 2>&1 || true
grep -h '^test-b\|^FAIL' "$S4_CACHE/test-b.log" "$S4_CACHE/test-b-harness.log" | tee "$HERE/results/test-b.txt"

# 5. three vectors committed (leaf 0, 2^30 - 1, derived)
mkdir -p "$HERE/../prover/vectors/S4"
for i in 0 1 2; do cp "$S4_CACHE/vec/m1-s4-$i-Z128.json" "$HERE/../prover/vectors/S4/"; done

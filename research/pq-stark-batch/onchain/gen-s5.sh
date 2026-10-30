#!/usr/bin/env bash
# Track 8 S5 + S6: generalized generator (N tables, heights, LogUp) and layout b2 (two inputs), end to end.
#   CARGO_TARGET_DIR=<cache>/target S5_CACHE=<cache>/s5 S4_CACHE=<cache>/s4 S3_CACHE=<cache>/s3 ./gen-s5.sh
# One heavy job at a time: the prover runs under nice with RAYON_NUM_THREADS=4; node is one process, under nice.
# Big artifacts stay in $S5_CACHE; results go to ./results/.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
: "${CARGO_TARGET_DIR:?set CARGO_TARGET_DIR}" "${S5_CACHE:?set S5_CACHE}" "${S4_CACHE:?set S4_CACHE}" "${S3_CACHE:?set S3_CACHE (S3 case files)}"
export RAYON_NUM_THREADS=4
B=$CARGO_TARGET_DIR/release/pq-stark-batch-prover
R=$HERE/results
mkdir -p "$S5_CACHE/vec" "$S5_CACHE/m1" "$R"

# 1. transaction-bound M2 statements (8) and second-seed proofs of two of them; M1: S4's 24 statements
if [ ! -f "$S5_CACHE/vec/m2-s5-7-Z128g_cpow3_lpow8.json" ]; then
  (cd "$HERE/../prover" && nice cargo build --release --offline -j4)
  nice node "$HERE/gen-statements.mjs" --bin "$B" --stmt m2 --set Z128g+cpow=3+lpow=8 --outdir "$S5_CACHE/vec" --count 8 --leaves 0,1073741823
  for i in 0 1; do
    F=$S5_CACHE/vec/m2-s5-$i-Z128g_cpow3_lpow8.json; O=${F%.json}-seed2.json
    CASE=$(node -e "console.log(JSON.parse(require('fs').readFileSync('$F','utf8')).case)")
    nice "$B" prove --case "$CASE" --set Z128g+cpow=3+lpow=8 --seed 9$i --out "$O" > /dev/null
    node -e '
      const fs = require("fs"); const [f, src] = process.argv.slice(1);
      const raw = fs.readFileSync(f, "utf8"); const s = JSON.parse(fs.readFileSync(src, "utf8"));
      fs.writeFileSync(f, raw.replace(/\}\s*$/, `,"s4_outputs":${JSON.stringify(s.s4_outputs)},"s4_ctx":"${s.s4_ctx}","s4_leaf":${s.s4_leaf},"s4_wseed":${s.s4_wseed}}\n`));' "$O" "$F"
  done
fi
for f in "$S4_CACHE"/vec/*.json "$S4_CACHE"/ovk/m1-s4-?-Z128-seed2.json; do ln -sf "$f" "$S5_CACHE/m1/"; done

# 2. the S3 case files this generator covers: Merkle cap 0 (b, b2), every AIR (M1, M2, Plonky3's batch tests)
ls "$S3_CACHE"/cases/*.json | grep -v -e cap5 -e PTZ > "$S5_CACHE/case-files.txt"
ls "$S3_CACHE"/cases/*.json | grep -v -e cap5 -e PTZ -e '/m1-' > "$S5_CACHE/case-files-m2p3.txt"
ls "$S3_CACHE"/cases/m1-*.json | grep -v cap5 > "$S5_CACHE/case-files-m1.txt"

# 3. model agreement: the on-chain algorithm (unsplit and split as b2) against verify-batch.mjs, transcripts included
nice node "$HERE/model-agree-n.mjs" --both $(cat "$S5_CACHE/case-files.txt") > "$S5_CACHE/model-agree-n.log" 2>&1 || true
tail -2 "$S5_CACHE/model-agree-n.log" | tee "$R/model-agree-n.txt"
grep -e '^DIS' -e '^skip' "$S5_CACHE/model-agree-n.log" >> "$R/model-agree-n.txt" || true

# 4. b2 sweeps on the S3 case files (harness statement: CTX as a witness item), with the layout family
nice node "$HERE/test-b2.mjs" --layout --out "$R/test-b2-m2p3.json" $(cat "$S5_CACHE/case-files-m2p3.txt") > "$S5_CACHE/test-b2-m2p3.log" 2>&1 || true
tail -2 "$S5_CACHE/test-b2-m2p3.log"
nice node "$HERE/test-b2.mjs" --layout --out "$R/test-b2-m1.json" $(cat "$S5_CACHE/case-files-m1.txt") > "$S5_CACHE/test-b2-m1.log" 2>&1 || true
tail -2 "$S5_CACHE/test-b2-m1.log"

# 5. production: transaction-bound statements (CTX from the spending transaction), tx/root/layout families
nice node "$HERE/test-b2.mjs" --prod --layout --out "$R/test-b2-prod.json" "$S5_CACHE"/m1/*.json "$S5_CACHE"/vec/*.json > "$S5_CACHE/test-b2-prod.log" 2>&1 || true
tail -2 "$S5_CACHE/test-b2-prod.log"

# 6. bytes, op-cost and regimes of the transaction-bound statements (seed2 files excluded)
nice node "$HERE/grade-b2.mjs" --out "$R/grade-b2.json" $(ls "$S5_CACHE"/m1/m1-s4-*-Z128.json "$S5_CACHE"/vec/m2-s5-?-Z128g_cpow3_lpow8.json) > "$S5_CACHE/grade-b2.log" 2>&1 || true
grep -v '^ \|^{\|^}' "$S5_CACHE/grade-b2.log" > "$R/grade-b2.txt" || true
cat "$R/grade-b2.txt"

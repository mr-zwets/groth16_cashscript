#!/usr/bin/env bash
# Track 8 S3 agreement suite: JS verify-batch.mjs vs Plonky3 verify_batch on the same valid and tampered cases.
#   CARGO_TARGET_DIR=<cache>/target S3_CACHE=<cache>/s3 S2_BATCH=<cache>/s2/batch ./gen-s3.sh
# One heavy job at a time: the Rust steps run under nice with RAYON_NUM_THREADS=4, node runs single-process.
# About 3 minutes. Big artifacts stay in $S3_CACHE; the summary goes to ./report/.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
VEC=$HERE/../prover/vectors
: "${CARGO_TARGET_DIR:?set CARGO_TARGET_DIR}" "${S3_CACHE:?set S3_CACHE}" "${S2_BATCH:?set S2_BATCH (S2 batch vectors)}"
export RAYON_NUM_THREADS=4
B=$CARGO_TARGET_DIR/release/pq-stark-batch-prover
(cd "$HERE/../prover" && nice cargo build --release --offline -j4)
mkdir -p "$S3_CACHE/seeds" "$HERE/report"

# 1. forced unsatisfying traces (S2) with their proof bytes
nice "$B" s2 forced --with-proofs --out "$S3_CACHE/forced-proofs.json"

# 2. extra ZK seeds: the same statements / cases proved again (same VK for M1/M2: published setup seed)
for leaf in 0@1 1073741823@2 723295799@3; do
  l=${leaf%@*}
  for seed in 2 3; do
    nice "$B" prove --case "m1@$leaf" --set Z128 --seed $seed --out "$S3_CACHE/seeds/m1-$l-Z128-seed$seed.json"
    nice "$B" prove --case "m1@$leaf" --set Z128+cap=5 --seed $seed --out "$S3_CACHE/seeds/m1-$l-Z128_cap5-seed$seed.json"
    nice "$B" prove --case "m2@$leaf" --set Z128g+cpow=3+lpow=8 --seed $seed --out "$S3_CACHE/seeds/m2-$l-Z128g_cpow3_lpow8-seed$seed.json"
  done
done
for c in "single_instance 3" "three_instances_mixed_sizes 5" "mixed_preprocessed 4" "both_lookups_zk 3" "periodic_air_zk 2"; do
  set -- $c
  for seed in 2 3; do nice "$B" prove --case "$1" --set Z128 --shift "$2" --seed $seed --out "$S3_CACHE/seeds/$1-Z128-seed$seed.json"; done
done
for c in "single_instance 1" "three_instances_mixed_sizes 3" "mixed_preprocessed 2" "both_lookups_zk 1" "periodic_air_zk 0"; do
  set -- $c
  nice "$B" prove --case "$1" --set Z128g --shift "$2" --seed 2 --out "$S3_CACHE/seeds/$1-Z128g-seed2.json"
done
for c in both_lookups_zk periodic_air_zk; do nice "$B" prove --case $c --set PTZ --shift 0 --seed 2 --out "$S3_CACHE/seeds/$c-PTZ-seed2.json"; done

# 3. the case set (DESIGN-T8 §8), one file per vector, plus VK-variant files
rm -rf "$S3_CACHE/cases"
nice node "$HERE/gen-cases.mjs" --out "$S3_CACHE/cases" --forced "$S3_CACHE/forced-proofs.json" --light-prefix "$S3_CACHE/" --light-prefix "$S2_BATCH/" \
  $(ls "$VEC"/P3/*.json "$VEC"/Z128/*.json "$VEC"/S2/*.json | grep -v accept-) "$S3_CACHE"/seeds/*.json "$S2_BATCH"/*.json \
  | tail -1 | tee "$HERE/report/gen-cases.txt"

# 4. Rust verdicts, then JS verdicts and the comparison
nice "$B" check --verdicts "$S3_CACHE/rust-verdicts.json" "$S3_CACHE"/cases/*.json 2>&1 | grep -v '^ok ' | tee "$HERE/report/rust-check.txt"
nice node "$HERE/agree.mjs" --rust "$S3_CACHE/rust-verdicts.json" --out "$S3_CACHE/agree-report.json" "$S3_CACHE"/cases/*.json \
  | grep -v '^ok ' | tee "$HERE/report/agree.txt"
node -e '
const r = JSON.parse(require("fs").readFileSync(process.argv[1], "utf8"));
const keep = ({ disagree, unexpected_list, vectors, ...rest }) => ({ ...rest, disagree, unexpected_list,
  vectors: vectors.map(({ file, case: c, set, seed, bytes, accept, transcript_identical, transcript_hashes, js_verify_ms, cases }) =>
    ({ file, case: c, set, seed, bytes, accept, transcript_identical, transcript_hashes, js_verify_ms, cases })) });
require("fs").writeFileSync(process.argv[2], JSON.stringify(keep(r), null, 1));' "$S3_CACHE/agree-report.json" "$HERE/report/summary.json"

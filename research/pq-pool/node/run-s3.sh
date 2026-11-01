#!/usr/bin/env bash
# Track 9 S3: fresh POLICY=1 BCHN v29.1.0 regtest node, run s3.ts, stop the node.
#   S2_VEC=<dir of m1-t9-<i>-Z128_cap5.json> OPCOST_DIR=<datadirs> ./run-s3.sh NAME [NODE_CPU] [DRIVER_CPU]
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
: "${S2_VEC:?}" "${OPCOST_DIR:?}"; export OPCOST_DIR
NAME=${1:?name}; NCPU=${2:-9}; DCPU=${3:-7}
POLICY=1 "$HERE/node.sh" start "$NAME" "$NCPU"
trap '"$HERE/node.sh" stop "$NAME" || true' EXIT
cd "$HERE" && nice taskset -c "$DCPU" "$HERE/../../../node_modules/.bin/tsx" s3.ts --node "$NAME" --vec "$S2_VEC" --out "$HERE/results/$NAME.jsonl" 2> "$HERE/results/$NAME.log"
node "$HERE/summarize-s3.mjs" "$HERE/results/$NAME.jsonl" > "$HERE/results/$NAME-summary.json"

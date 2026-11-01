#!/usr/bin/env bash
# Track 9 S4: fresh POLICY=1 BCHN v29.1.0 regtest node, run s4.ts (deposit -> flush -> prove -> withdraw, and with
# --wrap the ring wraparound), stop the node.
#   S2_VEC=<S2 vector dir (R is built from vector 0)> PROVER=<pq-pool-prover> S4_CACHE=<dir> OPCOST_DIR=<datadirs> \
#     ./run-s4.sh NAME [NODE_CPU] [DRIVER_CPU] [--wrap]
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
: "${S2_VEC:?}" "${PROVER:?}" "${S4_CACHE:?}" "${OPCOST_DIR:?}"; export OPCOST_DIR
NAME=${1:?name}; NCPU=${2:-9}; DCPU=${3:-7}; WRAP=${4:-}
POLICY=1 "$HERE/node.sh" start "$NAME" "$NCPU"
trap '"$HERE/node.sh" stop "$NAME" || true' EXIT
cd "$HERE" && nice taskset -c "$DCPU" "$HERE/../../../node_modules/.bin/tsx" s4.ts --node "$NAME" --vec "$S2_VEC" --prover "$PROVER" --cache "$S4_CACHE" --out "$HERE/results/$NAME.jsonl" $WRAP 2> "$HERE/results/$NAME.log"
node "$HERE/summarize-s4.mjs" "$HERE/results/$NAME.jsonl" > "$HERE/results/$NAME-summary.json"

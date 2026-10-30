#!/bin/sh
# Regenerate the vectors (gnark v0.16.4) with the Aztec Ignition SRS and re-check them with the JS reference verifier.
# SRS_CACHE holds the ceremony downloads (about 13 MB for LOG=16) and the derived SRS file; it is not committed.
set -e
cd "$(dirname "$0")"
CACHE=${SRS_CACHE:-srs-cache}
LOG=${SRS_LOG:-16}
POINTS=$(( (1 << LOG) + 3 ))
GOMAXPROCS=4 nice go run ./ceremony -cache "$CACHE" -log "$LOG"
GOMAXPROCS=4 nice go run . -srs "$CACHE/ignition_bn254_$POINTS.srs" -out vectors -proofs 5
nice node verify.mjs
# then copy vectors/*.json to ../verifier/vectors/ and run there: SRS_CACHE=$CACHE node srs-check.mjs

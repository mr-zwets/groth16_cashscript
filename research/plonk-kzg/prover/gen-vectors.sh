#!/bin/sh
# Regenerate the vectors (gnark v0.16.4) and re-check them with the JS reference verifier.
set -e
cd "$(dirname "$0")"
GOMAXPROCS=4 nice go run . -out vectors -proofs 5
nice node verify.mjs

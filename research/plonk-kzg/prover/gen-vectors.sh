#!/bin/sh
# Regenerate the vectors (gnark v0.16.4) and re-check them with the JS reference verifier.
set -e
cd "$(dirname "$0")"
GOMAXPROCS=4 nice go run . -out vectors -proofs 5
GOMAXPROCS=4 nice go run . -out vectors -proofs 5 -circuits range64,merkle16rc   # BSB22 commitments (v2-bsb22)
nice node verify.mjs

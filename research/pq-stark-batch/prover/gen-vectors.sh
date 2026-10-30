#!/usr/bin/env bash
# Regenerate every p3b-v1 vector and run the S1 acceptance (DESIGN-T8 section 7, S1).
# One heavy job at a time: nice, RAYON_NUM_THREADS=4, cargo -j4.
#   CARGO_TARGET_DIR  build directory (default ./target, git-ignored); point it outside the repository
#                     to keep the build cache out of the worktree.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-4}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$HERE/target}"
cd "$HERE"
nice cargo build --release --offline -j4
BIN="$CARGO_TARGET_DIR/release/pq-stark-batch-prover"
V="$HERE/vectors"
# 1. Plonky3's own test shapes and ZK settings (PT / PTZ), Plonky3's heights
nice "$BIN" accept --set P3 --shift 0 --outdir "$V/P3" --sweep
# 2. DESIGN-T8 Z128 (ZK, cap 0), heights raised to the strict FRI height rule
nice "$BIN" accept --set Z128 --outdir "$V/Z128" --sweep
# 3. Z128 without ZK, Z128 with cap 5 (today's-rules layout), Z128-g (final length 32)
nice "$BIN" accept --set Z128+zk=0 --outdir "$V/Z128" --sweep
nice "$BIN" accept --set Z128+cap=5 --outdir "$V/Z128" --sweep
nice "$BIN" accept --set Z128g --outdir "$V/Z128" --sweep
# 4. M1's trace height n = 2^10 (LDE 2^20, one arity-8 fold) and a mixed-height batch on the arity grid
nice "$BIN" prove --case single_instance --set Z128 --shift 5 --sweep --out "$V/Z128/single_instance-Z128-n1024.json"
nice "$BIN" prove --case both_lookups_zk --set Z128 --shift 5 --sweep --out "$V/Z128/both_lookups_zk-Z128-n1024.json"
nice "$BIN" prove --case three_instances_mixed_sizes --set Z128g --shift 6 --sweep --out "$V/Z128/three_instances_mixed_sizes-Z128g-n1024.json"
# 5. independent re-check: rebuild each verifying key, decode, verify_batch, every tampered case
nice "$BIN" check $(ls "$V"/*/*.json | grep -v '/accept-') | tee "$V/rust-check.txt" | tail -1

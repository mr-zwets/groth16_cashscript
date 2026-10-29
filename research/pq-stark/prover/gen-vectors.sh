#!/usr/bin/env bash
# Regenerates vectors/: valid proofs (Rust, Plonky3 pinned), tampered cases (JS), then checks every case
# with the independent JS verifier (incl. byte-exact transcript comparison) and with Plonky3's verifier.
set -euo pipefail
cd "$(dirname "$0")"
cargo build --release
B=./target/release/pq-stark-prover
rm -f vectors/*.json
for air in fib mimc; do
  for set in C100 C100h C128 P100 P128; do
    $B prove --air $air --log-n 16 --set $set --out vectors/$air-$set-0.json
    if [ "$set" != C100h ]; then   # the hiding configuration always uses 32-byte digests
      $B prove --air $air --log-n 16 --set $set --zk --out vectors/$air-$set-zk-0.json
      $B prove --air $air --log-n 16 --set $set --zkmin --out vectors/$air-$set-zkmin-0.json
    fi
  done
done
# a second statement per set (size variance; valid only)
for set in C100 C100h C128 P100 P128; do
  $B prove --air mimc --log-n 16 --set $set --k 1 --out vectors/mimc-$set-1.json
done
$B sets vectors/estimates.json > /dev/null
node gen-tampered.mjs $(ls vectors/*-0.json)
node verify.mjs --trace vectors/{fib,mimc}-*.json | tee vectors/js-verify.txt | tail -1
$B check vectors/{fib,mimc}-*.json 2>/dev/null | tee vectors/rust-check.txt | tail -1
node summary.mjs > vectors/summary.json

# PROGRESS (wip/pq-stark-prover; this file stays off main)

## Done
- Plonky3 pinned at 0d803737b681774186cd283b1fd2d8e493655c82. SHA-256 leaves, nodes, challenger and
  grinding over Goldilocks. D = 2 and D = 3 (cubic trinomial).
- AIRs: fib and mimc (Track 4 statement), n = 2^16.
- Sets: C100, C100h, C128, P100, P128, the Soundness picks S100, S100b, S128 and S128b, and the ZK picks
  S100z and S128z (zkmin only).
- ZK via HidingFriPcs: `-zk` (rc 4, salt 4) and `-zkmin` (rc = D, salt 2).
- p3s-v1 byte format (FORMAT.md) and an encoder/decoder that round-trips into Plonky3's verifier.
- verify.mjs: an independent verifier that compares transcripts byte-exactly.
- Tampered cases on every `-0` vector. 1,159 cases: JS 0 unexpected, Plonky3 0 unexpected.
- README.md: protocol, Track 4 differences, sizes, ZK overhead, hash profile, limitations.

## Resume notes
- 2026-10-29: resumed after a session crash. Generated the tampered cases for the S sets and re-ran both
  checkers (1159/1159). Wrote FORMAT.md, README.md and PROGRESS.md.
- Keep heavy runs low-priority: `nice`, and `RAYON_NUM_THREADS=4` for `check`. Grinding at 26-28 bits
  under `prove` uses every core.

## Open (for the Verifier phase)
- The CashVM verifier should follow verify.mjs.
- Bake the three separator seeds as constants.
- Use the trinomial cubic.
- Pick a set from the Soundness handoff (S128 is the smallest 128-bit candidate, at 78.4 KB).

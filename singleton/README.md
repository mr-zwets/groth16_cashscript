# singleton/ — full single-transaction reference verifiers

Each contract here computes a whole verifier step in ONE contract. These are the
CORRECTNESS ORACLES: they compile and run on the loosened BCH 2026 VM and are validated
against `@noble/curves` (and py_ecc), but they exceed BCH consensus limits per input.
They are NOT meant to run on-chain — they are the reference the `chunked/` versions must
match.

## Layout — one self-contained folder per curve

- **`bn254/`** — the complete BN254 Groth16 verifier: field tower (Fp2→Fp6→Fp12), Miller
  loop, final exponentiation, on-chain `vk_x` (`vkx.cash`), and the `verify.cash` /
  `groth16.cash` capstones. Graded byte-for-byte against `@noble/curves` bn254.
- **`bls12-381/`** — the same stack for BLS12-381 (the curve nChain's reference verifier
  uses), so the benchmark can compare on the same curve. Mirrors `bn254/` file-for-file;
  only the curve constants and the Miller / final-exp orchestration differ (ξ = 1+u,
  48-byte field, M-twist, |x| loop, BLS hard part).

Each folder's `README.md` has its per-layer status table and run instructions.

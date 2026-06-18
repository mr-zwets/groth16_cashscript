# singleton/ — full single-transaction reference verifiers

Each contract here computes a whole verifier step in ONE contract (e.g. `vkx.cash` = the full vk_x public-input aggregation). These are the CORRECTNESS ORACLES: they compile and run on the loosened BCH 2026 VM and are validated against py_ecc, but they exceed BCH consensus limits per input (vk_x ≈ 76M op-cost ≈ 10 inputs). They are NOT meant to run on-chain — they are the reference the chunked versions must match.

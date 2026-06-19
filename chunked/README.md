# chunked/ — BCH-limit-viable multi-transaction verifiers

Each verifier step here is split across multiple contracts/transactions so that EVERY chunk fits one BCH input (locking+unlocking <= 10,000 bytes, op-cost <= 8,032,800). State is carried between chunks via a `hash256` commitment (see ../multi-step-computation.md). Each chunk's result must match the singleton reference at the corresponding iteration boundary.

Two implementations of the `vk_x` checkpoint, kept for comparison (same milestone, different approaches):

- **`twoloop/`** — the simpler/original: two separate 254-iteration double-and-add scalar multiplications (`input0*IC1` then `input1*IC2`), inlined EC formulas, in-script Fermat inverse. Carries a 9-coord state (acc + base + R). Op-cost-bound: 16 chunks, ~183 KB total, ~85.2M op-cost.
- **`shamir/`** — the optimized: one shared Shamir/Straus doubling chain (508 → 254 doublings), elliptic-curve ops as reusable multi-return functions (`OP_DEFINE`/`OP_INVOKE`), verified-inverse-on-stack, per-chunk tuned padding. Carries a 5-coord state (R + the runtime public inputs). Size-bound: 16 chunks, ~165 KB total, ~18.9M op-cost.

Both take the public inputs at runtime and reproduce the py_ecc `vk_x` point. Each subfolder has its own `gen_chunks.py` (run from inside that folder), `manifest.json`, `build_vectors.mjs`, and `chunkNN.cash`.

# pq-hash on-chain verifier (CashVM, BCH 2026)

This folder holds the on-chain verifier for the pq-hash track: a SHA-256 DEEP-FRI STARK over Goldilocks (SPEC.md, zk-verifier-bench `wip/pq-hash-design` c3497a1). It consumes the prover's vectors (`../prover/vectors`, branch `wip/pq-hash-prover`) and builds the verifier in two layouts:
- **layout (b)**: one P2SH32 input under TXv5 or libauth bch-spec;
- **layout (a)**: today's standard rules, with inputs of at most 10,000 B and transactions of at most 100,000 B.

It also measures the verifier. The report and the harness cross-check live in zk-verifier-bench `wip/pq-hash-verifier`, `research/pq-hash/verifier/`. **This is research only, not a leaderboard entry.** It is not registered anywhere.

Zero-knowledge is out of scope: the proof has no masking. Soundness for the chosen parameters is in scope.

## Files

| file | what |
|---|---|
| `field.mjs`, `params.mjs` | Goldilocks and F_p[u]/(u^e − 7) reference arithmetic; the parameter set and the TAG, checked against the vector |
| `model.mjs` | reference model of the on-chain checks, and the witness encoders `encodeB` (layout b) and `encodeA` (layout a). Hints come from the proof's own canonical multiproof |
| `lib/asm.mjs`, `lib/slp.mjs` | assembler with a symbolic stack, and a straight-line program compiler with function calls. Extended from the pq-hash kernels |
| `gen.mjs` | code generator: shared OP_DEFINE functions and the emitters (transcript, AIR, constants, final-polynomial unpack, one query), plus `buildB` (layout b) |
| `gen-a.mjs` | layout (a): shared redeem, code read from input 1, graph pin, HEAD/CODE/QRY roles, NFT thread for two transactions |
| `layout-b.mjs`, `layout-a.mjs` | spends and transactions for the two layouts |
| `vm.mjs` | libauth 3.1.0-next.8 VMs, mirroring zk-verifier-bench `src/harness/vm.ts`: BCH 2026 real and loosened, bch-spec, TXv5 as written |
| `grade-b.mjs`, `grade-a.mjs` | grading. Writes `results/layout-b.json` and `results/layout-a.json` |
| `test-model.mjs`, `test-fns.mjs`, `test-b.mjs`, `test-a.mjs` | model vs vectors; unit tests of the shared functions; accept/reject sweeps (`results/test-*.log`) |
| `profile-b.mjs` | per-phase op-cost of layout (b) (`results/profile-b.json`) |

## Running

```
node test-model.mjs ../prover/vectors/*.json      # model: 14 accepted, 100 tamper cases rejected
node test-fns.mjs                                 # shared functions against JS references
node grade-b.mjs ../prover/vectors/*-[0-3].json   # layout (b): bch-spec and TXv5-as-written grades
node grade-a.mjs ../prover/vectors/*-[0-3].json   # layout (a): real BCH 2026 VM, standard and consensus
node test-b.mjs ../prover/vectors/*-[0-3].json; node test-a.mjs ../prover/vectors/P128-0.json ../prover/vectors/P128-1.json
```

## Design notes (soundness-relevant)

- **Statement.** It is baked into the redeem. The P2SH32 locking commits to (x_in, y_out), and t0 is a constant.
- **Merkle (layout b).** Each tree is checked by a LIFO multiproof in sorted leaf order. The witness supplies the processing order σ and an op stream: fresh runs, MERGE, DUPM, PARK, ROOT. The script checks the following:
  - σ is a permutation: Σ 2^σ = 2^s − 1 and every σ < 128.
  - Every node carries its heap index k. MERGE requires pk + k = 4·(k >> 1) + 1, which makes pk the sibling of k. DUPM requires equal index and equal digest. ROOT requires k = 1 and the committed root.
  - Parked nodes live on the altstack above a non-numeric marker, which is checked at the end of each tree.
  - Every record is consumed exactly. Op bytes are range-checked before OP_INVOKE.

  Every leaf's chain of hashes therefore ends in the committed root at its true position. The hints change only the cost, never the verdict.
- **DEEP inverses.** One Montgomery batch per query (8 norms and x0) with a hinted inverse T, checked by Π·T ≡ 1.
- **Folds.**
  - Folds are unscaled: the fold result is compared with a·(leaf value).
  - All comparisons are mod p. As in the reference verifier, leaf values are not range-checked.
- **Final polynomial.**
  - Coefficients are packed into three 136-bit slots and evaluated as dot products with y^0..y^31.
  - The 32-coefficient group sums are combined by Horner in y^32.
- **Layout (a).**
  - Every input re-derives the transcript from HEAD's PT. QRY inputs check HEAD's push headers before reading.
  - Every role pins its own layout (DEPTH, item sizes, zero pads).
  - The graph is pinned by the input count and by every input having the same locking bytecode.
  - P128 links two transactions with an NFT thread. A minting baton sits in tx0's input 0. tx0 mints an immutable NFT with commitment SHA256("pq-hash/thread" ‖ G ‖ 0x01). tx1 recomputes G, checks the commitment, and burns the token.

# Track 8 S4: layout (b) for M1 — one 100 KB input

Research only. This folder holds the CashVM (BCH 2026) verifier generator for Plonky3 `p3-batch-stark` proofs in
p3b-v1 (`../prover/FORMAT.md`), built for the M1 statement (Merkle membership at depth 30 plus a nullifier, AIR-SPEC
§3) under parameter set Z128 with Merkle cap 0 (DESIGN-T8 §5, layout b). Track 5 files are untouched; its generator
was copied here and adapted, and its generic model functions are imported read-only.

## What the generator does

- **Verifying key → script.** `model.mjs` `vkxFromVector` takes VK data only (via S3's `vkFromVector`, which
  re-derives the PCS layout, cap lengths and FRI schedule and requires them to equal the vector's `shape`). It also
  asserts the VK-time properties the per-proof check relies on: strict FRI height and the hiding budget. Supported:
  one table, one height, no preprocessed columns, no lookups, ood PoW 0, cap 0 (S5–S7 extend this).
- **Transcript.** As Track 5 (a chain of SHA-256 digests), with batch-stark's prefix: the batch domain-separator
  seed and degree_bits as an extension element are one constant, followed by the trace cap and the 12 public values.
- **Statement layer** (AIR-SPEC §3.1):
  - ROOT is a constant of the script (the pool's root; Track 9 would read it from covenant state).
  - NF is a witness item, 4 × u64 LE, each lane checked < p.
  - CTX is computed by the script from the spending transaction's outputs (`ctx.mjs`; serialization in
    `../prover/FORMAT.md` "CTX serialization"). The prover takes the hash as `m1@LEAF@WSEED@<hash>`.
- **AIR at ζ.** The exported constraint DAG (551 nodes, 53 constraints) runs in a small byte-code interpreter
  (`dagProgram` in `gen.mjs`): the DAG becomes a constant program of 2.1 KB, executed in 40-byte chunks by OP_INVOKE
  dispatch (op ids 100–113). Multi-use nodes are computed once into stack registers. Selectors are multiplied through
  by (ζ−1)(ζ−g⁻¹), so no inversion is needed. Periodic columns (11, period 32) use a 32-step loop with the
  coefficients packed at run time into 17-byte slots; the quotient is recomposed with prefix/suffix products.
- **DEEP, FRI, Merkle.** As Track 5: one hint per query, the packed dot products, the arity-8 fold, the group-packed
  final polynomial and the LIFO Merkle records. α′ powers, A_z and the packed row keys come from one loop over the
  94 opened values. Extension multiplication is a packed schoolbook product (17-byte slots).

## Files

| file | what |
|---|---|
| `model.mjs` | the on-chain algorithm in JS, and the witness encoder `encodeB` |
| `gen.mjs` | the generator (`build`, `makeGen`, `dagProgram`) |
| `ctx.mjs` | CTX: the script block and the JS serialization |
| `layout-b.mjs` | the program (VK + ROOT) and the spend (witness, unlocking, spending transaction) |
| `vm.mjs`, `lib/` | libauth 3.1.0-next.8 VMs: `bch` (today's rules), `r100` (one 100 KB input), `spec` (bch-spec), `loose` |
| `gen-statements.mjs` | transaction-bound statements: outputs → CTX → prover |
| `model-agree.mjs` | model vs `../verifier/verify-batch.mjs`, including transcript bytes |
| `grade-b.mjs`, `profile-b.mjs` | regimes, bytes and op-cost; per-phase profile against the S0 model |
| `test-b.mjs`, `test-ctx.mjs` | the accept/reject sweep; the CTX block against its definition |
| `gen-s4.sh` | everything, end to end |
| `results/` | outputs (see below) |

## Reproduce

```
CARGO_TARGET_DIR=<cache>/target S4_CACHE=<cache>/s4 S3_CACHE=<cache>/s3 ./gen-s4.sh
```

The S3 case files (`$S3_CACHE/cases`) come from `../verifier/gen-s3.sh`.

## Results

See PROGRESS.md (S4 entry) and `results/` for the numbers: `grade-b.json`, `profile-b.json`, `test-b.json`,
`test-b-harness.json`, `model-agree.txt`, `test-ctx.txt`.

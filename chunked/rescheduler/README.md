# Stack rescheduling for chunk redeems

The chunk builders compile through the cashc fork's `rescheduleStacks` pass
(`packages/cashc/src/stack-rescheduling.ts`): each straight-line block of the compiled
redeem is lifted to a dataflow DAG and re-emitted so operands are computed onto the top
of the stack instead of fetched from variable slots with `<depth> OP_PICK/OP_ROLL`
pairs, and each function's argument-arrival order is chosen jointly with its schedule.
Candidates are selected by the BCH2026 op-cost meter (bodies MEASURED on a loosened VM
and differentially tested; mains ranked statically with per-block
`min(cashc, rescheduled)`). On op-cost-bound chunks, 800 op-cost saved = 1 byte of
zero-padding removed from the unlocking.

**Rescheduling is ON by default** in `_millermath.mjs`'s `compileBytecode` /
`compileFileBytecode` — the committed vectors are built this way. `RESCHEDULE=off`
compiles plain for A/B. The `compile*Raw` exports always compile plain: the vector
builders use them to keep, per chunk, whichever redeem yields the smaller tuned
unlocking, and the chunk planners use them so the generated manifests stay independent
of the pass.

`opcost.mjs` is the original standalone implementation the compiler pass was ported
from and byte-for-byte validated against; `census.mjs` reports the surviving
PICK/ROLL-pair population over built vectors.

## Results (committed-proof runs, verifier benchmark)

| entry | before | after | Δ |
|---|---:|---:|---:|
| bch-groth16-grouped-residue | 257,810 | 241,628 | −6.3% |
| bch-groth16-intratx-residue | 257,696 | 241,518 | −6.3% |
| bch-groth16-grouped | 405,813 | 378,538 | −6.7% |
| bch-groth16-intratx | 405,542 | 378,323 | −6.7% |
| bch-groth16-chunked | 407,968 | 381,549 | −6.5% |
| bch-pairing-chunked | 228,811 | 217,562 | −4.9% |
| bch-pairing-intratx | 226,652 | 215,429 | −5.0% |
| bch-vkx-chunked-covenant | 17,695 | 13,950 | −21.2% |
| bch-groth16-singleton (size-scored) | 14,240 | 8,874 | −37.7% |

Flagship total op-cost 195,408,679 → 181,471,250 (−7.1%); the non-residue grouped
verifier packs into 5 standard transactions (was 6). All families: `allAccept=true`,
`allFit=true`, tampered runs rejected, on the committed proof, proof#1 and the
worst-case proof. The byte-objective singleton recompile is unaffected (8,385 B).

What remains is intrinsic arithmetic (~41% of op-cost) plus base instruction cost on
arithmetic ops — further gains live at the algorithm/protocol level, not in codegen.
Census-driven non-starters: seam/boundary solving (mains' whole surviving pair
population is ~2.1M one-shot ops) and re-chunking (padding is op-bound, so total
unlocking bytes are fixed by total op-cost regardless of packing; only ~0.3–0.5M op of
per-boundary seam overhead is real). Not yet ported: BLS12-381 families, the shamir
vk_x build (own compile path).

# Track 5 / Field cost: progress (wip/pq-stark-field only, never main)

Worktrees: groth16_cashscript -> work/pq-stark/field/g16 (generator copy: research/pq-stark/field/verifier),
zk-verifier-bench -> work/pq-stark/field/bench (kernels: research/pq-stark/field/kernels).

## Baseline (Track 4, P128-0, layout b)
op-cost 71.54M, redeem 5,945 B, unlocking 96,383 B. Per query: entry 55.5k, parse 68.8k, deep 454k, layers 347k, final 478k.
Query 0 opcode histogram: instructions are ~72% of op-cost; stack fetches (depth pushes + PICK/ROLL/OVER/SWAP/DUP) ~43%.

## Log
- gen.mjs copy gets mode switches (all-legacy {"fp":"grp","fold":"pair","deep":"pt"} reproduces Track 4 exactly: 71,541,117 / redeem 5,945 on P128-0).
- fp 'gpd' (group-packed final polynomial, H=8, G=32): q-final 478k -> 272k/query; unpack once 763k -> 1,083k. H=4: 291k, H=16: 309k.
- fold 'rot' (PAIRP, packed rotation columns of beta): q-layers 347k -> 273k, PAIRP 13.1k vs PAIR 15.5k.
- deep 'pk' (DPK, packed numerators from packed gamma columns): q-deep 438k -> 325k.
- P128-0 now 54.22M (from 71.54M), redeem 5,855 B (-90 B). fnprof.mjs gives per-function inclusive op-cost.
- fold 'pk' (packed fold values in 26-byte slots, PAIRK 9.5k/pair, FOLD8 87.7k vs 134k Track 4): P128-0 51.89M, redeem 5,688 B. test-b: 38/38 as expected. grade-a P100-0: pad 6,337 -> 780 B (71,024 B total); P128-0: QRY inputs 79.5% (was 92%), 151,915 B.
- xtab: x0 from runtime 4-bit window tables (5 x 16 values per proof): q-entry 55.5k -> 10.8k (P128).
- PKL expand rewritten generically (snapshot 65811a6): kernel 22.9k -> 22.0k per 192-byte leaf.
- Resume after session crash (2026-10-29): restored Track 4 pq-hash/verifier/results/profile-b.json that the crash snapshot had deleted; removed the scratch dis.tmp.mjs / q.tmp.mjs.
- Final re-measure at HEAD: P128-0 50,053,779 (-30.0%), per query 894k (entry 10.8k, parse 75.0k, deep 317.8k, layers 218.7k, final 271.7k), unpack 1,083k; P100-0 27,861,234 (-28.1%). test-fns all ok; test-b and test-a all as expected; layout (a) unchanged in inputs (P128 19/2 txs, P100 10/1 tx): QRY inputs are byte-bound at 3 queries.
- Not applied: witnessed inverses (C1: 29.1k -> 10.7k per query but +64 B per query; P128 would grow to ~99.1 KB tx and lose the margin under 100 KB, and in layout (a) it adds bytes to byte-bound inputs). Smaller final degree / higher arity: needs new prover parameters and moves the fold soundness term (P128 margin 0.31 bits): left to the soundness/prover tasks, kernel B4 gives the per-D costs.

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

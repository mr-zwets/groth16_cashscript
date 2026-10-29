# Track 5 / Field cost: progress (wip/pq-stark-field only, never main)

Worktrees: groth16_cashscript -> work/pq-stark/field/g16 (generator copy: research/pq-stark/field/verifier),
zk-verifier-bench -> work/pq-stark/field/bench (kernels: research/pq-stark/field/kernels).

## Baseline (Track 4, P128-0, layout b)
op-cost 71.54M, redeem 5,945 B, unlocking 96,383 B. Per query: entry 55.5k, parse 68.8k, deep 454k, layers 347k, final 478k.
Query 0 opcode histogram: instructions are ~72% of op-cost; stack fetches (depth pushes + PICK/ROLL/OVER/SWAP/DUP) ~43%.

## Log

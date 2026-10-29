# PROGRESS (branch only, never main)

- [x] worktree wip/plonk-kzg-verifier, node_modules symlink to the design worktree (bench pnpm install: libauth 3.1.0-next.8, noble 2.2.0)
- [x] math.mjs, plonk.mjs (value-level verifier, plan B with t', u = u1 + lambda u2), si.mjs (fixed-G2 SI prover)
- [x] script.mjs single input; asm fixes: roll() across a sized pile (symbolic index), mod-r kernel node, invokeBytes
- [x] accepted: mul2 + merkle16 on bch-spec (J=13) and TXv5 (J=8, minimal pad)
- [x] digit extraction by OP_RSHIFTNUM on s' = s + sum 16*32^i (no recoding loop): -3.9M op
- [x] full test suites single + chain: all pass
- [x] multi-input (today): 10-input chain accepted, both circuits
- [x] README, results/summary.json

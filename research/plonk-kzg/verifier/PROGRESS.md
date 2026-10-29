# PROGRESS (branch only, never main)

- [x] worktree wip/plonk-kzg-verifier, module dir, node_modules symlink to the design worktree (bench pnpm install)
- [x] math.mjs (fork of SI-GLS math: chains for any fixed G2 point, GLV, MSM offset), plonk.mjs (value-level verifier,
      plan B, u/t' substitution, MSM schedule and witness): 10/10 valid accepted, 154/154 tampered rejected
- [ ] si.mjs: SI pairing prover for Miller(P*, [1]_2) Miller(P_right, [x]_2)
- [ ] script.mjs: single-input program (bch-spec, 100 KB)
- [ ] multi-input chain (today)
- [ ] red team, sweep, profile, README, results/

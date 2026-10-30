# Track 7 / msm: chain MSM redesign + GT fold (worktree notes; not for main)

Baseline (main, mul2 proof 0): chain 92,295 B unlocking (10 inputs); single bch-spec 66,451 B (J=13).

- [x] function-level profiler (fprof.mjs, chainprof.mjs): LOADT 1.055M per MSM input, TV check 4.1M, window-loop overhead ~6.8k per (window, base).
- [x] LOADT: balanced SPLIT tree, no 0x00 sign byte for host-checked words: 1.055M -> 0.649M per MSM input. Chain 92,295 -> 89,259 B.
- [x] measured: single bch-spec without the 8 fixed bases in G1 (invalid build, cost only): 46.9 KB at J~26 (-19.5 KB).
- [x] GT fold (gt.mjs), 2-event chunks kept (33 states), NQ cap 348 (mul2) / 384 (merkle16); honest n_q 225-267.
      single bch-spec mul2: 58,554 B at J=27 (margin 0.2%, needs J sweep).
- [ ] chain with fold (variable WQ, GT tables per SI role, acc hand-over)
- [ ] role planner, tests, SOUNDNESS.md

# bn-native-v2a-proto (design-1 measurement prototype; NOT a bench entry)

Copy of `../bn-native-sound` with the angle-A changes of `work/native-bn/DESIGN-1.md` (verifier.cash):
single code host in input 0 (R 50 B), prefix-first remote reads, 5-word handover (x_T, y_T, R) with the cut state
hosted in the receiving input (F+- re-derived there), CUTS env (default 0,24,48,65; design value 0,26,48,65),
uneven delta pile pieces. Optional `D01=1` = rejected item B1 (DG = d01 || d2).

    CUTS=0,26,48,65 MARGIN=0.06 node measure.mjs     # build, accept (both modes), per-input op/unlocking, rejection checks
    VERIFIER_DIR=<zk-verifier-bench> CUTS=0,26,48,65 node caprule.mjs   # cap rule on fixtures + forced cases
    CUTS=0,26,48,65 node trace.mjs                    # op by section

build.mjs / export.mjs / redteam.mjs / sweep.mjs are the unmodified originals and do not run against this layout.

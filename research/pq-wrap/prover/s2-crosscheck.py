#!/usr/bin/env python3
"""Track 8 S2: cross-check the Rust statement traces (src/stmt.rs) against AIR-SPEC's executable companion
air8_ref.py (bench branch wip/stark-usable-design, research/pq-stark/design-t8/).

For every trace-<leaf>.json written by `pq-stark-batch-prover s2 selftest --dump DIR`, rebuild the M1 trace and
the M2 traces (T_hash, T_ctl) from the same witness with air8_ref.py and require them to be identical cell by
cell, together with NF/ROOT (public values) and air8_ref's own constraint check on the Rust trace.

    python3 s2-crosscheck.py <design-t8 dir> <dump dir>
"""
import glob
import json
import os
import sys

ref_dir, dump = sys.argv[1], sys.argv[2]
sys.path.insert(0, ref_dir)
import air8_ref as A  # noqa: E402

ok_all = True
files = sorted(glob.glob(os.path.join(dump, 'trace-*.json')))
assert files, 'no dumps'
for f in files:
    d = json.load(open(f))
    I = lambda xs: [int(x) for x in xs]  # noqa: E731
    nk, r, ctx = I(d['nk']), I(d['r']), I(d['ctx'])
    bits = [int(b) for b in d['bits']]
    sibs = [I(s) for s in d['sibs']]
    NF, ROOT = A.m1_native(nk, r, bits, sibs)
    pub = ROOT + NF + ctx
    pv_ok = I(d['public_values']) == pub
    m1 = A.m1_trace(nk, r, bits, sibs)
    m1_flat = [x for row in m1 for x in row]
    m1_ok = I(d['m1']) == m1_flat
    m1_viol = len(A.check_rows([I(d['m1'][i * 17:(i + 1) * 17]) for i in range(1024)], A.m1_constraints(pub)))
    th, th_pre, tc, tc_pre = A.m2_traces(nk, r, bits, sibs)
    th_ok = I(d['t_hash']) == [x for row in th for x in row]
    tc_ok = I(d['t_ctl']) == [x for row in tc for x in row]
    ok = pv_ok and m1_ok and m1_viol == 0 and th_ok and tc_ok
    ok_all &= ok
    print(f"{os.path.basename(f)}: public values {pv_ok}; M1 trace identical {m1_ok} ({len(m1_flat)} cells), "
          f"air8_ref violations on the Rust trace {m1_viol}; T_hash identical {th_ok}; T_ctl identical {tc_ok} -> "
          f"{'PASS' if ok else 'FAIL'}")
print('ALL:', 'PASS' if ok_all else 'FAIL')
sys.exit(0 if ok_all else 1)

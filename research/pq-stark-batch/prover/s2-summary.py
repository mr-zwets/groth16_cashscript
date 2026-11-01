#!/usr/bin/env python3
"""Track 8 S2 summary: proof sizes against S0's expected values (bytes8.py, AIR-SPEC sec. 3.5 / 4.3), ZK seed
freshness, prover time and peak RSS, and the acceptance verdicts of the S2 reports. Prints JSON.

    python3 s2-summary.py <vectors/S2> <cache>
"""
import glob
import json
import os
import statistics
import sys

V, CACHE = sys.argv[1], sys.argv[2]
R = os.path.join(V, 'report')
# S0 expected values (bytes8.py; AIR-SPEC sec. 3.5 and 4.3)
EXPECTED = {'Z128': 73434, 'Z128_cap5': 75967, 'Z128g_cpow3_lpow8': 122993}
TOL = 0.03

out = {'expected_bytes_S0': EXPECTED, 'tolerance': TOL, 'vectors': [], 'batches': {}, 'bench': {}}
ok_sizes = True          # every single proof within +-3%
outside = []
all_devs = {}            # per parameter set, every proof
fresh_ok = True
for f in sorted(glob.glob(os.path.join(V, '*.json'))):
    v = json.load(open(f))
    tag = os.path.basename(f).rsplit('-', 1)[1][:-5]
    b = v['sizes']['total']
    dev = b / EXPECTED[tag] - 1
    ok_sizes &= abs(dev) <= TOL
    all_devs.setdefault(tag, []).append(dev)
    if abs(dev) > TOL:
        outside.append({'file': os.path.basename(f), 'bytes': b, 'dev': round(dev, 4)})
    s2 = os.path.join(CACHE, 'bench', os.path.basename(f)[:-5] + '-seed2.json')
    differ = None
    if os.path.exists(s2):
        w = json.load(open(s2))
        differ = w['proof_hex'] != v['proof_hex'] and w['public_values'] == v['public_values']
        fresh_ok &= differ and w['rust_verify'] == 'accepted'
    out['vectors'].append({'file': os.path.basename(f), 'case': v['case'], 'set': v['set']['name'], 'bytes': b,
                           'dev_vs_S0': round(dev, 4), 'rust_verify': v['rust_verify'],
                           'tamper_cases': v['tamper_sweep']['cases'],
                           'tamper_unexpected': len(v['tamper_sweep']['unexpected_accepts']),
                           'seed2_bytes_differ': differ, 'prove_ms': v['prove_ms'],
                           'log_arities': v['shape']['log_arities'],
                           'num_chunks': [i['num_chunks'] for i in v['shape']['instances']],
                           'constraints': [len(d['constraints']) for d in v['dag']]})
for f in sorted(glob.glob(os.path.join(R, 'batch-*.json'))):
    s = json.load(open(f))
    tag = os.path.basename(f)[len('batch-m1-'):-5]
    exp = EXPECTED[tag]
    devs = [c['bytes'] / exp - 1 for c in s['cases']]
    ok_sizes &= all(abs(d) <= TOL for d in devs)
    all_devs.setdefault(tag, []).extend(devs)
    outside += [{'case': c['case'], 'bytes': c['bytes'], 'dev': round(c['bytes'] / exp - 1, 4)} for c in s['cases'] if abs(c['bytes'] / exp - 1) > TOL]
    out['batches'][os.path.basename(f)] = {'count': s['count'], 'all_ok': s['all_ok'], 'mean_bytes': round(s['bytes']['mean']),
                                           'sd_bytes': round(s['bytes']['sd']), 'min': s['bytes']['min'], 'max': s['bytes']['max'],
                                           'mean_dev_vs_S0': round(statistics.mean(devs), 4),
                                           'max_abs_dev_vs_S0': round(max(abs(d) for d in devs), 4),
                                           'prove_ms_median': s['prove_ms']['median']}
for f in sorted(glob.glob(os.path.join(CACHE, 'bench', '*-t[0-9]-[0-9].json'))):
    v = json.load(open(f))
    key = os.path.basename(f).rsplit('-', 1)[0]
    e = out['bench'].setdefault(key, {'prove_ms': [], 'peak_rss_mb': [], 'rust_verify_ms': []})
    e['prove_ms'].append(v['prove_ms'])
    e['peak_rss_mb'].append(round(v['peak_rss_kb_after_prove'] / 1024, 1))
    e['rust_verify_ms'].append(v['rust_verify_ms'])
for e in out['bench'].values():
    e['prove_ms_median'] = statistics.median(e['prove_ms'])
    e['peak_rss_mb_max'] = max(e['peak_rss_mb'])

rep = lambda n: json.load(open(os.path.join(R, n)))  # noqa: E731
st, mu, fo, pv = rep('selftest.json'), rep('mutate.json'), rep('forced.json'), rep('pvs.json')
check_line = open(os.path.join(R, 'rust-check.txt')).read().strip().splitlines()
out['acceptance'] = {
    'poseidon2_differential_vs_p3_goldilocks': st['poseidon2']['test_vector_and_differential'],
    'check_constraints_honest_traces (leaf 0, 2^30-1, random; M1 and M2)': all(r['pass'] for r in st['honest']),
    'single_cell_mutation_all_caught': mu['all_caught'],
    'mutation_counts': {k: f"{mu[k]['cells'] - mu[k]['missed']}/{mu[k]['cells']}" for k in ('m1', 't_hash', 't_ctl')},
    'forced_unsatisfying_rejected_by_verify_batch': fo['all_rejected'] and fo['controls_accepted'],
    'wrong_public_values_and_other_vks_rejected': pv['all_as_expected'],
    # AIR-SPEC sec. 6 item 5: S0's sizes are expected values; one proof varies by about +-2-3% (query-set luck)
    'size_mean_per_set_within_3pct_of_S0': all(abs(statistics.mean(d)) <= TOL for d in all_devs.values()),
    'size_mean_dev_per_set': {k: {'proofs': len(d), 'mean_dev': round(statistics.mean(d), 4),
                                  'min_dev': round(min(d), 4), 'max_dev': round(max(d), 4)} for k, d in all_devs.items()},
    'size_every_single_proof_within_3pct_of_S0': ok_sizes,
    'size_proofs_outside_3pct': outside,
    'zk_second_seed_differs': fresh_ok,
    'tamper_sweeps_zero_unexpected': all(x['tamper_unexpected'] == 0 for x in out['vectors']),
    'all_vectors_verify': all(x['rust_verify'] == 'accepted' for x in out['vectors']),
    'rust_check': [l for l in check_line if 'FAIL' in l][:5] or 'no FAIL lines',
}
print(json.dumps(out, indent=1))

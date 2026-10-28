#!/usr/bin/env python3
"""Generate test vectors for every parameter set: valid proofs and tampered proofs, plus measured sizes.

Writes vectors/<SET>-<k>.json (one per statement) and vectors/summary.json.
Usage:  python3 gen_vectors.py                 # all sets, default statement counts
        python3 gen_vectors.py P100 P128       # some sets
Requires numpy (prover only); the checks use the pure-Python reference verifier.
"""
import json
import os
import random
import statistics
import sys
import time

from pqparams import SETS, fri_shape, describe, expected_proof_bytes
from pqproto import layout, leaf_offset
from prover import prove, statement_input
from verifier import verify, apply_tamper

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, 'vectors')
STATEMENTS = dict(P100=4, P128=4, U100=2, C100=2, C128=2)


def tampers(p, res, honest_derived, tweak_proof):
    """Plain tampering only: each case must be rejected by the reference verifier."""
    proof = res['proof']
    off, pt_len, leaf_total, trees = layout(p)
    N, arities, sizes, _ = fri_shape(p)
    r = len(arities)
    sib0 = off['siblings'][0]
    out = []

    def add(name, desc, expect, **kw):
        out.append(dict(name=name, description=desc, expect='reject', expect_reason_prefix=expect, **kw))

    def x(o, b='01'):
        return [dict(offset=o, xor=b)]

    add('sibling_trace_first', 'flip bit 0 of the first multiproof sibling of the trace tree',
        'merkle: root mismatch in trace', patches=x(sib0))
    last_tree = trees[-1]['name']
    add(f'sibling_{last_tree}_last', f'flip bit 0 of the last multiproof sibling ({last_tree} tree)',
        f'merkle: root mismatch in {last_tree}', patches=x(len(proof) - p.h))
    add('opened_trace_value', 'flip bit 0 of X at coset point 0 in query 0\'s trace leaf',
        'merkle:', patches=x(leaf_offset(p, 0, 0)))
    add('opened_comp_value', 'flip bit 0 of H0.c0 at coset point 1 in query 0\'s composition leaf',
        'merkle:', patches=x(leaf_offset(p, 0, 1) + 2 * 8 * p.e))
    add('opened_fri1_value', 'flip bit 0 of the last value in the last query\'s fri1 leaf',
        'merkle:', patches=x(leaf_offset(p, p.s - 1, 2) + trees[2]['leaf'] - 8 * p.e))
    fo = off['final'][0]
    add('final_coeff_flip', 'flip bit 0 of final-polynomial coefficient 0 (transcript changes, nonce no longer grinds)',
        'grinding', patches=x(fo))
    add('final_coeff_last_flip', 'flip bit 0 of the top final-polynomial coefficient c2/c1 byte',
        'grinding', patches=x(fo + off['final'][1] - 1, '80'))
    add('final_coeff_reground', 'final coefficient 0 plus 1, then honestly re-ground and re-opened '
        '(only defect: final layer); full proof given', 'fri: final polynomial', proof_hex=tweak_proof.hex())
    add('public_input_x_in', 'flip bit 0 of x_in in the proof (challenges change)', 'air', patches=x(off['x_in'][0]))
    add('public_input_y_out', 'flip bit 0 of y_out in the proof (challenges change)', 'air', patches=x(off['y_out'][0]))
    add('public_input_noncanonical', 'x_in bytes set to 0xff..ff (>= p)', 'statement: non-canonical',
        patches=[dict(offset=off['x_in'][0], bytes='ff' * 8)])
    add('statement_mismatch', 'honest proof, verifier expects y_out + 1', 'statement: proof is for a different',
        patches=[], want_statement=[str(res['x_in']), str((res['y_out'] + 1) % (2**64 - 2**32 + 1))])
    add('root_trace_flip', 'flip bit 0 of root_trace', 'air', patches=x(off['root_trace'][0]))
    add('root_fri1_flip', 'flip bit 0 of root_fri1 (beta_2.. and G change)', 'grinding', patches=x(off['root_fri1'][0]))
    add('ood_flip', 'flip bit 0 of the OOD value X(z).c0', 'air', patches=x(off['ood'][0]))
    add('ood_H1_flip', 'flip bit 0 of the OOD value H1(z).c0', 'air', patches=x(off['ood'][0] + 4 * 8 * p.e))
    add('nonce_flip', 'flip bit 0 of the grinding nonce', 'grinding', patches=x(off['nonce'][0]))
    add('truncated', 'drop the last byte', 'parse', truncate=len(proof) - 1)
    add('trailing_byte', 'append one zero byte', 'parse: trailing', append='00')
    add('leaves_only_truncated', 'cut inside the leaves block', 'parse', truncate=pt_len + leaf_total)
    return out


def size_distribution(p, samples=20000, seed=1):
    """Monte Carlo distribution of canonical proof bytes over uniform query indices."""
    N, arities, sizes, trees = fri_shape(p)
    rng = random.Random(seed)
    off, pt_len, leaf_total, _ = layout(p)
    vals = []
    for _ in range(samples):
        idx = [rng.randrange(sizes[1]) for _ in range(p.s)]
        pos = [idx]
        for i in range(len(arities)):
            pos.append([v % sizes[i + 1] for v in pos[-1]])
        tot = 0
        for ti, t in enumerate(trees):
            cur = set(pos[(0 if ti < 2 else ti - 1) + 1])
            for _l in range(t['depth']):
                tot += sum(1 for k in cur if (k ^ 1) not in cur)
                cur = {k >> 1 for k in cur}
        vals.append(pt_len + p.s * leaf_total + tot * p.h)
    vals.sort()
    q = lambda f: vals[int(f * (len(vals) - 1))]
    return dict(samples=samples, mean=round(statistics.mean(vals), 1), stdev=round(statistics.pstdev(vals), 1),
                min=vals[0], p01=q(0.01), p50=q(0.5), p99=q(0.99), max=vals[-1])


def main(names):
    os.makedirs(OUT, exist_ok=True)
    summ_path = os.path.join(OUT, 'summary.json')
    summary = json.load(open(summ_path)) if os.path.exists(summ_path) else {}
    for name in names:
        p = SETS[name]
        print(f'== {name}: {p.label}')
        rows = []
        tweak = None
        for k in range(STATEMENTS[name]):
            x_in = statement_input(k)
            t0 = time.time()
            res = prove(p, x_in, log=lambda *a: None)
            secs = round(time.time() - t0, 1)
            proof = res['proof']
            ok, why, der = verify(p, proof, (res['x_in'], res['y_out']), derive=True)
            assert ok, f'{name}-{k}: honest proof rejected: {why}'
            print(f'   statement {k}: {len(proof)} B, prover {secs} s, nonce {res["nonce"]}: ACCEPT')
            rec = dict(format='pq-hash/vector/v1', params=describe(p),
                       statement=dict(x_in=str(res['x_in']), y_out=str(res['y_out']), k=k),
                       proof=proof.hex(), proof_bytes=len(proof), sections=res['sections'], nonce=res['nonce'],
                       prover_seconds=secs, prover_timings=res['timings'], derived=der,
                       openings=res['queries'], multiproof=res['multiproof'])
            if k == 0:
                t0 = time.time()
                tweak = prove(p, x_in, log=lambda *a: None, final_tweak=True)['proof']
                cases = tampers(p, res, der, tweak)
                for c in cases:
                    want = tuple(int(v) for v in c['want_statement']) if 'want_statement' in c else None
                    ok2, why2, _ = verify(p, apply_tamper(proof, c), want)
                    c['observed_reason'] = why2
                    assert not ok2 and why2.startswith(c['expect_reason_prefix']), (c['name'], ok2, why2)
                    print(f'     tamper {c["name"]:<28} REJECT: {why2}')
                rec['tampered'] = cases
            with open(os.path.join(OUT, f'{name}-{k}.json'), 'w') as fh:
                json.dump(rec, fh, indent=1)
            rows.append(dict(k=k, proof_bytes=len(proof), sections=res['sections'], nonce=res['nonce'],
                             prover_seconds=secs, duplicate_indices=p.s - len(set(der['indices']))))
        dist = size_distribution(p)
        sizes_ = [r_['proof_bytes'] for r_ in rows]
        summary[name] = dict(params=describe(p), expected_design=expected_proof_bytes(p),
                             measured=rows, measured_mean=round(statistics.mean(sizes_), 1),
                             measured_min=min(sizes_), measured_max=max(sizes_), monte_carlo=dist,
                             tamper_cases=len(cases))
        print(f'   measured {sizes_}; design expectation {expected_proof_bytes(p)["total"]}; MC {dist}')
        with open(summ_path, 'w') as fh:
            json.dump(summary, fh, indent=1)


if __name__ == '__main__':
    main(sys.argv[1:] or list(SETS))

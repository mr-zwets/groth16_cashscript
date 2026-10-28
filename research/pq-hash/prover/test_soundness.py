#!/usr/bin/env python3
"""Unit tests: FRI soundness parameter computation matches the design, and the protocol constants are sane.

Run:  python3 -m unittest test_soundness -v        (standard library only)
Optional cross-check against the design calculator itself: set PQ_DESIGN_PARAMS to its params.py, or
keep the default worktree layout (work/pq-hash/design/research/pq-hash/params.py).
"""
import importlib.util
import json
import math
import os
import unittest
from dataclasses import replace
from fractions import Fraction

from pqfield import P, Ext, root_of_unity, self_check
from pqparams import (SETS, fri_shape, soundness, min_queries, expected_proof_bytes, pt_size, periodic_poly,
                      round_constants, tag)
from pqproto import digest_to_ext, grinding_ok, layout, multiproof_root, node_hash, leaf_hash

HERE = os.path.dirname(os.path.abspath(__file__))

# Design calculator output (zk-verifier-bench wip/pq-hash-design c3497a1, params-output.json)
DESIGN = {
    'P100': dict(s=22, rounds={'ali': 184.69, 'deep': 157.37, 'batch+folds': 123.85, 'query': 100.11},
                 lam_iop=100.11, lam=100, limited_by='digest', bytes=50022, arities=[4, 8, 8],
                 trees=[('trace', 21, 64), ('comp', 21, 192), ('fri1', 18, 192), ('fri2', 15, 192)]),
    'P128': dict(s=43, rounds={'ali': 185.33, 'deep': 160.59, 'batch+folds': 128.31, 'query': 128.19},
                 lam_iop=128.19, lam=128, limited_by='digest', bytes=91468, arities=[4, 8, 8],
                 trees=[('trace', 19, 64), ('comp', 19, 192), ('fri1', 16, 192), ('fri2', 13, 192)]),
    'U100': dict(s=79, rounds={'ali': 126.42, 'deep': 106.87, 'batch': 108.0, 'fold1': 108.42, 'fold2': 110.19,
                               'fold3': 113.19, 'query': 100.09},
                 lam_iop=100.09, lam=100, limited_by='digest', bytes=107423, arities=[4, 8, 8],
                 trees=[('trace', 18, 64), ('comp', 18, 128), ('fri1', 15, 128), ('fri2', 12, 128)]),
    'C100': dict(s=11, rounds={'ali': 126.0, 'deep': 103.98, 'batch+folds': 100.0, 'query': 105},
                 lam_iop=100.0, lam=100.0, limited_by='batch+folds', bytes=23940, arities=[8, 16, 8],
                 trees=[('trace', 20, 128), ('comp', 20, 256), ('fri1', 16, 256), ('fri2', 13, 128)]),
    'C128': dict(s=15, rounds={'ali': 190.0, 'deep': 167.98, 'batch+folds': 164.19, 'query': 133},
                 lam_iop=133, lam=128, limited_by='digest', bytes=41748, arities=[4, 16, 8],
                 trees=[('trace', 21, 64), ('comp', 21, 192), ('fri1', 17, 384), ('fri2', 14, 192)]),
}


class FriSoundness(unittest.TestCase):
    def test_shape_matches_design(self):
        for name, d in DESIGN.items():
            N, arities, sizes, trees = fri_shape(SETS[name])
            self.assertEqual(arities, d['arities'], name)
            self.assertEqual([(t['name'], t['depth'], t['leaf']) for t in trees], d['trees'], name)
            # final layer: n / prod(arities) = 2^log_df coefficients
            self.assertEqual(2 ** SETS[name].log_n // math.prod(arities), 2 ** SETS[name].log_df, name)

    def test_rounds_match_design(self):
        for name, d in DESIGN.items():
            s = soundness(SETS[name])
            self.assertEqual(s['rounds'], d['rounds'], name)
            self.assertEqual(s['lam_iop'], d['lam_iop'], name)
            self.assertEqual(s['lam'], d['lam'], name)
            self.assertEqual(s['limited_by'], d['limited_by'], name)

    def test_query_count_is_minimal(self):
        for name, d in DESIGN.items():
            p = SETS[name]
            self.assertEqual(p.s, d['s'], name)
            self.assertEqual(min_queries(p, p.target), p.s, name)
            self.assertGreaterEqual(soundness(p)['lam_iop'], p.target, name)
            self.assertLess(soundness(replace(p, s=p.s - 1))['lam_iop'], p.target, name)
            self.assertGreaterEqual(4 * p.h, p.target, f'{name}: digest collision level 4h below target')

    def test_johnson_commit_error_exact(self):
        """BCIKS20 Thm 8.3 commit error and query error recomputed independently from the closed form, with
        rho = 2^-R written as powers of two (rho^(-3/2) = 2^(3R/2), rho^(-1/2) = 2^(R/2))."""
        for name in ('P100', 'P128'):
            p = SETS[name]
            N, arities, sizes, _ = fri_shape(p)
            m = Fraction(2 * p.m + 1, 2)
            R = p.log_blowup
            # term1 = (m+1/2)^7 N^2 / (2 rho^{3/2}) = (m+1/2)^7 N^2 2^{3R/2} / 2
            # term2 = (2m+1)(N+1)/sqrt(rho) * sum(a) = (2m+1)(N+1) 2^{R/2} sum(a)
            t1 = m ** 7 * N ** 2 / 2
            t2 = (2 * p.m + 1) * (N + 1) * sum(arities)
            log_eps = math.log2(float(t1) * 2 ** (1.5 * R) + float(t2) * 2 ** (0.5 * R))
            bits = p.e * math.log2(P) - log_eps
            self.assertAlmostEqual(bits, soundness(p)['rounds']['batch+folds'], places=2)
            # query round: s * -log2(sqrt(rho) (1 + 1/2m)) + g
            qbits = p.s * (R / 2 - math.log2(1 + Fraction(1, 2 * p.m))) + p.g
            self.assertAlmostEqual(qbits, soundness(p)['rounds']['query'], places=2)
        self.assertGreater(soundness(SETS['P128'])['rounds']['batch+folds'], 128.0)   # thin margin, SPEC 4.2

    def test_p128_needs_m4(self):
        """SPEC 4.2: with m = 3, P128 would need s = 44."""
        self.assertEqual(min_queries(replace(SETS['P128'], m=3), 128), 44)

    def test_design_expected_bytes(self):
        for name, d in DESIGN.items():
            self.assertEqual(expected_proof_bytes(SETS[name])['total'], d['bytes'], name)

    def test_against_design_calculator(self):
        path = os.environ.get('PQ_DESIGN_PARAMS') or os.path.normpath(
            os.path.join(HERE, '../../../../design/research/pq-hash/params.py'))
        if not os.path.exists(path):
            self.skipTest(f'design calculator not found at {path}')
        spec = importlib.util.spec_from_file_location('design_params', path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        for name in DESIGN:
            p = SETS[name]
            dp = mod.Params(name, p.regime, p.e, p.log_n, p.log_blowup, p.k0, p.k, p.log_df, p.s, p.g, 0, p.m, p.h)
            self.assertEqual(mod.soundness(dp), soundness(p), name)
            self.assertEqual(mod.proof_bytes(dp)['total'], expected_proof_bytes(p)['total'], name)
            self.assertEqual(mod.min_queries(dp, p.target).s, p.s, name)


class Constants(unittest.TestCase):
    def test_field_facts(self):
        self.assertTrue(self_check())

    def test_periodic_poly(self):
        C, Pc = round_constants(), periodic_poly()
        w8 = root_of_unity(8)
        for j in range(8):
            self.assertEqual(sum(Pc[k] * pow(w8, j * k, P) for k in range(8)) % P, C[j])

    def test_roots_nested(self):
        self.assertEqual(pow(root_of_unity(2 ** 23), 2 ** 7, P), root_of_unity(2 ** 16))

    def test_layout_sizes(self):
        for name, p in SETS.items():
            off, pt, leaf_total, trees = layout(p)
            self.assertEqual(pt, pt_size(p))
            self.assertEqual(len(tag(p)), 24 + 1 + 32)

    def test_digest_map_and_grinding(self):
        d = bytes(range(32))
        v = int.from_bytes(d, 'little')
        self.assertEqual(digest_to_ext(d, 3), (v % P, v // P % P, v // P ** 2 % P))
        self.assertTrue(grinding_ok(bytes([0, 0, 0, 0x0f]) + bytes(28), 28))
        self.assertFalse(grinding_ok(bytes([0, 0, 0, 0x10]) + bytes(28), 28))
        self.assertFalse(grinding_ok(bytes([0, 0, 1, 0]) + bytes(28), 28))

    def test_multiproof_small(self):
        h, depth = 25, 3
        leaves = [leaf_hash(1, bytes([i]), h) for i in range(8)]
        lvl = leaves
        levels = [lvl]
        while len(lvl) > 1:
            lvl = [node_hash(lvl[2 * i], lvl[2 * i + 1], h) for i in range(len(lvl) // 2)]
            levels.append(lvl)
        # positions 1, 2, 2 (duplicate): siblings in canonical order: level0 [0, 3], level1 [], level2 [node(2,1)]
        sib = iter([levels[0][0], levels[0][3], levels[2][1]])
        root = multiproof_root([1, 2, 2], [leaves[1], leaves[2], leaves[2]], depth, h, lambda: next(sib))
        self.assertEqual(root, levels[3][0])
        with self.assertRaises(ValueError):
            multiproof_root([2, 2], [leaves[2], leaves[3]], depth, h, lambda: b'')


class MeasuredSizes(unittest.TestCase):
    def test_measured_against_design(self):
        path = os.path.join(HERE, 'vectors', 'summary.json')
        if not os.path.exists(path):
            self.skipTest('vectors/summary.json not generated yet')
        with open(path) as fh:
            summ = json.load(fh)
        for name, row in summ.items():
            exp = DESIGN[name]['bytes']
            mc = row['monte_carlo']
            self.assertLess(abs(mc['mean'] - exp) / exp, 0.005, name)       # MC mean = design expectation
            for m in row['measured']:
                self.assertLessEqual(mc['min'], m['proof_bytes'], name)
                self.assertLessEqual(m['proof_bytes'], mc['max'], name)


if __name__ == '__main__':
    unittest.main()

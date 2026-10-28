#!/usr/bin/env python3
"""End-to-end round trip at small sizes (needs numpy): prove, verify, reject plain tampering.

Covers e = 2 and e = 3, arities 4/8/16 and 2- and 3-fold schedules. Run: python3 -m unittest test_roundtrip -v
"""
import unittest

from pqparams import Params, fri_shape
from pqproto import layout, leaf_offset
from prover import prove, statement_input
from verifier import verify


class RoundTrip(unittest.TestCase):
    def run_case(self, p):
        res = prove(p, statement_input(7), log=lambda *a: None, workers=2)
        proof = res['proof']
        ok, why, _ = verify(p, proof, (res['x_in'], res['y_out']))
        self.assertTrue(ok, why)
        off, pt, lt, trees = layout(p)

        def flip(o):
            b = bytearray(proof)
            b[o] ^= 1
            return verify(p, bytes(b))

        self.assertTrue(flip(off['siblings'][0])[1].startswith('merkle'))
        self.assertTrue(flip(leaf_offset(p, 0, 0))[1].startswith('merkle'))
        self.assertTrue(flip(leaf_offset(p, p.s - 1, len(trees) - 1))[1].startswith('merkle'))
        self.assertTrue(flip(off['final'][0])[1].startswith('grinding'))
        self.assertTrue(flip(off['x_in'][0])[1].startswith('air'))
        self.assertTrue(flip(off['ood'][0])[1].startswith('air'))
        tw = prove(p, statement_input(7), log=lambda *a: None, workers=2, final_tweak=True)['proof']
        self.assertTrue(verify(p, tw)[1].startswith('fri: final'))

    def test_e3_4_8(self):
        self.run_case(Params('T1', 9, 'JB', 3, 8, 3, 4, 8, 4, 6, 8, 3, 25, 0))

    def test_e3_4_8_three_folds(self):
        p = Params('T2', 9, 'JB', 3, 10, 2, 4, 8, 2, 8, 8, 3, 32, 0)
        self.assertEqual(len(fri_shape(p)[1]), 3)
        self.run_case(p)

    def test_e2_8_16(self):
        self.run_case(Params('T3', 9, 'CONJ', 2, 9, 4, 8, 16, 2, 5, 8, 3, 25, 0))


if __name__ == '__main__':
    unittest.main()

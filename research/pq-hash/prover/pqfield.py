"""Goldilocks field and its extensions F_p[u]/(u^e - 7), e in {2, 3}. Pure Python, scalar.

Shared by the reference verifier (verifier.py) and the scalar parts of the prover.
An extension element is a tuple of e base coefficients (c0, c1[, c2]) meaning c0 + c1*u [+ c2*u^2].
"""

P = 2**64 - 2**32 + 1     # Goldilocks
GEN = 7                   # generator of F_p^*; 7 is a non-square and a non-cube mod p
W = 7                     # extension modulus u^e = W
TWO_ADICITY = 32


def inv(a):
    a %= P
    if a == 0:
        raise ZeroDivisionError('inverse of 0 in F_p')
    return pow(a, P - 2, P)


def root_of_unity(order):
    """omega of exact order `order` (a power of two <= 2^32): GEN^((p-1)/order)."""
    assert order & (order - 1) == 0 and (P - 1) % order == 0
    return pow(GEN, (P - 1) // order, P)


class Ext:
    """Arithmetic in F_{p^e} = F_p[u]/(u^e - 7)."""

    def __init__(self, e):
        assert e in (2, 3)
        self.e = e
        self.zero = (0,) * e
        self.one = (1,) + (0,) * (e - 1)

    def lift(self, a):
        return (a % P,) + (0,) * (self.e - 1)

    def add(self, a, b):
        return tuple((x + y) % P for x, y in zip(a, b))

    def sub(self, a, b):
        return tuple((x - y) % P for x, y in zip(a, b))

    def neg(self, a):
        return tuple((-x) % P for x in a)

    def smul(self, a, k):
        """extension element times base scalar k"""
        return tuple((x * k) % P for x in a)

    def mul(self, a, b):
        if self.e == 2:
            a0, a1 = a
            b0, b1 = b
            return ((a0 * b0 + W * a1 * b1) % P, (a0 * b1 + a1 * b0) % P)
        a0, a1, a2 = a
        b0, b1, b2 = b
        return ((a0 * b0 + W * (a1 * b2 + a2 * b1)) % P,
                (a0 * b1 + a1 * b0 + W * a2 * b2) % P,
                (a0 * b2 + a1 * b1 + a2 * b0) % P)

    def sqr(self, a):
        return self.mul(a, a)

    def pow(self, a, k):
        r = self.one
        while k:
            if k & 1:
                r = self.mul(r, a)
            a = self.mul(a, a)
            k >>= 1
        return r

    def norm_adj(self, a):
        """(adjugate, norm) with a * adj = norm in F_p."""
        if self.e == 2:
            a0, a1 = a
            nrm = (a0 * a0 - W * a1 * a1) % P
            return ((a0 % P, (-a1) % P), nrm)
        a0, a1, a2 = a
        b0 = (a0 * a0 - W * a1 * a2) % P
        b1 = (W * a2 * a2 - a0 * a1) % P
        b2 = (a1 * a1 - a0 * a2) % P
        nrm = (a0 * b0 + W * (a2 * b1 + a1 * b2)) % P
        return ((b0, b1, b2), nrm)

    def inv(self, a):
        adj, nrm = self.norm_adj(a)
        return self.smul(adj, inv(nrm))

    def in_base(self, a):
        return all(x % P == 0 for x in a[1:])

    def eq(self, a, b):
        return all((x - y) % P == 0 for x, y in zip(a, b))

    def horner(self, coeffs, x):
        """sum coeffs[k] * x^k; coeffs are extension elements, x is an extension element."""
        acc = self.zero
        for c in reversed(coeffs):
            acc = self.add(self.mul(acc, x), c)
        return acc

    def horner_base_point(self, coeffs, x):
        """sum coeffs[k] * x^k with extension coefficients and a base-field point x."""
        acc = [0] * self.e
        for c in reversed(coeffs):
            acc = [(acc[i] * x + c[i]) % P for i in range(self.e)]
        return tuple(acc)

    def horner_base_coeffs(self, coeffs, x):
        """sum coeffs[k] * x^k with base coefficients and an extension point x."""
        acc = self.zero
        for c in reversed(coeffs):
            acc = self.mul(acc, x)
            acc = (( acc[0] + c) % P,) + acc[1:]
        return acc


def self_check():
    """Facts the design relies on (SPEC.md section 1.4)."""
    assert pow(GEN, (P - 1) // 2, P) == P - 1                  # 7 is a non-square
    assert (P - 1) % 3 == 0 and pow(GEN, (P - 1) // 3, P) != 1  # 7 is a non-cube
    from math import gcd
    assert gcd(7, P - 1) == 1                                   # x -> x^7 is a permutation
    assert (P - 1) % 2**32 == 0 and (P - 1) % 2**33 != 0        # 2-adicity 32
    for e in (2, 3):
        E = Ext(e)
        a = tuple(range(3, 3 + e))
        assert E.eq(E.mul(a, E.inv(a)), E.one)
    return True

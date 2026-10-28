#!/usr/bin/env python3
"""Reference prover for the pq-hash STARK (MiMC-7 chain AIR, DEEP-ALI + batched DEEP-FRI, SHA-256).

Deterministic: the same (parameter set, x_in) gives the same proof (the grinding nonce is the smallest
valid one). Vector field arithmetic uses numpy (uint64, Goldilocks reduction by hand); every transcript
and serialization step uses the shared pure-Python modules, exactly as the verifier does.
No zero-knowledge: no masking polynomials (SPEC.md 1.2).

Usage:  python3 prover.py P100 [x_in]     -> writes nothing, prints sizes and timings (see gen_vectors.py)
"""
import hashlib
import multiprocessing as mp
import sys
import time

import numpy as np

from pqfield import P, Ext, root_of_unity, inv
from pqparams import SETS, fri_shape, periodic_poly, round_constants
from pqproto import (Transcript, sha256, enc_base, enc_ext, grinding_ok, query_indices, layout)

U64 = np.uint64
PU = U64(P)
EPS = U64(2**32 - 1)
M32 = U64(0xFFFFFFFF)
S32 = U64(32)


# ================================================================ Goldilocks vector arithmetic
def vadd(a, b):
    s = a + b
    s = np.where(s < a, s + EPS, s)
    return np.where(s >= PU, s - PU, s)


def vsub(a, b):
    d = a - b
    return np.where(a < b, d - EPS, d)


def vneg(a):
    return np.where(a == 0, a, PU - a)


def vmul(a, b):
    a0, a1 = a & M32, a >> S32
    b0, b1 = b & M32, b >> S32
    ll, lh, hl, hh = a0 * b0, a0 * b1, a1 * b0, a1 * b1
    mid = lh + hl
    cmid = (mid < lh).astype(U64)
    lo = ll + (mid << S32)
    clo = (lo < ll).astype(U64)
    hi = hh + (mid >> S32) + (cmid << S32) + clo
    return reduce128(hi, lo)


def reduce128(hi, lo):
    """hi*2^64 + lo mod p, using 2^64 = 2^32 - 1 and 2^96 = -1."""
    h1, h0 = hi >> S32, hi & M32
    t = lo - h1
    t = np.where(lo < h1, t - EPS, t)
    u = h0 * EPS
    r = t + u
    r = np.where(r < t, r + EPS, r)
    return np.where(r >= PU, r - PU, r)


def vsmul(a, k):
    return vmul(a, U64(k % P))


def arr(vals):
    return np.array([v % P for v in vals], dtype=U64)


def to_ints(a):
    return [int(x) for x in a]


def vpow_seq(base, n, start=1):
    """[start * base^i for i < n]"""
    out = np.empty(n, dtype=U64)
    out[0] = start % P
    m = 1
    while m < n:
        k = min(m, n - m)
        out[m:m + k] = vmul(out[:k], U64(pow(base, m, P)))
        m += k
    return out


def batch_inv(a):
    """Elementwise inverse of a nonzero uint64 vector (chunked Montgomery trick)."""
    n = a.size
    cols = 1
    while cols * cols < n:
        cols *= 2
    rows = (n + cols - 1) // cols
    pad = rows * cols - n
    x = np.concatenate([a, np.ones(pad, dtype=U64)]).reshape(rows, cols)
    pref = np.empty_like(x)
    pref[0] = x[0]
    for i in range(1, rows):
        pref[i] = vmul(pref[i - 1], x[i])
    tot = arr([inv(int(v)) for v in pref[-1]])
    out = np.empty_like(x)
    for i in range(rows - 1, 0, -1):
        out[i] = vmul(tot, pref[i - 1])
        tot = vmul(tot, x[i])
    out[0] = tot
    return out.reshape(-1)[:n]


_bitrev_cache = {}


def bitrev(n):
    if n not in _bitrev_cache:
        k = n.bit_length() - 1
        i = np.arange(n, dtype=np.int64)
        r = np.zeros(n, dtype=np.int64)
        for b in range(k):
            r |= ((i >> b) & 1) << (k - 1 - b)
        _bitrev_cache[n] = r
    return _bitrev_cache[n]


def ntt(a, omega):
    """A[i] = sum_j a[j] omega^(ij), len(a) a power of two, omega of order len(a)."""
    n = a.size
    x = a[bitrev(n)].copy()
    tw = vpow_seq(omega, max(n // 2, 1))
    half = 1
    while half < n:
        L = 2 * half
        w = tw[::n // L][:half]
        X = x.reshape(n // L, 2, half)
        u = X[:, 0, :]
        v = vmul(X[:, 1, :], w[None, :])
        y = np.empty_like(X)
        y[:, 0, :] = vadd(u, v)
        y[:, 1, :] = vsub(u, v)
        x = y.reshape(n)
        half = L
    return x


def intt(a, omega):
    n = a.size
    return vsmul(ntt(a, inv(omega)), inv(n))


def coset_eval(coeffs, shift, size):
    """Evaluations of sum c_k X^k at shift * w_size^i, i < size."""
    c = np.zeros(size, dtype=U64)
    c[:coeffs.size] = vmul(coeffs, vpow_seq(shift, coeffs.size))
    return ntt(c, root_of_unity(size))


def coset_interp(vals, shift):
    """Coefficients of the polynomial with the given values on shift * <w_n> (n = len(vals))."""
    n = vals.size
    c = intt(vals, root_of_unity(n))
    return vmul(c, vpow_seq(inv(shift), n))


# ================================================================ extension vectors (lists of e arrays)
def ev_mul(e, a, b):
    if e == 2:
        return [vadd(vmul(a[0], b[0]), vsmul(vmul(a[1], b[1]), 7)),
                vadd(vmul(a[0], b[1]), vmul(a[1], b[0]))]
    return [vadd(vmul(a[0], b[0]), vsmul(vadd(vmul(a[1], b[2]), vmul(a[2], b[1])), 7)),
            vadd(vadd(vmul(a[0], b[1]), vmul(a[1], b[0])), vsmul(vmul(a[2], b[2]), 7)),
            vadd(vadd(vmul(a[0], b[2]), vmul(a[1], b[1])), vmul(a[2], b[0]))]


def ev_scal(e, a, k):
    """extension vector a times extension scalar k (tuple)"""
    kb = [np.full(a[0].size, U64(c), dtype=U64) for c in k]
    return ev_mul(e, a, kb)


def ev_add(a, b):
    return [vadd(x, y) for x, y in zip(a, b)]


def ev_sub_const(a, k):
    return [vsub(x, U64(c)) for x, c in zip(a, k)]


def ev_base_times_scalar(v, k):
    """base vector v times extension scalar k"""
    return [vmul(v, U64(c)) for c in k]


def ev_inv_x_minus(e, x, z):
    """1 / (x - z) for a base vector x and an extension scalar z not in F_p."""
    n = x.size
    a0 = vsub(x, U64(z[0]))
    if e == 2:
        a1 = np.full(n, U64((-z[1]) % P), dtype=U64)
        nrm = vsub(vmul(a0, a0), vsmul(vmul(a1, a1), 7))
        ni = batch_inv(nrm)
        return [vmul(a0, ni), vmul(vneg(a1), ni)]
    a1 = np.full(n, U64((-z[1]) % P), dtype=U64)
    a2 = np.full(n, U64((-z[2]) % P), dtype=U64)
    b0 = vsub(vmul(a0, a0), vsmul(vmul(a1, a2), 7))
    b1 = vsub(vsmul(vmul(a2, a2), 7), vmul(a0, a1))
    b2 = vsub(vmul(a1, a1), vmul(a0, a2))
    nrm = vadd(vmul(a0, b0), vsmul(vadd(vmul(a2, b1), vmul(a1, b2)), 7))
    ni = batch_inv(nrm)
    return [vmul(b0, ni), vmul(b1, ni), vmul(b2, ni)]


# ================================================================ Merkle trees
class Tree:
    def __init__(self, leaf_matrix, tag_byte, h):
        """leaf_matrix: uint64 array (num_leaves, values_per_leaf), serialized little-endian row-wise."""
        self.h = h
        raw = leaf_matrix.astype('<u8').tobytes()
        self.leaf_len = leaf_matrix.shape[1] * 8
        self.raw = raw
        nl = leaf_matrix.shape[0]
        tb = bytes([tag_byte])
        L = self.leaf_len
        sh = hashlib.sha256
        lvl = b''.join(sh(tb + raw[i * L:(i + 1) * L]).digest()[:h] for i in range(nl))
        self.levels = [lvl]
        while len(lvl) > h:
            m = len(lvl) // (2 * h)
            lvl = b''.join(sh(lvl[2 * i * h:(2 * i + 2) * h]).digest()[:h] for i in range(m))
            self.levels.append(lvl)
        self.root = lvl
        self.depth = len(self.levels) - 1

    def leaf(self, i):
        return self.raw[i * self.leaf_len:(i + 1) * self.leaf_len]

    def node(self, level, i):
        return self.levels[level][i * self.h:(i + 1) * self.h]

    def path(self, i):
        return [self.node(l, (i >> l) ^ 1) for l in range(self.depth)]

    def multiproof(self, positions):
        """Canonical dedup multiproof siblings (SERIALIZATION.md 4.2)."""
        out = []
        cur = sorted(set(positions))
        for l in range(self.depth):
            s = set(cur)
            nxt = []
            for k in cur:
                if k % 2 == 1 and (k - 1) in s:
                    continue
                if k % 2 == 0 and (k + 1) in s:
                    pass
                else:
                    out.append(self.node(l, k ^ 1))
                nxt.append(k >> 1)
            cur = sorted(set(nxt))
        return out


# ================================================================ grinding
def _grind_chunk(args):
    t, start, count, g = args
    base = hashlib.sha256(t)
    for nonce in range(start, start + count):
        h = base.copy()
        h.update(nonce.to_bytes(8, 'little'))
        if grinding_ok(h.digest(), g):
            return nonce
    return None


def grind(t, g, workers=None, chunk=1 << 20):
    """Smallest nonce with SHA256(t || u64le nonce) having g leading zero bits."""
    if g <= 16:
        return _grind_chunk((t, 0, 1 << 40, g))
    workers = workers or mp.cpu_count()
    start = 0
    with mp.get_context('fork').Pool(workers) as pool:
        while True:
            jobs = [(t, start + i * chunk, chunk, g) for i in range(workers)]
            for res in pool.map(_grind_chunk, jobs):
                if res is not None:
                    return res
            start += workers * chunk


# ================================================================ statement
def mimc_trace(x_in, n):
    C = round_constants()
    X, Y = [0] * n, [0] * n
    X[0] = x_in % P
    for i in range(n):
        s = (X[i] + C[i % 8]) % P
        Y[i] = pow(s, 3, P)
        if i + 1 < n:
            X[i + 1] = Y[i] * Y[i] % P * s % P
    return X, Y


def statement_input(k):
    return int.from_bytes(sha256(b'verifier.cash/pq-hash/x_in' + bytes([k])), 'little') % P


# ================================================================ prover
def prove(p, x_in, log=print, workers=None, final_tweak=False):
    """final_tweak=True adds 1 to final coefficient 0 (c0) AFTER the honest computation and then
    continues honestly (grind, open): a rejection-test proof whose only defect is the final layer."""
    t_start = time.time()
    E = Ext(p.e)
    e = p.e
    N, arities, sizes, trees = fri_shape(p)
    r = len(arities)
    n = 2 ** p.log_n
    N1 = sizes[1]
    a0 = arities[0]
    stats = {}

    def tick(name):
        stats[name] = round(time.time() - t_start, 2)
        log(f'  [{p.name}] {name} at {stats[name]} s')

    Xt, Yt = mimc_trace(x_in, n)
    y_out = Xt[-1]
    w_n = root_of_unity(n)
    Xc = intt(arr(Xt), w_n)
    Yc = intt(arr(Yt), w_n)
    X_L = coset_eval(Xc, 7, N)
    Y_L = coset_eval(Yc, 7, N)
    tick('trace LDE')

    # trace commitment: leaf v holds (X, Y) at u = v + j*N1, j < a0
    Xr, Yr = X_L.reshape(a0, N1), Y_L.reshape(a0, N1)
    tmat = np.stack([c for j in range(a0) for c in (Xr[j], Yr[j])], axis=1)
    T_trace = Tree(tmat, trees[0]['tag'], p.h)
    del tmat
    T = Transcript(p, x_in, y_out)
    T.absorb(T_trace.root, 't1')
    alpha = [T.challenge('a', j) for j in range(1, 5)]
    tick('trace tree')

    # composition on D2 = 7 * <w_2n> (positions of L0 at stride N/2n)
    n2 = 2 * n
    st = N // n2
    XD, YD = X_L[::st].copy(), Y_L[::st].copy()
    XwD = np.roll(XD, -2)                                    # X(w x): w = w_2n^2
    xD = vpow_seq(root_of_unity(n2), n2, 7)
    Pc = periodic_poly()
    w16 = root_of_unity(16)
    base8 = pow(7, n // 8, P)
    cvals = [sum(Pc[k] * pow(base8 * pow(w16, j, P) % P, k, P) for k in range(8)) % P for j in range(16)]
    cD = np.tile(arr(cvals), n2 // 16)                       # x^(n/8) = 7^(n/8) * w16^j
    s = vadd(XD, cD)
    C1 = vsub(YD, vmul(vmul(s, s), s))
    C2 = vsub(XwD, vmul(vmul(YD, YD), s))
    w_last = pow(w_n, n - 1, P)
    zn_vals = arr([(pow(7, n, P) - 1) % P, (-pow(7, n, P) - 1) % P])   # x^n - 1 = 7^n * (-1)^j - 1
    zinv = np.tile(arr([inv(int(v)) for v in zn_vals]), n2 // 2)
    q = vmul(vsub(xD, U64(w_last)), zinv)
    inv_x1 = batch_inv(vsub(xD, U64(1)))
    inv_xl = batch_inv(vsub(xD, U64(w_last)))
    b1 = vmul(vsub(XD, U64(x_in)), inv_x1)
    b2 = vmul(vsub(XD, U64(y_out)), inv_xl)
    C1q, C2q = vmul(C1, q), vmul(C2, q)
    Hcoef = []
    for k in range(e):
        hk = vadd(vadd(vsmul(C1q, alpha[0][k]), vsmul(C2q, alpha[1][k])),
                  vadd(vsmul(b1, alpha[2][k]), vsmul(b2, alpha[3][k])))
        c = coset_interp(hk, 7)
        assert int(c[n2 - 1]) == 0, 'composition degree too high: trace does not satisfy the AIR'
        Hcoef.append(c)
    H0c = [c[:n] for c in Hcoef]
    H1c = [c[n:] for c in Hcoef]
    H0_L = [coset_eval(c, 7, N) for c in H0c]
    H1_L = [coset_eval(c, 7, N) for c in H1c]
    tick('composition LDE')
    H0r = [x.reshape(a0, N1) for x in H0_L]
    H1r = [x.reshape(a0, N1) for x in H1_L]
    cmat = np.stack([c for j in range(a0) for c in [H0r[k][j] for k in range(e)] + [H1r[k][j] for k in range(e)]],
                    axis=1)
    T_comp = Tree(cmat, trees[1]['tag'], p.h)
    del cmat
    T.absorb(T_comp.root, 't2')
    z = T.challenge('z')
    if E.in_base(z):
        raise RuntimeError('z in base field (probability ~2^-128); not handled by this prover')
    tick('comp tree')

    # OOD values
    Xz = E.horner_base_coeffs(to_ints(Xc), z)
    Yz = E.horner_base_coeffs(to_ints(Yc), z)
    wz = E.smul(z, w_n)
    Xwz = E.horner_base_coeffs(to_ints(Xc), wz)
    H0co = list(zip(*[to_ints(c) for c in H0c]))
    H1co = list(zip(*[to_ints(c) for c in H1c]))
    H0z = E.horner(H0co, z)
    H1z = E.horner(H1co, z)
    ood = enc_ext(Xz) + enc_ext(Yz) + enc_ext(Xwz) + enc_ext(H0z) + enc_ext(H1z)
    T.absorb(ood, 't3')
    gamma = [T.challenge('g', j) for j in range(1, 6)]
    beta = [T.challenge('b')]
    tick('OOD')

    # DEEP polynomial f0 on L0
    xL = vpow_seq(root_of_unity(N), N, 7)
    num = ev_add(ev_base_times_scalar(X_L, gamma[0]), ev_base_times_scalar(Y_L, gamma[1]))
    num = ev_add(num, ev_scal(e, H0_L, gamma[3]))
    num = ev_add(num, ev_scal(e, H1_L, gamma[4]))
    K = E.add(E.add(E.mul(gamma[0], Xz), E.mul(gamma[1], Yz)), E.add(E.mul(gamma[3], H0z), E.mul(gamma[4], H1z)))
    num = ev_sub_const(num, K)
    f = ev_mul(e, num, ev_inv_x_minus(e, xL, z))
    del num
    t2 = ev_sub_const(ev_base_times_scalar(X_L, gamma[2]), E.mul(gamma[2], Xwz))
    f = ev_add(f, ev_mul(e, t2, ev_inv_x_minus(e, xL, wz)))
    del t2, xL
    tick('DEEP')

    # FRI commit phase
    layers = [f]
    fri_trees = []
    shift = 7
    for i in range(r):
        a = arities[i]
        f = fold_layer(e, layers[-1], a, beta[i], shift, sizes[i])
        shift = pow(shift, a, P)
        layers.append(f)
        if i + 1 < r:
            a1 = arities[i + 1]
            nl = sizes[i + 2]
            fr = [c.reshape(a1, nl) for c in f]
            mat = np.stack([fr[k][j] for j in range(a1) for k in range(e)], axis=1)
            tr = Tree(mat, trees[2 + i]['tag'], p.h)
            fri_trees.append(tr)
            T.absorb(tr.root, f't{4 + i}')
            beta.append(T.challenge('b'))
    tick('FRI commit')
    # final polynomial: coefficients of f_r on L_r = shift * <w_{N_r}>
    fc = [coset_interp(c, shift) for c in layers[-1]]
    D = 2 ** p.log_df
    for c in fc:
        assert not c[D:].any(), 'final layer degree too high'
    final = [tuple(int(fc[k][i]) for k in range(e)) for i in range(D)]
    if final_tweak:
        final[0] = ((final[0][0] + 1) % P,) + final[0][1:]
    final_b = b''.join(enc_ext(c) for c in final)
    T.absorb(final_b, f't{3 + r}')
    tick('final poly')
    nonce = grind(T.t, p.g, workers)
    nonce_b = nonce.to_bytes(8, 'little')
    G = sha256(T.t + nonce_b)
    tick(f'grinding (nonce {nonce})')
    idx = query_indices(G, p.s, N1)

    # assemble the canonical proof
    all_trees = [T_trace, T_comp] + fri_trees
    roots = [t.root for t in all_trees]
    pt = enc_base(x_in) + enc_base(y_out) + roots[0] + roots[1] + ood + b''.join(roots[2:]) + final_b + nonce_b
    pos = [[ix] for ix in idx]
    for qq in range(p.s):
        for i in range(r):
            pos[qq].append(pos[qq][i] % sizes[i + 1])
    tree_pos = lambda ti: [pos[qq][(0 if ti < 2 else ti - 1) + 1] for qq in range(p.s)]
    leaves = b''.join(all_trees[ti].leaf(tree_pos(ti)[qq]) for qq in range(p.s) for ti in range(len(all_trees)))
    sib = [all_trees[ti].multiproof(tree_pos(ti)) for ti in range(len(all_trees))]
    proof = pt + leaves + b''.join(b''.join(x) for x in sib)
    off, pt_len, leaf_total, _ = layout(p)
    assert len(pt) == pt_len and len(leaves) == p.s * leaf_total
    tick('assemble')
    sections = dict(pt=len(pt), leaves=len(leaves),
                    siblings={trees[ti]['name']: len(sib[ti]) * p.h for ti in range(len(all_trees))},
                    siblings_total=sum(len(x) for x in sib) * p.h,
                    plain_paths_total=len(pt) + len(leaves) + sum(t.depth for t in all_trees) * p.h * p.s)
    queries = []
    for qq in range(p.s):
        qd = dict(index=idx[qq], positions=pos[qq], trees={})
        for ti, t in enumerate(all_trees):
            lp = tree_pos(ti)[qq]
            qd['trees'][trees[ti]['name']] = dict(leaf_index=lp, leaf=t.leaf(lp).hex(),
                                                  path=[x.hex() for x in t.path(lp)])
        queries.append(qd)
    return dict(proof=proof, x_in=x_in, y_out=y_out, nonce=nonce, roots=[x.hex() for x in roots],
                ood=ood.hex(), final=final_b.hex(), sections=sections, queries=queries,
                multiproof={trees[ti]['name']: [x.hex() for x in sib[ti]] for ti in range(len(all_trees))},
                timings=stats, transcript_t=T.t.hex())


def fold_layer(e, f, a, beta, shift, size):
    """Fold f (on shift*<w_size>) by arity a with challenge beta -> values on shift^a * <w_{size/a}>."""
    m = size // a
    R = [c.reshape(a, m) for c in f]
    wai = inv(root_of_unity(a))
    V = []
    for t in range(a):
        comp = []
        for k in range(e):
            acc = R[k][0].copy()
            for j in range(1, a):
                acc = vadd(acc, vsmul(R[k][j], pow(wai, j * t, P)))
            comp.append(acc)
        V.append(comp)
    x0inv = vpow_seq(inv(root_of_unity(size)), m, inv(shift))
    y = ev_base_times_scalar(x0inv, beta)
    acc = V[a - 1]
    for t in range(a - 2, -1, -1):
        acc = ev_add(ev_mul(e, acc, y), V[t])
    ai = inv(a)
    return [vsmul(c, ai) for c in acc]


if __name__ == '__main__':
    name = sys.argv[1] if len(sys.argv) > 1 else 'P128'
    x = int(sys.argv[2]) if len(sys.argv) > 2 else statement_input(0)
    out = prove(SETS[name], x)
    print(name, 'proof bytes', len(out['proof']), out['sections'])

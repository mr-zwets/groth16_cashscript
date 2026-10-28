"""Parameter sets, FRI shape, soundness calculator and baked constants for the pq-hash STARK.

The soundness formulas are a line-for-line re-implementation of the design calculator
(zk-verifier-bench, branch wip/pq-hash-design, commit c3497a1, research/pq-hash/params.py, function
`soundness`). test_soundness.py checks that both agree and that s is the minimal query count.
Pure Python, standard library only.
"""
import hashlib
import math
from dataclasses import dataclass, replace

from pqfield import P, GEN, root_of_unity, inv

LOG_P = math.log2(P)

# AIR (SPEC.md section 2)
W_COLS = 2       # trace columns X, Y
D = 3            # max constraint degree
SEG = D - 1      # composition segments H0, H1
M_C = 4          # constraints
N_OOD = 5        # X(z), Y(z), X(wz), H0(z), H1(z)
M_D = 5          # DEEP quotients batched into f0
N_RC = 8         # periodic round constants

TAG_PREFIX = b'verifier.cash/pq-hash/v1'
RC_PREFIX = b'verifier.cash/pq-hash/rc'
LEAF_TAG_TRACE = 0x01
LEAF_TAG_COMP = 0x02
LEAF_TAG_FRI_BASE = 0x02    # FRI tree i (i >= 1) uses tag 0x02 + i


@dataclass(frozen=True)
class Params:
    name: str
    pid: int             # param-id byte in TAG
    regime: str          # 'JB' | 'UDR' | 'CONJ' | 'JB25'
    e: int               # extension degree
    log_n: int
    log_blowup: int
    k0: int
    k: int
    log_df: int
    s: int
    g: int
    m: int
    h: int
    target: int          # security target (bits) the set was sized for
    label: str = ''


SETS = {
    'P100': Params('P100', 1, 'JB', 3, 16, 7, 4, 8, 8, 22, 28, 3, 25, 100,
                   'provable, Johnson (BCIKS20 Thm 8.3), F_p^3, h=25'),
    'P128': Params('P128', 2, 'JB', 3, 16, 5, 4, 8, 8, 43, 28, 4, 32, 128,
                   'provable, Johnson (BCIKS20 Thm 8.3, m=4), F_p^3, h=32'),
    'U100': Params('U100', 3, 'UDR', 2, 16, 4, 4, 8, 8, 79, 28, 3, 25, 100,
                   'comparison: provable, unique decoding, F_p^2'),
    'C100': Params('C100', 4, 'CONJ', 2, 16, 7, 8, 16, 6, 11, 28, 3, 25, 100,
                   'comparison: CONJECTURED (ethSTARK-style), F_p^2'),
    'C128': Params('C128', 5, 'CONJ', 3, 16, 7, 4, 16, 7, 15, 28, 3, 32, 128,
                   'comparison: CONJECTURED, F_p^3'),
}


def fri_shape(p: Params):
    """(N, arities, sizes, trees) exactly as the design calculator's fri_shape."""
    N = 2 ** (p.log_n + p.log_blowup)
    arities, deg, a = [], 2 ** p.log_n, p.k0
    while deg > 2 ** p.log_df:
        a_eff = min(a, deg // 2 ** p.log_df)
        arities.append(a_eff)
        deg //= a_eff
        a = p.k
    sizes = [N]
    for a in arities:
        sizes.append(sizes[-1] // a)
    trees = [dict(name='trace', tag=LEAF_TAG_TRACE, depth=int(math.log2(N // arities[0])),
                  leaf=arities[0] * W_COLS * 8, arity=arities[0]),
             dict(name='comp', tag=LEAF_TAG_COMP, depth=int(math.log2(N // arities[0])),
                  leaf=arities[0] * SEG * p.e * 8, arity=arities[0])]
    for i in range(1, len(arities)):
        trees.append(dict(name=f'fri{i}', tag=LEAF_TAG_FRI_BASE + i, depth=int(math.log2(sizes[i] // arities[i])),
                          leaf=arities[i] * p.e * 8, arity=arities[i]))
    return N, arities, sizes, trees


# ---------------------------------------------------------------- soundness (design calculator formulas)
def soundness(p: Params):
    N, arities, sizes, _ = fri_shape(p)
    n = 2 ** p.log_n
    rho = 2.0 ** -p.log_blowup
    log_q = p.e * LOG_P
    lg = math.log2
    r = {}
    if p.regime == 'UDR':
        r['ali'] = log_q - lg(M_C - 1)
        r['deep'] = log_q - lg(D * n + 2 * N)
        r['batch'] = log_q - lg(N)
        for i, a in enumerate(arities):
            r[f'fold{i+1}'] = log_q - lg((a - 1) * sizes[i + 1])
        delta = (1 - rho) / 2 - 1.0 / N
        r['query'] = -p.s * lg(1 - delta)
    elif p.regime in ('JB', 'JB25'):
        m = p.m
        L = (m + 0.5) / math.sqrt(rho)
        r['ali'] = log_q - lg(L * M_C)
        r['deep'] = log_q - lg(L * L * (D * n + 2 * N))
        if p.regime == 'JB':
            eps_c = ((m + 0.5) ** 7 * N ** 2) / (2 * rho ** 1.5) + (2 * m + 1) * (N + 1) / math.sqrt(rho) * sum(arities)
            r['batch+folds'] = log_q - lg(eps_c)
        else:
            def a_line(nn):
                return (2 * (m + 0.5) ** 5 + 3 * (m + 0.5) * rho) / (3 * rho ** 1.5) * nn + (m + 0.5) / math.sqrt(rho)
            r['batch'] = log_q - lg((M_D - 1) * a_line(N))
            for i, a in enumerate(arities):
                r[f'fold{i+1}'] = log_q - lg((a - 1) * a_line(sizes[i]))
        r['query'] = -p.s * lg(math.sqrt(rho) * (1 + 1 / (2 * m)))
    elif p.regime == 'CONJ':
        r['ali'] = log_q - lg(M_C)
        r['deep'] = log_q - lg(D * n + 2 * N)
        r['batch+folds'] = log_q - lg(N * sum(arities))
        r['query'] = p.s * p.log_blowup
    else:
        raise ValueError(p.regime)
    out = {k_: v + (p.g if k_ == 'query' else 0) for k_, v in r.items()}
    lam_iop = min(out.values())
    lam_hash = 4 * p.h
    return dict(rounds={k_: round(v, 2) for k_, v in out.items()}, lam_iop=round(lam_iop, 2),
                lam=round(min(lam_iop, lam_hash), 2),
                limited_by=(min(out, key=out.get) if lam_iop <= lam_hash else 'digest'))


def min_queries(p: Params, target):
    """Smallest s with lambda_IOP >= target (as the design calculator), or None."""
    if soundness(replace(p, s=4000))['lam_iop'] < target:
        return None
    lo, hi = 1, 4000
    while lo < hi:
        mid = (lo + hi) // 2
        if soundness(replace(p, s=mid))['lam_iop'] >= target:
            hi = mid
        else:
            lo = mid + 1
    return lo


def expected_proof_bytes(p: Params):
    """Design expectation for the canonical proof (dedup multiproof over uniform indices)."""
    N, arities, sizes, trees = fri_shape(p)
    pt = pt_size(p)
    leaves = sum(t['leaf'] for t in trees) * p.s

    def exp_siblings(depth, s):
        return sum(2 ** l * ((1 - 2.0 ** -l) ** s - (1 - 2.0 ** (1 - l)) ** s) for l in range(1, depth + 1))
    sib = sum(exp_siblings(t['depth'], p.s) for t in trees) * p.h
    return dict(total=round(pt + leaves + sib), pt=pt, leaves=leaves, siblings=round(sib))


# ---------------------------------------------------------------- constants and layout
def round_constants():
    """C[j] = LE(SHA256(RC_PREFIX || u8 j)) mod p."""
    return [int.from_bytes(hashlib.sha256(RC_PREFIX + bytes([j])).digest(), 'little') % P for j in range(N_RC)]


def periodic_poly(C=None):
    """Coefficients of P_c (degree < 8) with P_c(w8^j) = C[j], w8 = 7^((p-1)/8)."""
    C = C or round_constants()
    w8 = root_of_unity(N_RC)
    w8i = inv(w8)
    ninv = inv(N_RC)
    return [sum(C[j] * pow(w8i, j * k, P) for j in range(N_RC)) * ninv % P for k in range(N_RC)]


def pt_size(p: Params):
    N, arities, sizes, trees = fri_shape(p)
    e8 = p.e * 8
    return 16 + len(trees) * p.h + N_OOD * e8 + (2 ** p.log_df) * e8 + 8


def baked_constants(p: Params):
    """Byte string hashed into TAG (SERIALIZATION.md section 2)."""
    N, arities, sizes, trees = fri_shape(p)
    C = round_constants()
    Pc = periodic_poly(C)
    le8 = lambda v: (v % P).to_bytes(8, 'little')
    b = b''.join(le8(c) for c in C) + b''.join(le8(c) for c in Pc)
    b += le8(root_of_unity(2 ** p.log_n)) + le8(root_of_unity(N))
    b += bytes([p.e, 7, p.log_n, int(math.log2(N)), len(arities)]) + bytes(arities)
    b += bytes([p.log_df]) + p.s.to_bytes(2, 'little') + bytes([p.g, p.h, p.m])
    return b


def tag(p: Params):
    return TAG_PREFIX + bytes([p.pid]) + hashlib.sha256(baked_constants(p)).digest()


def describe(p: Params):
    N, arities, sizes, trees = fri_shape(p)
    return dict(name=p.name, pid=p.pid, regime=p.regime, label=p.label, e=p.e, n=2 ** p.log_n, N=N,
                log_blowup=p.log_blowup, arities=arities, layer_sizes=sizes, log_final_degree=p.log_df,
                final_coeffs=2 ** p.log_df, queries=p.s, grinding_bits=p.g, m=p.m, digest_bytes=p.h,
                trees=[dict(name=t['name'], tag=t['tag'], depth=t['depth'], leaf_bytes=t['leaf'], arity=t['arity'])
                       for t in trees],
                pt_bytes=pt_size(p), tag_hex=tag(p).hex(), soundness=soundness(p),
                expected_proof_bytes=expected_proof_bytes(p))

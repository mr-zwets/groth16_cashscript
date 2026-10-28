#!/usr/bin/env python3
"""Reference (value-level) verifier for the pq-hash DEEP-ALI / DEEP-FRI STARK over Goldilocks.

Pure Python, standard library only. It reads the canonical proof byte stream of SERIALIZATION.md
(the layout (b) single-input format) and returns (accepted, reason, derived) where `derived` holds the
transcript, challenges, indices and per-query intermediate values (for kernel and script tests).

Usage:  python3 verifier.py vectors/P100-0.json      # verifies the valid proof and every tamper case
"""
import json
import sys

from pqfield import P, Ext, root_of_unity, inv
from pqparams import SETS, fri_shape, periodic_poly, N_OOD
from pqproto import (Transcript, sha256, dec_base, dec_ext, enc_ext, grinding_ok, query_indices,
                     leaf_hash, multiproof_root, layout)


class Reject(Exception):
    pass


def verify(p, proof, want_statement=None, derive=False):
    try:
        d = _verify(p, proof, want_statement)
        return True, 'accept', (d if derive else None)
    except Reject as r:
        return False, str(r), None


def _verify(p, proof, want_statement):
    E = Ext(p.e)
    e8 = 8 * p.e
    N, arities, sizes, trees = fri_shape(p)
    r = len(arities)
    n = 2 ** p.log_n
    off, pt_len, leaf_total, _ = layout(p)
    if len(proof) < pt_len + p.s * leaf_total:
        raise Reject('parse: proof shorter than PT + leaves')

    def field(name):
        o, ln = off[name]
        return proof[o:o + ln]

    # -- statement (canonical) --------------------------------------------------------------------
    x_raw, y_raw = int.from_bytes(field('x_in'), 'little'), int.from_bytes(field('y_out'), 'little')
    if x_raw >= P or y_raw >= P:
        raise Reject('statement: non-canonical public input')
    x_in, y_out = x_raw, y_raw
    if want_statement is not None and (x_in, y_out) != tuple(want_statement):
        raise Reject('statement: proof is for a different statement')

    # -- transcript --------------------------------------------------------------------------------
    T = Transcript(p, x_in, y_out)
    T.absorb(field('root_trace'), 't1')
    alpha = [T.challenge('a', j) for j in range(1, 5)]
    T.absorb(field('root_comp'), 't2')
    z = T.challenge('z')
    if E.in_base(z):
        raise Reject('z-in-base-field')
    ood_b = field('ood')
    Xz, Yz, Xwz, H0z, H1z = (dec_ext(ood_b[i * e8:(i + 1) * e8], p.e) for i in range(N_OOD))
    T.absorb(ood_b, 't3')
    gamma = [T.challenge('g', j) for j in range(1, 6)]
    beta = [T.challenge('b')]
    for i in range(1, r):
        T.absorb(field(f'root_fri{i}'), f't{3 + i}')
        beta.append(T.challenge('b'))
    fin_b = field('final')
    final = [dec_ext(fin_b[k * e8:(k + 1) * e8], p.e) for k in range(2 ** p.log_df)]
    T.absorb(fin_b, f't{3 + r}')
    G = sha256(T.t + field('nonce'))

    # -- AIR identity at z, cross-multiplied (SPEC.md 2) --------------------------------------------
    w_n = root_of_unity(n)
    w_last = pow(w_n, n - 1, P)
    zn = E.pow(z, n)
    zm = E.sub(z, E.lift(w_last))
    z1 = E.sub(z, E.one)
    zn1 = E.sub(zn, E.one)
    cz = E.horner_base_coeffs(periodic_poly(), E.pow(z, n // 8))
    sv = E.add(Xz, cz)
    C1 = E.sub(Yz, E.mul(E.sqr(sv), sv))
    C2 = E.sub(Xwz, E.mul(E.sqr(Yz), sv))
    lhs = E.mul(E.mul(E.mul(E.add(H0z, E.mul(zn, H1z)), zn1), z1), zm)
    rhs = E.mul(E.mul(E.add(E.mul(alpha[0], C1), E.mul(alpha[1], C2)), E.sqr(zm)), z1)
    rhs = E.add(rhs, E.mul(E.mul(E.mul(alpha[2], E.sub(Xz, E.lift(x_in))), zn1), zm))
    rhs = E.add(rhs, E.mul(E.mul(E.mul(alpha[3], E.sub(Xz, E.lift(y_out))), zn1), z1))
    if not E.eq(lhs, rhs):
        raise Reject('air: composition identity at z fails')

    # -- grinding and indices -----------------------------------------------------------------------
    if not grinding_ok(G, p.g):
        raise Reject('grinding: proof-of-work check fails')
    idx = query_indices(G, p.s, sizes[1])

    # -- leaves and Merkle multiproofs -------------------------------------------------------------
    lo = pt_len
    leaves = []
    for q in range(p.s):
        row = []
        for t in trees:
            row.append(proof[lo:lo + t['leaf']])
            lo += t['leaf']
        leaves.append(row)
    pos = [[ix] for ix in idx]                    # pos[q][i] = position in L_i
    for q in range(p.s):
        for i in range(r):
            pos[q].append(pos[q][i] % sizes[i + 1])
    cursor = [lo]

    def take():
        o = cursor[0]
        if o + p.h > len(proof):
            raise Reject('parse: proof truncated inside multiproof')
        cursor[0] = o + p.h
        return proof[o:o + p.h]

    roots = [field('root_trace'), field('root_comp')] + [field(f'root_fri{i}') for i in range(1, r)]
    for ti, t in enumerate(trees):
        layer = 0 if ti < 2 else ti - 1
        positions = [pos[q][layer + 1] for q in range(p.s)]
        hashes = [leaf_hash(t['tag'], leaves[q][ti], p.h) for q in range(p.s)]
        try:
            root = multiproof_root(positions, hashes, t['depth'], p.h, take)
        except ValueError:
            raise Reject(f"merkle: duplicate leaf mismatch in {t['name']}")
        if root != roots[ti]:
            raise Reject(f"merkle: root mismatch in {t['name']}")
    if cursor[0] != len(proof):
        raise Reject('parse: trailing bytes after multiproofs')

    # -- per-query DEEP, folds, final polynomial -----------------------------------------------------
    w_N = [root_of_unity(sz) for sz in sizes]
    shift = [7]
    for a in arities:
        shift.append(pow(shift[-1], a, P))
    wz = E.mul(E.lift(w_n), z)
    K = E.add(E.add(E.mul(gamma[0], Xz), E.mul(gamma[1], Yz)), E.add(E.mul(gamma[3], H0z), E.mul(gamma[4], H1z)))
    gXwz = E.mul(gamma[2], Xwz)
    per_query = []
    for q in range(p.s):
        a0 = arities[0]
        v = pos[q][1]
        tl, cl = leaves[q][0], leaves[q][1]
        x0 = shift[0] * pow(w_N[0], v, P) % P
        wa = root_of_unity(a0)
        vals = []
        for j in range(a0):
            x = x0 * pow(wa, j, P) % P
            Xx, Yx = dec_base(tl[16 * j:16 * j + 8]), dec_base(tl[16 * j + 8:16 * j + 16])
            H0x = dec_ext(cl[2 * e8 * j:2 * e8 * j + e8], p.e)
            H1x = dec_ext(cl[2 * e8 * j + e8:2 * e8 * (j + 1)], p.e)
            num = E.add(E.add(E.smul(gamma[0], Xx), E.smul(gamma[1], Yx)),
                        E.add(E.mul(gamma[3], H0x), E.mul(gamma[4], H1x)))
            num = E.sub(num, K)
            t1 = E.mul(num, E.inv(E.sub(E.lift(x), z)))
            t2 = E.mul(E.sub(E.smul(gamma[2], Xx), gXwz), E.inv(E.sub(E.lift(x), wz)))
            vals.append(E.add(t1, t2))
        qd = dict(index=idx[q], positions=pos[q], f0=[enc_ext(v_).hex() for v_ in vals], folded=[])
        cur = fold(E, vals, beta[0], x0, a0)
        qd['folded'].append(enc_ext(cur).hex())
        for i in range(1, r):
            a = arities[i]
            slot = pos[q][i] // sizes[i + 1]
            leaf = leaves[q][i + 1]
            if not E.eq(dec_ext(leaf[slot * e8:(slot + 1) * e8], p.e), cur):
                raise Reject(f'fri: layer {i} value does not match fold of layer {i - 1} (query {q})')
            coset = [dec_ext(leaf[j * e8:(j + 1) * e8], p.e) for j in range(a)]
            x0 = shift[i] * pow(w_N[i], pos[q][i + 1], P) % P
            cur = fold(E, coset, beta[i], x0, a)
            qd['folded'].append(enc_ext(cur).hex())
        y = shift[r] * pow(w_N[r], pos[q][r], P) % P
        if not E.eq(E.horner_base_point(final, y), cur):
            raise Reject(f'fri: final polynomial does not match last fold (query {q})')
        per_query.append(qd)

    hx = lambda a: enc_ext(a).hex()
    return dict(transcript=T.log + [('G', G.hex())], alpha=[hx(a) for a in alpha], z=hx(z),
                gamma=[hx(g) for g in gamma], beta=[hx(b) for b in beta], G=G.hex(), indices=idx,
                air=dict(zn=hx(zn), cz=hx(cz), lhs=hx(lhs), rhs=hx(rhs)), queries=per_query)


def fold(E, vals, beta, x0, a):
    """f_{i+1}(x0^a) = (1/a) * sum_t (beta * x0^-1)^t * V_t,  V_t = sum_j v_j * w_a^(-j t)."""
    wai = inv(root_of_unity(a))
    V = []
    for t in range(a):
        acc = E.zero
        for j in range(a):
            acc = E.add(acc, E.smul(vals[j], pow(wai, j * t, P)))
        V.append(acc)
    y = E.smul(beta, inv(x0))
    acc = E.zero
    for t in reversed(range(a)):
        acc = E.add(E.mul(acc, y), V[t])
    return E.smul(acc, inv(a))


def apply_tamper(proof, tamper):
    if 'proof_hex' in tamper:
        return bytes.fromhex(tamper['proof_hex'])
    b = bytearray(proof)
    for patch in tamper.get('patches', []):
        o = patch['offset']
        if 'xor' in patch:
            for i, x in enumerate(bytes.fromhex(patch['xor'])):
                b[o + i] ^= x
        else:
            nb = bytes.fromhex(patch['bytes'])
            b[o:o + len(nb)] = nb
    if 'truncate' in tamper:
        b = b[:tamper['truncate']]
    if 'append' in tamper:
        b += bytes.fromhex(tamper['append'])
    return bytes(b)


def main(paths):
    bad = 0
    for path in paths:
        v = json.load(open(path))
        p = SETS[v['params']['name']]
        proof = bytes.fromhex(v['proof'])
        st = (int(v['statement']['x_in']), int(v['statement']['y_out']))
        ok, why, _ = verify(p, proof, st)
        print(f"{path}: valid proof ({len(proof)} B): {'ACCEPT' if ok else 'REJECT ' + why}")
        bad += not ok
        for t in v.get('tampered', []):
            want = tuple(int(x) for x in t['want_statement']) if 'want_statement' in t else None
            ok, why, _ = verify(p, apply_tamper(proof, t), want)
            exp = t['expect_reason_prefix']
            good = (not ok) and why.startswith(exp)
            print(f"   tamper {t['name']:<28} {'REJECT' if not ok else 'ACCEPT'}: {why}   [{'ok' if good else 'UNEXPECTED'}]")
            bad += not good
    print('all as expected' if not bad else f'{bad} unexpected results')
    return bad


if __name__ == '__main__':
    sys.exit(1 if main(sys.argv[1:]) else 0)

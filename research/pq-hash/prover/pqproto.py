"""Byte-level protocol shared by prover and verifier: encodings, Merkle hashing, transcript, proof layout.

Everything here is specified in SERIALIZATION.md; keep the two in sync. Pure Python.
"""
import hashlib

from pqfield import P, Ext
from pqparams import fri_shape, tag, N_OOD


def sha256(b):
    return hashlib.sha256(b).digest()


# ---------------------------------------------------------------- encodings
def enc_base(v):
    return (v % P).to_bytes(8, 'little')


def dec_base(b):
    """8-byte little-endian, unsigned, reduced mod p (no range check: SERIALIZATION.md 1)."""
    return int.from_bytes(b, 'little') % P


def enc_ext(a):
    return b''.join(enc_base(c) for c in a)


def dec_ext(b, e):
    return tuple(dec_base(b[8 * i:8 * i + 8]) for i in range(e))


def digest_to_ext(d, e):
    """E(d): v = LE(d) < 2^256; c_i = (v div p^i) mod p, i < e."""
    v = int.from_bytes(d, 'little')
    out = []
    for _ in range(e):
        out.append(v % P)
        v //= P
    return tuple(out)


def grinding_ok(G, g):
    """top g bits of G (bytes in order, d[0] most significant) are zero."""
    full, rem = divmod(g, 8)
    if any(G[:full]):
        return False
    return rem == 0 or (G[full] >> (8 - rem)) == 0


# ---------------------------------------------------------------- Merkle (SHA-256, truncated to h bytes)
def leaf_hash(tag_byte, leaf, h):
    return sha256(bytes([tag_byte]) + leaf)[:h]


def node_hash(left, right, h):
    return sha256(left + right)[:h]


def multiproof_root(positions, leaf_hashes, depth, h, take_sibling):
    """Canonical deduplicated multiproof (SERIALIZATION.md 4.2).

    positions/leaf_hashes: per query, in query order (duplicates allowed). take_sibling() returns the
    next proof sibling (h bytes). Returns the root, or raises ValueError on a duplicate-leaf mismatch."""
    cur = {}
    for pos, lh in zip(positions, leaf_hashes):
        if pos in cur and cur[pos] != lh:
            raise ValueError('duplicate leaf mismatch')
        cur[pos] = lh
    for _ in range(depth):
        nxt = {}
        keys = sorted(cur)
        i = 0
        while i < len(keys):
            k = keys[i]
            if k % 2 == 0 and i + 1 < len(keys) and keys[i + 1] == k + 1:
                nxt[k >> 1] = node_hash(cur[k], cur[k + 1], h)
                i += 2
                continue
            sib = take_sibling()
            nxt[k >> 1] = node_hash(cur[k], sib, h) if k % 2 == 0 else node_hash(sib, cur[k], h)
            i += 1
        cur = nxt
    assert list(cur) == [0]
    return cur[0]


# ---------------------------------------------------------------- transcript (SERIALIZATION.md 3)
class Transcript:
    """t0 = SHA256(TAG || x_in || y_out); t_{i+1} = SHA256(t_i || message_i); challenges from full digests."""

    def __init__(self, p, x_in, y_out):
        self.p = p
        self.E = Ext(p.e)
        self.t = sha256(tag(p) + enc_base(x_in) + enc_base(y_out))
        self.log = [('t0', self.t.hex())]

    def absorb(self, msg, name):
        self.t = sha256(self.t + msg)
        self.log.append((name, self.t.hex()))

    def challenge(self, label, j=None):
        suffix = label.encode() + (bytes([j]) if j is not None else b'')
        return digest_to_ext(sha256(self.t + suffix), self.p.e)


def query_indices(G, s, n1):
    """idx_i = LE(SHA256(G || u16le i)) mod N1, i < s (with replacement)."""
    return [int.from_bytes(sha256(G + i.to_bytes(2, 'little')), 'little') % n1 for i in range(s)]


# ---------------------------------------------------------------- proof layout (SERIALIZATION.md 4)
def layout(p):
    """Offsets of the public-transcript (PT) fields and the leaves block."""
    N, arities, sizes, trees = fri_shape(p)
    e8 = p.e * 8
    off = {}
    o = 0
    for name, ln in [('x_in', 8), ('y_out', 8), ('root_trace', p.h), ('root_comp', p.h), ('ood', N_OOD * e8)] + \
                    [(f'root_fri{i}', p.h) for i in range(1, len(arities))] + \
                    [('final', (2 ** p.log_df) * e8), ('nonce', 8)]:
        off[name] = (o, ln)
        o += ln
    pt = o
    leaf_total = sum(t['leaf'] for t in trees)
    off['leaves'] = (pt, p.s * leaf_total)
    off['siblings'] = (pt + p.s * leaf_total, None)
    return off, pt, leaf_total, trees


def leaf_offset(p, q, tree_index):
    """Byte offset of query q's leaf for tree `tree_index` in the canonical proof."""
    off, pt, leaf_total, trees = layout(p)
    return pt + q * leaf_total + sum(t['leaf'] for t in trees[:tree_index])

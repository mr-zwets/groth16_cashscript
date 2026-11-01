// Track 9 S1: JS reference for the W-state data structures (DESIGN-T9 sec. 1, 2, 3).
//
// Nullifier set: SHA-256 sparse Merkle tree (SMT) of depth 64.
//   key      K(NF) = little-endian integer of SHA-256("t9NF" || NF)[0..8), NF = 4 lanes u64 LE (32 B, the HEAD push)
//   leaves   absent = Z (32 zero bytes), present = ONE (0x01 || 31 zero bytes)
//   nodes    H(l, r) = Z if l = r = Z, else SHA-256(l || r); depth is fixed, so leaves and nodes cannot be confused
//   path     level 0 is the leaf level; at level l the node is the right child iff bit l of K is 1
//   witness  compressed path: bitmap (8 B, little-endian; bit l set <=> the level-l sibling is not Z) and the non-Z
//            siblings, level 0 first, concatenated (32 B each); a sibling that is sent must not be Z (one encoding);
//            L = the lowest set bit of the bitmap (64 if none), a derived witness item the script checks
// Root history: 16 slots of 32 B (Z = empty), committed as a 4-level SHA-256 Merkle root histRoot (plain
//   SHA-256(l || r) at every level; slot i is leaf i, bit l of i set <=> right child at level l).
// W-state commitment: 0x57 || nfRoot (32) || histRoot (32) || epoch (u32 LE) = 69 B.
//
// The SMT here is an explicit node store (independent of the script's walk); `walk` is the script's algorithm in JS,
// used only to explain mismatches, never as the reference for the agreement test.
import {createHash} from 'node:crypto';

export const Z = Buffer.alloc(32);
export const ONE = Buffer.concat([Buffer.from([1]), Buffer.alloc(31)]);
export const DEPTH = 64;
export const NF_TAG = Buffer.from('t9NF');
export const sha256 = (...parts) => createHash('sha256').update(Buffer.concat(parts.map((p) => Buffer.from(p)))).digest();
export const H = (l, r) => (l.equals(Z) && r.equals(Z) ? Z : sha256(l, r));
const M64 = (1n << 64n) - 1n;
export const lowBit = (bm) => { bm = BigInt(bm); if (bm === 0n) return 64; let l = 0; while (!((bm >> BigInt(l)) & 1n)) l++; return l; };

export const u64le = (x) => { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(x) & M64); return b; };
export const nfBytes = (lanes) => Buffer.concat(lanes.map(u64le));
export const keyBytes = (nf32) => sha256(NF_TAG, nf32).subarray(0, 8);
export const keyOf = (nf32) => keyBytes(nf32).readBigUInt64LE(0);

export class SMT {
  constructor() { this.nodes = new Map(); this.keys = new Set(); }
  node(l, idx) { return this.nodes.get(`${l}:${idx}`) ?? Z; }
  root() { return this.node(DEPTH, 0n); }
  has(K) { return this.keys.has(BigInt(K)); }
  get size() { return this.keys.size; }
  insert(K) {
    K = BigInt(K);
    if (this.keys.has(K)) throw new Error('SMT: key present');
    this.keys.add(K);
    let cur = ONE;
    this.nodes.set(`0:${K}`, cur);
    for (let l = 0; l < DEPTH; l++) {
      const idx = K >> BigInt(l), sib = this.node(l, idx ^ 1n);
      cur = (idx & 1n) ? H(sib, cur) : H(cur, sib);
      this.nodes.set(`${l + 1}:${idx >> 1n}`, cur);
    }
    return cur;
  }
  // the 64 siblings of K's path (level 0 first)
  siblings(K) { K = BigInt(K); return Array.from({length: DEPTH}, (_, l) => this.node(l, (K >> BigInt(l)) ^ 1n)); }
  // compressed path of K (for an absent key: the absence + insert witness)
  path(K) {
    const sibs = this.siblings(K);
    let bm = 0n; const out = [];
    sibs.forEach((s, l) => { if (!s.equals(Z)) { bm |= 1n << BigInt(l); out.push(s); } });
    return {bitmap: u64le(bm), sibs: Buffer.concat(out), count: out.length, L: lowBit(bm)};
  }
}

// The script's walk in JS: (K, bitmap, sibs) -> {old, new} or an error string. Used only for diagnostics.
export function walk(K, bitmap, sibs) {
  K = BigInt(K);
  if (bitmap.length !== 8) return 'bitmap size';
  let B = bitmap.readBigUInt64LE(0), S = Buffer.from(sibs), o = Z, n = ONE;
  for (let l = 0; l < DEPTH; l++) {
    let s = Z;
    if (B & 1n) { if (S.length < 32) return 'short sibs'; s = S.subarray(0, 32); S = S.subarray(32); if (s.equals(Z)) return 'zero sibling sent'; }
    B >>= 1n;
    const d = (K >> BigInt(l)) & 1n;
    n = d ? sha256(s, n) : sha256(n, s);
    o = (o.equals(Z) && s.equals(Z)) ? Z : (d ? sha256(s, o) : sha256(o, s));
  }
  if (S.length) return 'unused sibs';
  return {old: o, new: n};
}

// ---------------------------------------------------------------- root history ring
export const RING = 16, RING_DEPTH = 4;
export function ringRoot(slots) {
  if (slots.length !== RING) throw new Error('ring: 16 slots');
  let lvl = slots.map((s) => Buffer.from(s));
  while (lvl.length > 1) lvl = Array.from({length: lvl.length / 2}, (_, i) => sha256(lvl[2 * i], lvl[2 * i + 1]));
  return lvl[0];
}
export function ringPath(slots, i) {
  let lvl = slots.map((s) => Buffer.from(s)), idx = i; const sibs = [];
  for (let l = 0; l < RING_DEPTH; l++) {
    sibs.push(lvl[idx ^ 1]);
    lvl = Array.from({length: lvl.length / 2}, (_, j) => sha256(lvl[2 * j], lvl[2 * j + 1]));
    idx >>= 1;
  }
  return Buffer.concat(sibs);
}

// ---------------------------------------------------------------- W-state commitment
export const W_PREFIX = 0x57;
export const encodeW = ({nfRoot, histRoot, epoch}) => {
  const e = Buffer.alloc(4); e.writeUInt32LE(epoch);
  return Buffer.concat([Buffer.from([W_PREFIX]), nfRoot, histRoot, e]);
};
export const decodeW = (c) => {
  c = Buffer.from(c);
  if (c.length !== 69 || c[0] !== W_PREFIX) throw new Error('W commitment');
  return {nfRoot: c.subarray(1, 33), histRoot: c.subarray(33, 65), epoch: c.readUInt32LE(65)};
};

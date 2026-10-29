// Parameter set and baked constants for the on-chain verifier, derived from a vector's `params` object
// (SERIALIZATION.md section 2). The TAG is recomputed and checked against params.tag_hex.
import {P, md, powp, invp, rou, sha, leNum, le8, u16, cat, hex, Ext} from './field.mjs';

export function roundConstants() {
  return Array.from({length: 8}, (_, j) => leNum(sha(Buffer.from('verifier.cash/pq-hash/rc'), Uint8Array.of(j))) % P);
}
export function periodicPoly(C) {
  const w8i = invp(rou(8)), i8 = invp(8n);
  return Array.from({length: 8}, (_, k) => md(C.reduce((s, c, j) => s + c * powp(w8i, BigInt(j * k)), 0n) * i8));
}

export function makeParams(pj) {
  const e = pj.e, n = pj.n, N = pj.N, a = pj.arities.map(Number), r = a.length;
  const sizes = pj.layer_sizes.map(Number);
  const D = pj.final_coeffs, s = pj.queries, g = pj.grinding_bits, h = pj.digest_bytes;
  const C = roundConstants(), Pc = periodicPoly(C);
  const K = cat(...C.map(le8), ...Pc.map(le8), le8(rou(n)), le8(rou(N)),
    Uint8Array.from([e, 7, Math.log2(n), Math.log2(N), r, ...a, pj.log_final_degree]), u16(s),
    Uint8Array.from([g, h, pj.m]));
  const TAG = cat(Buffer.from('verifier.cash/pq-hash/v1'), Uint8Array.of(pj.pid), sha(K));
  if (hex(TAG) !== pj.tag_hex) throw new Error('TAG mismatch for ' + pj.name);
  const shift = [7n]; for (const ai of a) shift.push(powp(shift[shift.length - 1], ai));
  const wN = sizes.map((sz) => rou(sz));
  const trees = pj.trees.map((t, i) => ({...t, layer: i < 2 ? 0 : i - 1}));
  // byte offsets of each tree's leaf inside a query's leaf blob (trace, comp, fri1, ...)
  let off = 0; for (const t of trees) { t.off = off; off += t.leaf_bytes; }
  const leafBytes = off;
  const ptBytes = 16 + 2 * h + 5 * 8 * e + (r - 1) * h + D * 8 * e + 8;
  return {
    name: pj.name, pid: pj.pid, e, n, N, a, r, sizes, D, s, g, h, trees, leafBytes, ptBytes, TAG, C, Pc, shift, wN,
    wn: rou(n), F: Ext(e), raw: pj,
  };
}

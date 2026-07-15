// Affine GLV Straus replay for the op-optimized singleton: computes the k-decomposition,
// the witnessed top-bit index nb, and the 32B-LE slope blob consumed by the nb-bounded
// AFFINE vk_x accumulator in groth16_minop.cash (g1DoubleAffine/g1AddAffine slopes in exact
// execution order: per iteration [double-slope?][add-slope?], then the final +IC0 chord).
// The returned vkx MUST equal the pairing-side vk_x — callers assert this (fail-closed).
import { bn254 } from '@noble/curves/bn254.js';

const G = await import('../../chunked/pairing/gen_vkx_glv.mjs');
const Fp = bn254.fields.Fp;
const P = Fp.ORDER;

// parse the baked 15-entry subset-sum table (32-byte-LE x,y pairs) back into points
const tableHex = G.GLV_TABLE_HEX.slice(2);
const le = (h) => { let v = 0n; for (let i = h.length - 2; i >= 0; i -= 2) v = (v << 8n) | BigInt(parseInt(h.slice(i, i + 2), 16)); return v; };
const TABLE = Array.from({ length: 15 }, (_, k) => [le(tableHex.slice(k * 128, k * 128 + 64)), le(tableHex.slice(k * 128 + 64, k * 128 + 128))]);
const IC0 = G.GLV_IC0.map((x) => ((x % P) + P) % P);
const le32 = (v) => { v = ((v % P) + P) % P; let s = ''; for (let b = 0; b < 32; b++) s += Number((v >> BigInt(8 * b)) & 0xffn).toString(16).padStart(2, '0'); return s; };

export function glvAffineWitness(in0, in1) {
  // Exhaustively choose congruent bounded representatives jointly, minimizing the union
  // popcount processed by the four-scalar Straus loop. This changes only the witness: the
  // contract still checks both GLV congruences and every affine slope.
  const [k10, k20, k11, k21] = G.glvDecomposeJoint(BigInt(in0), BigInt(in1));
  const nb = Math.max(0, ...[k10, k20, k11, k21].map((k) => (k === 0n ? 0 : k.toString(2).length - 1)));
  const slopes = [];
  let acc = null;
  const dbl = (pt) => {
    const m = Fp.div(Fp.mul(Fp.sqr(pt[0]), 3n), Fp.mul(pt[1], 2n));
    slopes.push(m);
    const nx = Fp.sub(Fp.sqr(m), Fp.mul(pt[0], 2n));
    return [nx, Fp.sub(Fp.mul(m, Fp.sub(pt[0], nx)), pt[1])];
  };
  const add = (pt, q) => {
    const m = Fp.div(Fp.sub(q[1], pt[1]), Fp.sub(q[0], pt[0]));
    slopes.push(m);
    const nx = Fp.sub(Fp.sub(Fp.sqr(m), pt[0]), q[0]);
    return [nx, Fp.sub(Fp.mul(m, Fp.sub(pt[0], nx)), pt[1])];
  };
  for (let gk = 0; gk <= nb; gk++) {
    const gidx = BigInt(nb - gk);
    if (acc !== null) acc = dbl(acc);
    const idx = Number((k10 >> gidx) & 1n) + 2 * Number((k20 >> gidx) & 1n)
      + 4 * Number((k11 >> gidx) & 1n) + 8 * Number((k21 >> gidx) & 1n);
    if (idx !== 0) {
      const e = TABLE[idx - 1];
      acc = acc === null ? [e[0], e[1]] : add(acc, e);
    }
  }
  const vkx = acc === null ? [IC0[0], IC0[1]] : add(acc, IC0); // final chord; result IS vk_x
  return { k10, k20, k11, k21, nb: BigInt(nb), blobHex: slopes.map(le32).join(''), vkx };
}

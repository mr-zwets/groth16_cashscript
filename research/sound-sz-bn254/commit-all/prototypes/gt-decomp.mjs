// 4-dimensional decomposition n = k0 + k1 p + k2 p^2 + k3 p^3 (mod r) used by the "vk_x in GT"
// option: e(vk_x, gamma) == G0 * prod_i prod_j phi^j(G_i)^{k_ij} (mod ker of the final exponentiation).
// Finds a reduced basis of L = {k in Z^4 : sum k_j p^j == 0 mod r} with LLL, then Babai rounding.
import {pathToFileURL} from 'node:url';
import {bn254} from '@noble/curves/bn254.js';
import {createHash} from 'node:crypto';
const p = bn254.fields.Fp.ORDER, r = bn254.fields.Fr.ORDER;
const mod = (a, m) => ((a % m) + m) % m;
const pj = [1n, mod(p, r), mod(p * p, r), mod(p ** 3n, r)];
// lattice basis rows: (r,0,0,0), (-pj[1],1,0,0), (-pj[2],0,1,0), (-pj[3],0,0,1)
let Bm = [[r, 0n, 0n, 0n], [mod(-pj[1], r), 1n, 0n, 0n], [mod(-pj[2], r), 0n, 1n, 0n], [mod(-pj[3], r), 0n, 0n, 1n]];
// exact rational LLL (delta 3/4), tiny dimension
const dot = (a, b) => a.reduce((s, x, i) => s + x * b[i], 0n);
function lll(B) {
  B = B.map((x) => [...x]);
  const n = B.length;
  const gs = () => { // Gram-Schmidt with rationals as [num, den]
    const Bs = [], mu = Array.from({length: n}, () => Array(n).fill(null)), Bn = [];
    for (let i = 0; i < n; i++) {
      let v = B[i].map((x) => [x, 1n]);
      for (let j = 0; j < i; j++) {
        const num = dot(B[i], Bs[j].num), den = Bs[j].den; // <b_i, b*_j> = num/den
        const m = [num * Bn[j][1], den * Bn[j][0]]; // mu = <b_i,b*_j>/|b*_j|^2
        mu[i][j] = m;
        v = v.map((x, k) => { const a = [m[0] * Bs[j].num[k], m[1] * Bs[j].den]; return [x[0] * a[1] - a[0] * x[1], x[1] * a[1]]; });
      }
      // put v over common denominator
      const den = v.reduce((d, x) => (d * x[1]) / gcd(d, x[1]), 1n);
      const num = v.map((x) => (x[0] * den) / x[1]);
      Bs.push({num, den}); Bn.push([dot(num, num), den * den]);
    }
    return {mu, Bn};
  };
  let k = 1;
  while (k < n) {
    for (let j = k - 1; j >= 0; j--) {
      const {mu} = gs(); const m = mu[k][j]; const q = roundDiv(m[0], m[1]);
      if (q) B[k] = B[k].map((x, i) => x - q * B[j][i]);
    }
    const {mu, Bn} = gs();
    const m = mu[k][k - 1];
    // Lovasz: |b*_k|^2 >= (3/4 - mu^2)|b*_{k-1}|^2
    const lhs = [Bn[k][0], Bn[k][1]];
    const rhsF = [3n * m[1] * m[1] - 4n * m[0] * m[0], 4n * m[1] * m[1]];
    const rhs = [rhsF[0] * Bn[k - 1][0], rhsF[1] * Bn[k - 1][1]];
    if (lhs[0] * rhs[1] >= rhs[0] * lhs[1]) k++; else { [B[k], B[k - 1]] = [B[k - 1], B[k]]; k = Math.max(k - 1, 1); }
  }
  return B;
}
function gcd(a, b) { a = a < 0n ? -a : a; b = b < 0n ? -b : b; while (b) [a, b] = [b, a % b]; return a; }
function roundDiv(a, b) { if (b < 0n) { a = -a; b = -b; } const q = a >= 0n ? (2n * a + b) / (2n * b) : -((-2n * a + b) / (2n * b)); return q; }
const L = lll(Bm);
for (const row of L) if (mod(row.reduce((s, x, i) => s + x * pj[i], 0n), r) !== 0n) throw new Error('not in lattice');
// Babai: solve k = (n,0,0,0) - round((n,0,0,0) B^-1) B ; use exact 4x4 inverse via adjugate (rationals)
function det3(m) { return m[0][0] * (m[1][1] * m[2][2] - m[1][2] * m[2][1]) - m[0][1] * (m[1][0] * m[2][2] - m[1][2] * m[2][0]) + m[0][2] * (m[1][0] * m[2][1] - m[1][1] * m[2][0]); }
function minor(m, i, j) { return m.filter((_, a) => a !== i).map((row) => row.filter((_, b) => b !== j)); }
const det = L[0].reduce((s, x, j) => s + (j % 2 ? -1n : 1n) * x * det3(minor(L, 0, j)), 0n);
const adj = Array.from({length: 4}, (_, i) => Array.from({length: 4}, (_, j) => ((i + j) % 2 ? -1n : 1n) * det3(minor(L, j, i))));
export function decompose(n) {
  // coordinates c = (n,0,0,0) * L^-1 = n * adj[0][*] / det
  const c = [0, 1, 2, 3].map((j) => roundDiv(n * adj[0][j], det));
  const k = [n, 0n, 0n, 0n].map((v, i) => v - c.reduce((s, cj, j) => s + cj * L[j][i], 0n));
  if (mod(k.reduce((s, x, i) => s + x * pj[i], 0n) - n, r) !== 0n) throw new Error('bad decomposition');
  return k;
}
if (import.meta.url === pathToFileURL(process.argv[1]).href) {
console.log('reduced basis (bits):', L.map((row) => row.map((x) => (x < 0n ? -x : x).toString(2).length)));
const bits = (x) => (x < 0n ? -x : x).toString(2).length;
let maxBits = 0; const hist = {};
for (let i = 0; i < 20000; i++) {
  const n = mod(BigInt('0x' + createHash('sha256').update('n' + i).digest('hex')), r);
  const k = decompose(n); const b = Math.max(...k.map(bits)); maxBits = Math.max(maxBits, b); hist[b] = (hist[b] ?? 0) + 1;
}
console.log('max |k_j| bits over 20000 random n:', maxBits, 'histogram of max bits', hist);
// popcount of 8 scalars per bit position (two public inputs)
const pc = Array(66).fill(0); let tot = 0;
for (let i = 0; i < 2000; i++) {
  const ks = [0, 1].flatMap((t) => decompose(mod(BigInt('0x' + createHash('sha256').update('m' + i + ':' + t).digest('hex')), r)));
  for (let b = 0; b < 66; b++) { const c = ks.filter((k) => ((k < 0n ? -k : k) >> BigInt(b)) & 1n).length; pc[b] += c; tot += c; }
}
console.log('avg set bits per event (8 scalars, binary):', (tot / 2000 / 65).toFixed(2));
}

// n_q (structural quotient length) over random statements, from the nibble bits only (no proving needed):
// n_q = nqOf(bits of N at each GLS position, affine/projective schedule). Also the forced extremes.
import {r, mod, glsDecompose, GLS_BITS, GLS_OFFSET} from './math.mjs';
import {nqOf} from './protocol.mjs';
const E_P = Number(process.env.E_P ?? 52); const affOf = (e) => e < E_P;
const nibbles = (n) => { const u = glsDecompose(mod(n, r)).map((v) => v + GLS_OFFSET); return Array.from({length: GLS_BITS}, (_, g) => u.reduce((s, v, i) => s | (Number((v >> BigInt(63 - g)) & 1n) << i), 0)); };
const nqFor = (n0, n1) => { const N = [nibbles(n0), nibbles(n1)]; const bits = (g) => [0, 1].reduce((s, k) => s + [0, 1, 2, 3].filter((i) => (N[k][g] >> i) & 1).length, 0); return nqOf(bits, affOf); };
let seed = 987654321n; const rnd = () => (seed = (seed * 6364136223846793005n + 1442695040888963407n) % (1n << 64n), seed);
const big = () => mod(rnd() * rnd() * rnd() * rnd(), r);
const hist = {}; const samples = Number(process.env.N ?? 20000); let mn = 1e9, mx = 0;
for (let s = 0; s < samples; s++) { const q = nqFor(big(), big()); hist[q] = (hist[q] ?? 0) + 1; mn = Math.min(mn, q); mx = Math.max(mx, q); }
const qs = Object.keys(hist).map(Number).sort((a, b) => a - b); let acc = 0; const pct = (x) => { acc = 0; for (const q of qs) { acc += hist[q]; if (acc >= x * samples) return q; } };
console.log('random statements', samples, 'E_p', E_P, 'n_q min', mn, 'p1', pct(0.01), 'median', pct(0.5), 'p99', pct(0.99), 'max', mx);
console.log('fixture0 (123,456)', nqFor(123n, 456n), ' small (1,2)', nqFor(1n, 2n), ' (0,0)', nqFor(0n, 0n), ' (r-1,r-1)', nqFor(r - 1n, r - 1n));
console.log('all-zero nibbles', nqOf(() => 0, affOf), ' all-15', nqOf(() => 8, affOf));

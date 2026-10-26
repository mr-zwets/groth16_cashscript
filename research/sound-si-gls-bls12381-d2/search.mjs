// Chunking search: for each Q cap (worst-case odd words), the partitions with the fewest committed states
// whose every chunk meets the cap (exact DP over chunk boundaries), then the honest n_q distribution over
// random statements (GLS digit bits of random n < r), and the byte/op trade-off.
//   node search.mjs [OPB=boundary op] [OPQ=op per Q word]
import {NE, BITS, r, glsDigits} from './math.mjs';
import {layoutFor, nqFor, nqMax, chunkDegP} from './protocol.mjs';
const OPB = Number(process.env.OPB ?? 100000), OPQ = Number(process.env.OPQ ?? 8000), NS = Number(process.env.NSAMP ?? 3000);
// random statements -> per-event GLS bit counts
let seed = 12345n; const rnd = () => { seed = (seed * 6364136223846793005n + 1442695040888963407n) % (1n << 128n); return seed; };
const samples = Array.from({length: NS}, () => { const ns = [rnd() * rnd() % r, rnd() * rnd() % r]; const ds = ns.map(glsDigits);
  return Array.from({length: 64}, (_, e1) => ds.reduce((s, d) => s + d.filter((v) => (v >> BigInt(63 - e1)) & 1n).length, 0)); });
// worst-case D degree of chunk [a, b] (inclusive; a = -1 is the init step), last chunk adds Rconst and the W degree 11
const L1 = {chunks: [], NSTATES: -1};
const worstNq = (a, b, last) => { const L = {chunks: [[a, b]], NSTATES: last ? 0 : 1}; return nqFor(L, () => 8); };
const res = [];
for (let cap = 40; cap <= 520; cap++) {
  // DP over items t = 0..64 (item t = event t - 1): best[t] = min states covering items [0, t)
  const INF = 1e9; const best = Array(65).fill(INF), from = Array(65).fill(-1); best[0] = 0;
  for (let t = 0; t < 64; t++) { if (best[t] >= INF) continue;
    for (let u = t + 1; u <= Math.min(64, t + 6); u++) { const last = u === 64; if (worstNq(t - 1, u - 2, last) > cap) break;
      const c = best[t] + (last ? 0 : 1); if (c < best[u]) { best[u] = c; from[u] = t; } } }
  if (best[64] >= INF) continue;
  const bounds = []; for (let u = 64; u > 0; u = from[u]) if (u !== 64) bounds.unshift(u - 2);
  const L = layoutFor(bounds); if (res.length && res.at(-1).NSTATES === L.NSTATES) continue;
  const nqs = samples.map((s) => nqFor(L, (e) => s[e + 1])).sort((x, y) => x - y);
  const mean = nqs.reduce((a, b) => a + b, 0) / nqs.length;
  res.push({cap: nqMax(L), NSTATES: L.NSTATES, nqMean: +mean.toFixed(1), nqP50: nqs[nqs.length >> 1], nqP99: nqs[Math.floor(nqs.length * 0.99)], nqMaxSeen: nqs.at(-1),
    bytes: Math.round(288 * L.NSTATES + 48 * mean), opEq: Math.round((OPB * L.NSTATES + OPQ * mean) / 800), bounds: bounds.join(',')});
}
console.table(res.map(({bounds, ...x}) => ({...x, total: x.bytes + x.opEq})));
for (const x of res) console.log(x.NSTATES, x.cap, x.bounds);
const bestR = res.reduce((a, b) => (a.bytes + a.opEq <= b.bytes + b.opEq ? a : b)); console.log('best', bestR);

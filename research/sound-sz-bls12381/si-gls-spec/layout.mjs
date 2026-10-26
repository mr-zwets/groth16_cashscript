// Chunk-layout search for BLS SI-GLS. Chunk degrees are exact functions of the event structure (polynomial degrees add):
//   event factor degree f(e) = lB(e) + 8 + [addition: lB(e) + 8 + 6] + 6 * (GLS bits applied at e),  lB = 8 affine / 9 projective
//   chunk: start degree 6 (a state; chunk 0: S_c(-X) times the bit-63 factors), deg <- 2 deg + f(e) per event;
//   + 6 where Rconst' sits (end of one chosen chunk), D = P(X)S'(-X) - P(-X)S'(X) has degree deg P + 6 (+11 for the
//   terminal W = Frob(S_c)) when that is odd, else less; n_q = (max deg D - 11) / 2.
// Greedy partition (longest chunk under a degree threshold) is optimal for "fewest chunks with max degree <= T".
// Score proxy in the balanced (op = 95% budget) regime: 1 state ~ 201 B, 1 quotient word ~ 31.5 B (see README).
//   node layout.mjs [--eaff=14]
import {BITS, NE, glsDigits, r} from './blsmath.mjs';
const arg = (k, d) => { const a = process.argv.find((x) => x.startsWith(`--${k}=`)); return a ? a.split('=')[1] : d; };
const pop = (n) => n.toString(2).split('').filter((c) => c === '1').length;
export const nibbles = (inputs) => inputs.map((n) => { const a = glsDigits(n); return Array.from({length: 64}, (_, j) => a.reduce((s, ai, i) => s | (Number((ai >> BigInt(63 - j)) & 1n) << i), 0)); });
export const eventDegrees = (nib, eaff) => Array.from({length: NE}, (_, e) => { const lB = e < eaff ? 8 : 9; return lB + 8 + (BITS[e] ? lB + 8 + 6 : 0) + 6 * (pop(nib[0][e + 1]) + pop(nib[1][e + 1])); });
const oddDeg = (d) => (d % 2 ? d : d - 1);
// degrees of D for a layout (array of chunk lengths), with Rconst' at the end of chunk rc (default: the last)
export function chunkDegrees(layout, f, init, rc = layout.length - 1) {
  let e = 0; return layout.map((len, k) => { let d = k === 0 ? 6 + 6 * init : 6; for (let j = 0; j < len; j++, e++) d = 2 * d + f[e]; if (k === rc) d += 6; return oddDeg(d + (k === layout.length - 1 ? 11 : 6)); });
}
export function greedy(f, init, T, maxLen = 4) { // chunks with deg D <= T (Rconst' placed afterwards), or null
  const out = []; let e = 0;
  while (e < NE) {
    let best = 0; for (let len = 1; len <= maxLen && e + len <= NE; len++) { let d = out.length === 0 ? 6 + 6 * init : 6; for (let j = 0; j < len; j++) d = 2 * d + f[e + j]; if (oddDeg(d + (e + len === NE ? 11 : 6)) <= T) best = len; }
    if (!best) return null; out.push(best); e += best;
  }
  return out;
}
export function bestRc(layout, f, init) { let best = null; for (let rc = 0; rc < layout.length; rc++) { const m = Math.max(...chunkDegrees(layout, f, init, rc)); if (!best || m < best.m) best = {rc, m}; } return best; }
const nq = (m) => (m - 11) / 2;

if (import.meta.url === `file://${process.argv[1]}`) {
  const eaff = Number(arg('eaff', '14'));
  const stm = {committed: [123n, 456n], zero: [0n, 0n], dense: [40792793307691160132937706698213704133054528069427933762012433436987942497952n, 20976222017425405296340351928930328963278634447870202382235661951061637561134n], max: [r - 1n, r - 1n]};
  const N = Object.fromEntries(Object.entries(stm).map(([k, v]) => [k, nibbles(v)]));
  const F = Object.fromEntries(Object.entries(N).map(([k, nb]) => [k, eventDegrees(nb, eaff)]));
  const INIT = Object.fromEntries(Object.entries(N).map(([k, nb]) => [k, pop(nb[0][0]) + pop(nb[1][0])]));
  const worstF = Array.from({length: NE}, (_, e) => { const lB = e < eaff ? 8 : 9; return lB + 8 + (BITS[e] ? lB + 8 + 6 : 0) + 48; });
  const evalLayout = (name, L) => {
    const rcw = bestRc(L, worstF, 8); const rcC = bestRc(L, F.committed, INIT.committed);
    const rc = rcC.rc; // the script fixes one placement; choose it for the primary statement and report the cap with it
    const row = {states: L.length - 1, rc, cap: nq(Math.max(...chunkDegrees(L, worstF, 8, rc)))};
    for (const k of Object.keys(stm)) row[k] = nq(Math.max(...chunkDegrees(L, F[k], INIT[k], rc)));
    row.proxyPrimary = Math.round(201 * row.states + 31.5 * row.committed); row.proxyDense = Math.round(201 * row.states + 31.5 * row.dense);
    console.log(name.padEnd(28), JSON.stringify(row), rcw.rc !== rc ? `(cap-optimal rc ${rcw.rc}: ${nq(rcw.m)})` : '');
    return row;
  };
  const pairs = (s) => { const o = []; for (let e = s; e < NE; e += 2) o.push(Math.min(2, NE - e)); return o; };
  evalLayout('u2 [0][1,2]...', [1, ...pairs(1)]);
  evalLayout('a2 adds-second', [1, 2, 1, 2, 1, ...pairs(7)]);
  // greedy against the worst case (robust) and against the committed statement (bench-tuned), scanning T
  for (const [tag, ff, init] of [['robust(worst)', worstF, 8], ['dense', F.dense, INIT.dense], ['committed', F.committed, INIT.committed]]) {
    let best = null;
    for (let T = 41; T <= 700; T += 2) { const L = greedy(ff, init, T); if (!L) continue; const row = {L, states: L.length - 1, nqT: nq(T)}; const c = 201 * row.states + 31.5 * row.nqT; if (!best || c < best.c) best = {c, row}; }
    evalLayout(`greedy ${tag} (${best.row.L.length} ch)`, best.row.L); console.log('   ', JSON.stringify(best.row.L));
  }
}

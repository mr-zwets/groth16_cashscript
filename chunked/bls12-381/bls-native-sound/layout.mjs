// Layout search: chunk ownership (CUTS) and the placement of the movable bytes (constant blocks K_i, the program
// blob) so that every input has its liveness margin at the worst case, within the 10,000-byte unlocking cap, with the
// fewest total bytes. Op model from measure.mjs (VM measurements): per-event costs (dense nibbles for the Miller
// inputs, the forced n_q = N_MIN witness for input 0), per-role prefix and suffix; reads of a relocated piece are
// charged READ_PER_B * U_host + READ_FIX.
//   MARGIN=0.065 node layout.mjs meas.json [top]      prints the best layouts and an NATIVE_CUTS / NATIVE_PLACE pair
import {readFileSync} from 'node:fs';
import {CHUNK_START, CHUNK_END, K_IDS, NSTATES, STMT_SIZE, NQ_MAX, N_MIN, W, hdrLen} from './protocol.mjs';
const meas = JSON.parse(readFileSync(process.argv[2]));
const MARGIN = Number(process.env.MARGIN ?? 0.065), CAP = 10000 - Number(process.env.CAP_SLACK ?? 0), READ_PER_B = 2.2, READ_FIX = 2500, RLEN = meas.R + hdrLen(meas.R);
const BLOB = meas.blob;
const isAddE = (e) => [0, 2, 5, 14, 46].includes(e);
// per-event worst op: dense witness for every event (from whichever input ran it), forced witness inside input 0
const evDense = [], evForced = [];
const WD = process.env.LAYOUT_WIT ?? 'dense', WF = process.env.LAYOUT_WIT ?? Object.keys(meas.wit).find((k) => k.startsWith('forced'));
for (const x of meas.wit[WD].inputs) for (const v of x.events) evDense[v.e] = v.op;
for (const x of meas.wit[WF].inputs) for (const v of x.events) evForced[v.e] = v.op;
const d = meas.wit[WD].inputs, f = meas.wit[WF];
const PRE_W = Math.max(d[1].prefix, d[2].prefix, d[3].prefix), SUF_W = d[1].suffix, SUF_T = d[3].suffix, PRE_H = f.inputs[0].prefix, NQ_H = f.nq;
const roleOf = (cuts, i) => { const c0 = cuts[i], c1 = cuts[i + 1]; const e0 = CHUNK_START[c0], e1 = CHUNK_END[c1 - 1]; const events = []; for (let e = e0; e <= e1; e++) events.push(e);
  const ns = []; for (let k = c0; k < c1; k++) if (k < NSTATES) ns.push(k); const nsl = events.reduce((s, e) => s + 1 + (isAddE(e) ? 1 : 0), 0);
  return {e0, e1, events, G: (i === 0 ? STMT_SIZE : 0) + 288 * ns.length + 96 * nsl, K: 192 + 96 * nsl, CL: i === 3 ? W : 5 * W}; };
const push = (n) => hdrLen(n) + n;
function evalCuts(cuts) {
  const ro = [0, 1, 2, 3].map((i) => roleOf(cuts, i));
  const op = ro.map((r, i) => (i === 0 ? PRE_H + r.events.reduce((s, e) => s + evForced[e], 0) + SUF_W : PRE_W + r.events.reduce((s, e) => s + evDense[e], 0) + (i === 3 ? SUF_T : SUF_W)));
  const fixedB = ro.map((r, i) => push(r.G) + push(r.CL) + RLEN + (i === 0 ? push(2 * W) + push(48 * N_MIN) : 0));
  const capB = ro.map((r, i) => CAP - (i === 0 ? 48 * (NQ_MAX - N_MIN) : 0));   // max unlocking (input 0: at n_q = NQ_MAX)
  return {ro, op, fixedB, capB};
}
// placement of the movable bytes: blob parts (hosts 1..3, at most BLOB_PARTS) and K pieces (at most 2 per block)
const needOf = (o) => Math.ceil(o / (800 * (1 - MARGIN))) - 41;
function place(L, blobHosts) {
  const {ro, fixedB, capB} = L; const op = L.op.slice(); const n = 4;
  const U = fixedB.slice(); const pieces = ro.map(() => []); const blobParts = [];
  const room = (i) => capB[i] - U[i] - 3;
  // the blob parts: fill the chosen hosts' deficits in order, the remainder to the last host
  let left = BLOB;
  blobHosts.forEach((h, j) => {
    const last = j === blobHosts.length - 1; const def = needOf(op[h]) - U[h] - 3;
    const take = last ? left : Math.max(200, Math.min(left - 200, def, room(h)));
    if (take > room(h)) { blobParts.push(null); return; }
    blobParts.push([h, take]); U[h] += take + 3; left -= take;
  });
  if (blobParts.some((x) => x === null)) return null;
  // every input reads every blob part (the loader in R)
  for (let i = 0; i < n; i++) for (const [h] of blobParts) op[i] += READ_PER_B * U[h];
  // K pieces: own block first up to the own deficit, then other deficits, then anywhere with room (own first)
  const kl = ro.map((r) => r.K);
  for (let i = 0; i < n; i++) { const def = needOf(op[i]) - U[i] - 3; const take = Math.min(kl[i], Math.max(0, def), room(i)); if (take >= 48) { pieces[i].push([i, take]); U[i] += take + 3; kl[i] -= take; } }
  for (let j = 0; j < n; j++) while (kl[j] > 0) {
    let best = -1, bs = -Infinity;
    for (let i = 0; i < n; i++) { if (room(i) < 48 || pieces[j].some(([h]) => h === i)) continue; const def = needOf(op[i]) - U[i] - 3; const sc = (def > 0 ? 1e6 + def : 0) + (i === j ? 5e5 : 0) + room(i) / 1e3; if (sc > bs) { bs = sc; best = i; } }
    if (best < 0 || pieces[j].length >= 2) return null;
    const def = needOf(op[best]) - U[best] - 3; let take = Math.min(kl[j], room(best)); if (def > 0 && pieces[j].length === 0 && kl[j] - def >= 48) take = Math.min(take, Math.max(48, def));
    if (kl[j] - take > 0 && kl[j] - take < 48) take = kl[j] - 48;
    pieces[j].push([best, take]); U[best] += take + 3; kl[j] -= take;
    if (best !== j) op[j] += READ_FIX + READ_PER_B * U[best];
  }
  // code growth: every relocated piece is a read in its owner's role body, every filler a drop
  const need = op.map(needOf); const filler = U.map((u, i) => Math.max(0, need[i] - u));
  const extra = 18 * pieces.reduce((s, pc, j) => s + pc.filter(([h]) => h !== j).length, 0) + 6 * filler.filter((x) => x > 0).length;
  U[blobHosts.at(-1)] += extra; blobParts.at(-1)[1] += extra;
  for (let i = 0; i < n; i++) if (filler[i]) filler[i] = Math.max(0, need[i] - U[i]) + 3;
  if (U.some((u, i) => u + filler[i] > capB[i])) return null;
  const total = U.reduce((s, u, i) => s + u + filler[i], 0);
  return {U, filler, total, pieces, blobParts, op, need};
}
const res = [];
const HOSTSETS = [[1], [2], [3], [1, 2], [1, 3], [2, 3], [2, 1], [3, 1], [3, 2]].filter((h) => h.length <= Number(process.env.BLOB_PARTS ?? 2));
for (let c1 = 3; c1 <= 9; c1++) for (let c2 = c1 + 4; c2 <= 30; c2++) for (let c3 = c2 + 3; c3 <= 32; c3++) for (const hs of HOSTSETS) {
  const L = evalCuts([0, c1, c2, c3, K_IDS]); const P = place(L, hs); if (!P) continue;
  res.push({cuts: [0, c1, c2, c3, K_IDS], hs, ...P});
}
res.sort((a, b) => a.total - b.total);
for (const x of res.slice(0, Number(process.argv[3] ?? 8))) {
  console.log(`total ${x.total} (score ${x.total + 332}) cuts ${x.cuts} blob ${JSON.stringify(x.blobParts)} U ${x.U.join(',')} filler ${x.filler.join(',')} need ${x.need.join(',')} op ${x.op.map((o) => (o / 1e6).toFixed(2)).join(',')}`);
  console.log(`   NATIVE_CUTS=${x.cuts.join(',')} NATIVE_PLACE='${JSON.stringify({blob: x.blobParts.map(([h]) => h), blobLens: x.blobParts.slice(0, -1).map(([, l]) => l), K: x.pieces, fill: x.filler})}'`);
}
if (process.env.DBG) { const L = evalCuts(process.env.DBG.split(',').map(Number)); console.log(JSON.stringify({op: L.op, fixedB: L.fixedB, need: L.op.map(needOf), K: L.ro.map((r) => r.K)})); console.log(place(L, JSON.parse(process.env.HS ?? '[3]'))); }

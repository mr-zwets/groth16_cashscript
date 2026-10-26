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
function evalCuts(cuts, carrier) {
  const ro = [0, 1, 2, 3].map((i) => roleOf(cuts, i));
  const op = ro.map((r, i) => (i === 0 ? PRE_H + r.events.reduce((s, e) => s + evForced[e], 0) + SUF_W : PRE_W + r.events.reduce((s, e) => s + evDense[e], 0) + (i === 3 ? SUF_T : SUF_W)));
  const fixedB = ro.map((r, i) => push(r.G) + push(r.CL) + RLEN + (i === 0 ? push(2 * W) + push(48 * N_MIN) : 0) + (i === carrier ? push(BLOB) : 0));
  const need = op.map((o) => Math.ceil(o / (800 * (1 - MARGIN))) - 41);
  const cap = fixedB.map((b, i) => CAP - b - (i === 0 ? 48 * (NQ_MAX - N_MIN) : 0)); // room for hosted pieces
  return {ro, op, fixedB, need, cap, carrier};
}
// placement: own K first (as much as fits), then cover each deficit with pieces of surplus K bytes; filler if short
function place(L) {
  const {ro, op, fixedB, need, cap} = L; const n = 4; const hosted = Array(n).fill(0); const pieces = ro.map(() => []);
  const ks = ro.map((r) => r.K); const left = ks.slice();
  // 1. inputs whose own block is needed for their deficit keep it (or the part that fits)
  for (let i = 0; i < n; i++) { const room = cap[i] - hosted[i]; const want = Math.max(0, need[i] - fixedB[i] - hosted[i]); const take = Math.min(left[i], room, Math.max(want, 0)); if (take > 0) { pieces[i].push([i, take]); hosted[i] += take + 3; left[i] -= take; } }
  // 2. remaining K bytes go to inputs with a deficit (cost: a read for the owner), then anywhere with room
  for (let pass = 0; pass < 2; pass++) for (let j = 0; j < n; j++) {
    while (left[j] > 0) {
      let best = -1, bestScore = -Infinity;
      for (let i = 0; i < n; i++) { const room = cap[i] - hosted[i] - 3; if (room < 48) continue; const def = need[i] - fixedB[i] - hosted[i]; const sc = pass === 0 ? def : room; if (pass === 0 && def <= 0) continue; if (sc > bestScore) { bestScore = sc; best = i; } }
      if (best < 0) { if (pass === 0) break; return null; }
      const room = cap[best] - hosted[best] - 3; const def = need[best] - fixedB[best] - hosted[best];
      let take = Math.min(left[j], room, pass === 0 ? Math.max(48, def) : left[j]); if (left[j] - take > 0 && left[j] - take < 48) take = left[j] - 48; if (take < 48) take = Math.min(left[j], room);
      pieces[j].push([best, take]); hosted[best] += take + 3; left[j] -= take;
      if (best !== j) op[j] += READ_FIX + READ_PER_B * (fixedB[best] + hosted[best]);
    }
  }
  const need2 = op.map((o) => Math.ceil(o / (800 * (1 - MARGIN))) - 41);
  const U = fixedB.map((b, i) => b + hosted[i]); const filler = U.map((u, i) => Math.max(0, need2[i] - u));
  // the blob grows with every relocated piece (a read in the owner's role code) and every filler push (a drop)
  const extra = 18 * pieces.reduce((s, pc, j) => s + pc.filter(([h]) => h !== j).length, 0) + 6 * filler.filter((x) => x > 0).length;
  if (L.carrier !== undefined) U[L.carrier] += extra;
  if (U.some((u, i) => u + filler[i] + (filler[i] ? 3 : 0) > CAP - (i === 0 ? 48 * (NQ_MAX - N_MIN) : 0))) return null;
  const total = U.reduce((s, u, i) => s + u + filler[i] + (filler[i] ? 3 : 0), 0);
  return {U, filler, total, pieces, op, need: need2, maxPieces: Math.max(...pieces.map((p) => p.length))};
}
const res = [];
for (let c1 = 3; c1 <= 9; c1++) for (let c2 = c1 + 4; c2 <= 30; c2++) for (let c3 = c2 + 3; c3 <= 32; c3++) for (const carrier of [1, 2, 3]) {
  const L = evalCuts([0, c1, c2, c3, K_IDS], carrier); const P = place(L); if (!P) continue; if (P.maxPieces > 2) continue;
  res.push({cuts: [0, c1, c2, c3, K_IDS], carrier, ...P});
}
res.sort((a, b) => a.total - b.total);
for (const x of res.slice(0, Number(process.argv[3] ?? 8))) {
  console.log(`total ${x.total} (+${4 * 78 + 20} = score ${x.total + 332}) cuts ${x.cuts} carrier ${x.carrier} U ${x.U.join(',')} filler ${x.filler.join(',')} need ${x.need.join(',')} op ${x.op.map((o) => (o / 1e6).toFixed(2)).join(',')}`);
  console.log(`   NATIVE_CUTS=${x.cuts.join(',')} NATIVE_PLACE='${JSON.stringify({blob: x.carrier, K: x.pieces, fill: x.filler.map((v) => (v ? v + Number(process.env.FILL_SLACK ?? 40) : 0))})}'`);
}
if (process.env.DBG) { const L = evalCuts(process.env.DBG.split(',').map(Number), 3); console.log(JSON.stringify({op: L.op, fixedB: L.fixedB, need: L.need, cap: L.cap, K: L.ro.map((r) => r.K)})); console.log(place(L)); }

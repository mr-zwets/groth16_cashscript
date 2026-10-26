// Layout model for MSI-GLS (design 2): choose the event split and the data placement that maximise the
// minimum per-input op-cost margin under bch-2026 (standard mode), from MEASURED costs:
//   - per-event op cost: max over 5 witnesses of the reviewed SI-GLS program (prof-events.mjs -> event-costs.json)
//   - pre-loop / terminal / quotient sections: SI-GLS profile (prof-*.json)
//   - glue (dispatcher, introspection transcript, handovers): proto-tx.mjs in a real n-input bch-2026 tx
// Bytes: K_i code from the SI-GLS section byte counts (build.json) plus the measured glue code.
//   node layout.mjs [n] [safety=0.01]
import {readFileSync} from 'node:fs';

const EV = JSON.parse(readFileSync(new URL('./event-costs.json', import.meta.url))).max;
import {DIGITS as DIG} from '../../chunked/bn254/sound-si-gls/math.mjs';
const n = Number(process.argv[2] ?? 4), SAFETY = Number(process.argv[3] ?? 0.01);
const ACC_PER_EVENT = 2500;             // GLS accumulator work removed from the loop (moved to the last input)
const T_DATA = 6978 + 4224;             // WS + fixed-width WQ (132 words)
const H = 224, DELTA = 6 + 3 + n * 4 + 1 + 3 + 32 * n + 2 + 9 + 6;   // dispatcher bytes (proto: 174 at n=4, 210 at n=5)
// ---- fixed op cost per role (standard mode) ----
const GLUE = {head: 255000, worker: 275000, last: 257000};          // measured, proto-tx.mjs (n=4, realistic sizes)
const FIX = {
  head: 3500 + 238000 + 100000 + 340000 + 46000 + 50000,             // prologue, parse+curve checks, powers (no gamma), tables (no TB), setup, cleanup
  worker: 3500 + 140000 + 100000 + 340000 + 46000 + 70000 + 50000,   // + F init from the first state
  last: 3500 + 150000 + 135000 + 340000 + 30000 + 46000 + 70000 + 707000 + 880000 + 210000 + 54000, // + TB, terminal, quotient (132 words), GLS binding loop, cleanup
};
// ---- code bytes per role (excluding delta slopes) ----
const KB = {head: 4290, worker: 4209, last: 5700};
const slopes = (a, b, last) => { let s = 0; for (let e = a; e < b; e++) s += 1 + (DIG[e] ? 1 : 0); return s + (last ? 2 : 0); };
const hdr = (x) => (x <= 75 ? 1 : x <= 255 ? 2 : 3);
function inputOf(i, a, b) {
  const role = i === 0 ? 'head' : i === n - 1 ? 'last' : 'worker';
  let op = FIX[role] + GLUE[role]; for (let e = a; e < b; e++) op += EV[e] - ACC_PER_EVENT;
  const ns = slopes(a, b, role === 'last'); const kb = KB[role] + 64 * ns + 3 * Math.ceil(ns / 8);
  const fixedU = (role === 'last' ? 1 : 2 + H) + hdr(kb) + kb + hdr(DELTA) + DELTA; // without the data push
  return {i, role, events: [a, b], slopes: ns, op: Math.round(op * (1 + SAFETY)), K: kb, fixedU};
}
function place(ins) { // maximise the min margin: binary search m, need U_i >= op_i / (800 (1 - m)) - 41
  const need = (m) => ins.map((x) => Math.max(1, Math.ceil(x.op / (800 * (1 - m)) - 41 - x.fixedU)));
  const ok = (m) => { const d = need(m); return d.every((di, k) => ins[k].fixedU + hdr(di) + di <= 10000) && d.reduce((s, x) => s + x + 3, 0) <= T_DATA + 3 * n; };
  let lo = -1, hi = 0.5; if (!ok(lo)) return null;
  for (let it = 0; it < 60; it++) { const mid = (lo + hi) / 2; if (ok(mid)) lo = mid; else hi = mid; }
  const d = need(lo); let rest = T_DATA - d.reduce((s, x) => s + x, 0);
  // spread the remainder to the inputs with the most room (keeps every U_i <= 10,000)
  while (rest > 0) { let best = -1, room = 0; ins.forEach((x, k) => { const r = 10000 - (x.fixedU + hdr(d[k]) + d[k]); if (r > room) { room = r; best = k; } }); if (best < 0) return null; const t = Math.min(rest, room); d[best] += t; rest -= t; }
  return ins.map((x, k) => { const U = x.fixedU + hdr(d[k]) + d[k]; const budget = 800 * (41 + U); return {...x, data: d[k], U, budget, margin: budget - x.op, marginPct: +(100 * (1 - x.op / budget)).toFixed(2)}; });
}
let best = null;
const cuts = []; const rec = (k, prev, acc) => { if (k === n - 1) { cuts.push([...acc, 65]); return; } for (let c = prev + 2; c <= 64 - 2 * (n - 2 - k); c += 2) rec(k + 1, c, [...acc, c]); };
rec(0, 0, [0]);
for (const c of cuts) {
  const ins = Array.from({length: n}, (_, i) => inputOf(i, c[i], c[i + 1]));
  const lay = place(ins); if (!lay) continue;
  const minM = Math.min(...lay.map((x) => x.margin / x.budget));
  if (!best || minM > best.minM) best = {minM, cuts: c, lay};
}
if (!best) { console.log(JSON.stringify({n, feasible: false})); process.exit(0); }
const U = best.lay.reduce((s, x) => s + x.U, 0);
const txOv = 8 + 1 + 1 + 10 + n * (36 + 4 + 3);
const out = {n, safety: SAFETY, cuts: best.cuts, minMarginPct: +(100 * best.minM).toFixed(2), sumUnlocking: U, lockings: 35 * n, txOverhead: txOv, score: U + 35 * n + txOv,
  opTotal: best.lay.reduce((s, x) => s + x.op, 0), budgetTotal: best.lay.reduce((s, x) => s + x.budget, 0), delta: DELTA, inputs: best.lay};
console.log(JSON.stringify(out, null, 1));

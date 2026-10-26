// Layout model for the multi-input BLS12-381 SI-GLS verifier on bch-2026: per-input bytes, op cost (consensus and
// standard), budget and margin, from the measured chunk costs (chunk-costs.json, end-to-end VM segments) and the
// measured setup/terminal costs (skeleton.json when present, else kernel-sum estimates). Searches the contiguous
// partition of the 32 chunks into E event inputs and places the movable data (quotient words, code blob) so that
// every input meets the margin target with the fewest total bytes.
//   node model.mjs [E=5] [margin=0.10] [--json out.json]
import {readFileSync, existsSync, writeFileSync} from 'node:fs';
import assert from 'node:assert/strict';
import {VKC, nqMax, uniformBounds} from './protocol.mjs';

const E = Number(process.argv[2] ?? 5), MARGIN = Number(process.argv[3] ?? 0.10);
const outJson = process.argv.includes('--json') ? process.argv[process.argv.indexOf('--json') + 1] : null;
const CH = JSON.parse(readFileSync(new URL('./chunk-costs.json', import.meta.url)));
const SK = existsSync(new URL('./skeleton.json', import.meta.url)) ? JSON.parse(readFileSync(new URL('./skeleton.json', import.meta.url))) : null;
const bounds = CH.bounds; const NCH = bounds.length; // 32 chunks of 2 events
const chunkOp = CH.perChunk.map((s) => Math.ceil(s.max * 1.01)); // +1% over the worst measured proof
// sizes (bytes)
const W = 48, STATE = 6 * W, NQ = nqMax(uniformBounds(2));
const STMT = 8 * W + 2 * 32, NIB = 2 * 64, SC = 6 * W, HANDOFF = 7 * W, QBYTES = NQ * W;
const dLinesInChunk = bounds.map((b, k) => VKC.lines.filter((l) => l.e >= (k ? bounds[k - 1] : 0) && l.e < b).length);
const R_BYTES = SK?.redeem ?? 72, CB_BYTES = SK?.blob ?? 6800; // uniform redeem; shared code blob (estimate until measured)
// op costs not in the chunk table (standard mode; consensus is lower by the hashing difference)
const hashStd = (bytes) => Math.ceil(bytes / 64 + 1) * 192, hashCons = (bytes) => Math.ceil(bytes / 64 + 1) * 64;
const P1_TOTAL = STMT + NIB + SC + NCH * STATE;
const setupOp = (N, mode) => SK ? SK.setup[mode] + SK.perSibling[mode] * N : // measured
  55000 + N * 35000 + (mode === 'std' ? hashStd : hashCons)(P1_TOTAL + QBYTES + CB_BYTES + 4000) + 20000 + 12000 + 150000 + 600000 + 37000 + 37000 + 10500 + 37000;
const TERMINAL = SK?.terminal ?? 1350000, GLOBAL = SK?.global ?? 130000;
const LOOP_OVH = SK?.loopPerEvent ?? 3000; // OP_BEGIN/OP_UNTIL control per event (the measured segments are straight-line)
const overhead = (N) => 20 + 43 * N + 35 * N; // tx framing + spent P2SH32 lockings (scored)

function evaluate(cuts, {place = true} = {}) { // cuts: chunk index where each event input starts (length E), cuts[0] = 0
  const N = E; const ins = [];
  for (let j = 0; j < E; j++) {
    const c0 = cuts[j], c1 = j + 1 < E ? cuts[j + 1] : NCH; const ev = 2 * (c1 - c0);
    const loop = chunkOp.slice(c0, c1).reduce((a, b) => a + b, 0) + LOOP_OVH * ev;
    const extra = (j === E - 1 ? TERMINAL : 0) + (j === 0 ? GLOBAL : 0);
    const op = {std: setupOp(N, 'std') + loop + extra, cons: setupOp(N, 'cons') + loop + extra};
    const mandatory = (j ? HANDOFF : 0) + (j === 0 ? STMT + NIB + SC : 0) + (c1 - c0) * STATE + dLinesInChunk.slice(c0, c1).reduce((a, b) => a + b, 0) * 4 * W;
    ins.push({j, chunks: [c0, c1], events: ev, op, mandatory, q: 0, cb: 0});
  }
  // bytes needed for the op budget at the margin target: (41 + U) * 800 * (1 - m) >= op.std, U = W + 3 + R + 1
  for (const x of ins) { x.need = Math.max(0, Math.ceil(x.op.std / (800 * (1 - MARGIN))) - 41 - 3 - (R_BYTES + 1)); }
  // place the code blob (indivisible) where the slack is largest, then quotient words into the remaining slack
  const slack = (x) => x.need - (x.mandatory + x.q + x.cb);
  let cbHost = ins.slice().sort((a, b) => slack(b) - slack(a))[0]; cbHost.cb = CB_BYTES;
  let qLeft = NQ; for (const x of ins.slice().sort((a, b) => slack(b) - slack(a))) { const take = Math.max(0, Math.min(qLeft, Math.floor(slack(x) / W))); x.q += take * W; qLeft -= take; }
  while (qLeft > 0) { const x = ins.slice().sort((a, b) => (a.mandatory + a.q + a.cb) - (b.mandatory + b.q + b.cb))[0]; x.q += W; qLeft--; }
  let ok = true;
  for (const x of ins) {
    x.content = x.mandatory + x.q + x.cb; x.pad = Math.max(0, x.need - x.content); x.wit = x.content + x.pad;
    x.unlocking = x.wit + 3 + R_BYTES + 1; x.budget = (41 + x.unlocking) * 800;
    x.marginStd = 1 - x.op.std / x.budget; x.marginCons = 1 - x.op.cons / x.budget;
    if (x.unlocking > 10000 || x.op.std > x.budget) ok = false;
  }
  const bytes = ins.reduce((a, x) => a + x.unlocking, 0);
  return {ok, ins, bytes, score: bytes + overhead(N), pad: ins.reduce((a, x) => a + x.pad, 0)};
}
// search contiguous partitions
let best = null; const cuts = [0];
const rec = (j, start) => {
  if (j === E) { const r = evaluate(cuts); if (r.ok && (!best || r.score < best.score)) best = {...r, cuts: cuts.slice()}; return; }
  for (let c = start + 1; c <= NCH - (E - j); c++) { cuts.push(c); rec(j + 1, c); cuts.pop(); }
};
rec(1, 0);
if (!best) { console.log(`E=${E}: no feasible layout at margin ${MARGIN}`); process.exit(0); }
const totOp = best.ins.reduce((a, x) => a + x.op.std, 0);
console.log(`E=N=${E} margin>=${MARGIN}  score ${best.score} B (unlocking ${best.bytes}, overhead ${overhead(E)}), padding ${best.pad} B, total op ${totOp} std, NQ ${NQ}, blob ${CB_BYTES}, redeem ${R_BYTES}${SK ? ' (measured setup/terminal)' : ' (estimated setup/terminal)'}`);
console.log('in  chunks   ev  mand    Q   CB  pad  unlock    op.std    op.cons   budget  m.std  m.cons');
for (const x of best.ins) console.log(String(x.j).padStart(2), `${x.chunks[0]}-${x.chunks[1]}`.padStart(7), String(x.events).padStart(4), String(x.mandatory).padStart(5), String(x.q).padStart(5), String(x.cb).padStart(5), String(x.pad).padStart(5), String(x.unlocking).padStart(7), String(x.op.std).padStart(10), String(x.op.cons).padStart(10), String(x.budget).padStart(9), (100 * x.marginStd).toFixed(1).padStart(6), (100 * x.marginCons).toFixed(1).padStart(6));
if (outJson) writeFileSync(outJson, JSON.stringify({E, margin: MARGIN, ...best}, null, 1));

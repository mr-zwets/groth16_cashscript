// Layout model for the multi-input BLS12-381 SI-GLS verifier on bch-2026: per-input bytes, op cost (consensus and
// standard), budget and margin. Inputs: chunk-costs.json (end-to-end VM event segments, worst of 9 proofs) and
// skeleton.json (VM-measured setup / terminal costs of the 5-input skeleton). Searches the contiguous partition of the
// 32 chunks into N event inputs and places the movable data (quotient words, code blob, shared tables) so that every
// input meets the margin target with the fewest total bytes.
//   node model.mjs [N=5] [margin=0.10] [variant=base|tbl|bcast] [--json out.json]
//   base : every input derives the challenges and builds its own GT-GLS tables
//   tbl  : input 0 builds the tables and checks a claimed copy (64 words) that the others decode
//   bcast: input 0 derives the challenges and every z-dependent value and checks a claimed copy that the others decode
import {readFileSync, writeFileSync} from 'node:fs';
import {VKC, nqMax, uniformBounds} from './protocol.mjs';

const args = process.argv.slice(2).filter((x, i, a) => !x.startsWith('--') && a[i - 1] !== '--json');
const N = Number(args[0] ?? 5), MARGIN = Number(args[1] ?? 0.10), VARIANT = args[2] ?? 'base';
const outJson = process.argv.includes('--json') ? process.argv[process.argv.indexOf('--json') + 1] : null;
const CH = JSON.parse(readFileSync(new URL('./chunk-costs.json', import.meta.url)));
const SK = JSON.parse(readFileSync(new URL('./skeleton.json', import.meta.url)));
const bounds = CH.bounds; const NCH = bounds.length;
const chunkOp = CH.perChunk.map((s) => Math.ceil(s.max * 1.01)); // +1% over the worst measured proof
const W = 48, STATE = 6 * W, NQ = nqMax(uniformBounds(2));
const STMT = 8 * W + 2 * 32, NIB = 2 * 64, SC = 6 * W, HANDOFF = 7 * W;
const dLinesInChunk = bounds.map((b, k) => VKC.lines.filter((l) => l.e >= (k ? bounds[k - 1] : 0) && l.e < b).length);
const SHARED_WORDS = {base: 0, tbl: 64, bcast: SK.bcastWords};
const overhead = (n) => 20 + 43 * n + 35 * n; // tx framing + spent P2SH32 lockings (scored)
// per-input op: setup by role kind (measured), the event chunks, loop control, terminal
const setup = (j, mode) => {
  const full = SK.setup[mode] - (j === 0 ? SK.firstInputSaving[mode] : 0);
  if (VARIANT === 'base') return full;
  const hubExtra = SK.sharedCheckPerWord * SHARED_WORDS[VARIANT], decode = SK.sharedDecodeFixed + SK.sharedDecodePerWord * SHARED_WORDS[VARIANT];
  if (j === 0) return full + hubExtra;
  return full - (VARIANT === 'tbl' ? SK.tablesOp : SK.setup[mode] - SK.consumerBase[mode]) + decode;
};
function evaluate(cuts) {
  const ins = [];
  for (let j = 0; j < N; j++) {
    const c0 = cuts[j], c1 = j + 1 < N ? cuts[j + 1] : NCH; const ev = 2 * (c1 - c0);
    const loop = chunkOp.slice(c0, c1).reduce((a, b) => a + b, 0) + SK.loopPerEvent * ev;
    const term = j === N - 1 ? SK.terminal : 0;
    const op = {std: setup(j, 'std') + loop + term, cons: setup(j, 'cons') + loop + term};
    const mandatory = (j ? HANDOFF : 0) + (j === 0 ? STMT + NIB + SC + SHARED_WORDS[VARIANT] * W : 0) + (c1 - c0) * STATE + dLinesInChunk.slice(c0, c1).reduce((a, b) => a + b, 0) * 4 * W;
    ins.push({j, chunks: [c0, c1], events: ev, op, mandatory, q: 0, cb: 0});
  }
  for (const x of ins) x.need = Math.max(0, Math.ceil(x.op.std / (800 * (1 - MARGIN))) - 41 - 3 - (SK.redeem + 1));
  const slack = (x) => x.need - (x.mandatory + x.q + x.cb);
  // the code blob goes where it fits with the least excess; quotient words fill the remaining slack
  const fits = ins.filter((x) => x.mandatory + SK.blob <= 10000 - 4 - SK.redeem - 1);
  if (!fits.length) return {ok: false};
  const host = fits.sort((a, b) => Math.max(0, SK.blob - slack(a)) - Math.max(0, SK.blob - slack(b)) || slack(b) - slack(a))[0]; host.cb = SK.blob;
  let qLeft = NQ; for (const x of ins.slice().sort((a, b) => slack(b) - slack(a))) { const take = Math.max(0, Math.min(qLeft, Math.floor(slack(x) / W))); x.q += take * W; qLeft -= take; }
  while (qLeft > 0) { const x = ins.filter((y) => y.mandatory + y.q + y.cb + W <= 10000 - 4 - SK.redeem - 1).sort((a, b) => (a.mandatory + a.q + a.cb) - (b.mandatory + b.q + b.cb))[0]; if (!x) return {ok: false}; x.q += W; qLeft--; }
  let ok = true;
  for (const x of ins) {
    x.content = x.mandatory + x.q + x.cb; x.pad = Math.max(0, x.need - x.content); x.wit = x.content + x.pad;
    x.unlocking = x.wit + 3 + SK.redeem + 1; x.budget = (41 + x.unlocking) * 800;
    x.marginStd = 1 - x.op.std / x.budget; x.marginCons = 1 - x.op.cons / x.budget;
    if (x.unlocking > 10000 || x.marginStd < MARGIN - 1e-9) ok = false;
  }
  const bytes = ins.reduce((a, x) => a + x.unlocking, 0);
  return {ok, ins, bytes, score: bytes + overhead(N), pad: ins.reduce((a, x) => a + x.pad, 0)};
}
let best = null; const cuts = [0];
const rec = (j, start) => {
  if (j === N) { const r = evaluate(cuts); if (r.ok && (!best || r.score < best.score)) best = {...r, cuts: cuts.slice()}; return; }
  for (let c = start + 1; c <= NCH - (N - j); c++) { cuts.push(c); rec(j + 1, c); cuts.pop(); }
};
rec(1, 0);
if (!best) { console.log(`N=${N} ${VARIANT}: no feasible layout at margin ${MARGIN}`); process.exit(0); }
const totOp = best.ins.reduce((a, x) => a + x.op.std, 0);
console.log(`N=${N} ${VARIANT} margin>=${MARGIN}: score ${best.score} B (unlocking ${best.bytes} + overhead ${overhead(N)}), padding ${best.pad} B, op ${(totOp / 1e6).toFixed(2)}M std, quotient ${NQ} words, blob ${SK.blob} B, redeem ${SK.redeem} B`);
console.log(' in chunks events  mand     Q    CB   pad unlock   op.std  op.cons   budget m.std m.cons');
for (const x of best.ins) console.log(String(x.j).padStart(3), `${x.chunks[0]}-${x.chunks[1]}`.padStart(6), String(x.events).padStart(6), String(x.mandatory).padStart(5), String(x.q).padStart(5), String(x.cb).padStart(5), String(x.pad).padStart(5), String(x.unlocking).padStart(6), (x.op.std / 1e6).toFixed(3).padStart(8), (x.op.cons / 1e6).toFixed(3).padStart(8), (x.budget / 1e6).toFixed(3).padStart(8), (100 * x.marginStd).toFixed(1).padStart(5), (100 * x.marginCons).toFixed(1).padStart(6));
if (outJson) writeFileSync(outJson, JSON.stringify({N, margin: MARGIN, variant: VARIANT, ...best}, null, 1));

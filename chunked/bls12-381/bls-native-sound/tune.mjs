// Fit the zero fillers of a layout to the measured worst case: build with the layout, run the worst witnesses on the
// real VM (standard mode: the tighter one), set each input's filler so that its smallest margin is >= MARGIN, repeat
// until stable; writes layout.json. A filler is only added where an input's own bytes do not buy enough budget.
//   MARGIN=0.06 WIT=dense,forced:44,random:1,random:2,random:3 node tune.mjs '{"cuts":[...],"place":{...}}'
import {writeFileSync, readFileSync} from 'node:fs';
import {execFileSync} from 'node:child_process';
const MARGIN = Number(process.env.MARGIN ?? 0.06), WIT = process.env.WIT ?? 'dense,forced:44,forced:45,forced:46,forced:47,random:1,random:2,random:3,sweep:random proof #37,sweep:random proof #26,sweep:random proof #27,sweep:random B and C #2,sweep:random proof #9,sweep:random proof #34,sweep:random B and C #1';
const L = JSON.parse(process.argv[2] ?? readFileSync(new URL('./layout.json', import.meta.url), 'utf8'));
L.place.fill = L.place.fill ?? [0, 0, 0, 0];
for (let it = 0; it < 6; it++) {
  const env = {...process.env, NATIVE_CUTS: L.cuts.join(','), NATIVE_PLACE: JSON.stringify(L.place), WIT};
  const out = execFileSync('node', ['--input-type=module', '-e', `
    const {buildAll} = await import('./script.mjs'); const {txPushes} = await import('./protocol.mjs'); const {witnessFor} = await import('./measure.mjs');
    const {p2sh32, txOf, unlockingsFor, evalTxUnlimited} = await import('./vm.mjs');
    const {PLACE} = await import('./protocol.mjs'); const b = buildAll(); const res = [];
    for (const spec of process.env.WIT.split(',')) { const w = await witnessFor(spec); const un = unlockingsFor(txPushes(w, b.blob), b.R); const ctx = txOf(un, un.map(() => p2sh32(b.R)));
      const rs = evalTxUnlimited(ctx, 'standard'); res.push({spec, nq: w.nq, rs: rs.map((x) => ({ok: x.ok, op: x.op, U: x.bytes}))}); }
    console.log(JSON.stringify({blob: b.blob.length, K: PLACE.K, res}));`], {env, cwd: new URL('.', import.meta.url).pathname, maxBuffer: 1 << 26}).toString();
  const m = JSON.parse(out.trim().split('\n').at(-1));
  L.place.K = m.K;                                     // the normalized piece lengths (they sum to each kSize)
  if (m.res.some((x) => x.rs.some((y) => !y.ok))) throw new Error('a witness is rejected: ' + JSON.stringify(m.res.map((x) => [x.spec, x.rs.map((y) => y.ok)])));
  // slack per input: own bytes beyond what its worst witness needs at the margin (negative: bytes missing)
  const slack = [0, 1, 2, 3].map((i) => Math.min(...m.res.map((x) => { const r = x.rs[i]; return r.U - (Math.ceil(r.op / (800 * (1 - MARGIN))) - 41); })));
  let changed = false; const fill = L.place.fill.slice();
  // 1. remove filler where there is slack
  for (let i = 0; i < 4; i++) if (fill[i] > 0 && slack[i] > 0) { const d = Math.min(fill[i], slack[i]); fill[i] -= d; slack[i] -= d; if (fill[i] === 0) slack[i] += 3; changed = true; }
  // 2. move bytes along the movable edges (blob split between its carriers; pieces of a constant block) from slack to deficit
  const edges = [];
  if (L.place.blob.length === 2) edges.push({a: L.place.blob[0], b: L.place.blob[1], move: (from, t) => { L.place.blobLens[0] += from === L.place.blob[0] ? -t : t; }, room: (from) => (from === L.place.blob[0] ? L.place.blobLens[0] - 500 : 1e9)});
  L.place.K.forEach((pcs) => { for (let x = 0; x < pcs.length; x++) for (let y = x + 1; y < pcs.length; y++) { const px = pcs[x], py = pcs[y];
    edges.push({a: px[0], b: py[0], move: (from, t) => { if (from === px[0]) { px[1] -= t; py[1] += t; } else { py[1] -= t; px[1] += t; } }, room: (from) => (from === px[0] ? px[1] - 48 : py[1] - 48)}); } });
  for (let pass = 0; pass < 8; pass++) for (const e of edges) {
    const [rich, poor] = slack[e.a] > slack[e.b] ? [e.a, e.b] : [e.b, e.a];
    let t = Math.floor((slack[rich] - slack[poor]) / 2); if (slack[poor] >= 0) t = Math.min(t, Math.max(0, slack[rich])); t = Math.min(t, e.room(rich));
    if (t >= 8) { e.move(rich, t); slack[rich] -= t; slack[poor] += t; changed = true; }
  }
  // 3. filler where bytes are still missing
  for (let i = 0; i < 4; i++) if (slack[i] < 0) { fill[i] += -slack[i] + (fill[i] === 0 ? 3 : 0); changed = true; }
  console.log(`iter ${it}: blob ${m.blob}; slack before ${[0, 1, 2, 3].map((i) => Math.min(...m.res.map((x) => { const r = x.rs[i]; return r.U - (Math.ceil(r.op / (800 * (1 - MARGIN))) - 41); }))).join(',')}; fill -> ${fill.join(',')}; place ${JSON.stringify({blobLens: L.place.blobLens, K: L.place.K})}`);
  L.place.fill = fill;
  if (!changed) break;
}
writeFileSync(new URL('./layout.json', import.meta.url), JSON.stringify({note: 'chunk ownership and placement of the movable bytes; layout.mjs (MARGIN=' + MARGIN + ') then tune.mjs (fillers fitted on the VM to the worst measured witnesses)', cuts: L.cuts, place: L.place}, null, 1) + '\n');
console.log('wrote layout.json', JSON.stringify(L));

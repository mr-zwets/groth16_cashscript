// Per-input witness composition, bytes, op and margin of a model layout (markdown table for the README).
//   node layout_table.mjs layout-rec.json
import {readFileSync} from 'node:fs';
import {VKC, uniformBounds} from './protocol.mjs';
const L = JSON.parse(readFileSync(process.argv[2] ?? 'layout-rec.json')); const bounds = uniformBounds(2); const W = 48;
const hub = L.hub ?? 0, N = L.ins.length, BCW = L.variant === 'bcast' ? 83 : 0;
console.log('| input | role | events | chunks / states | P1 (transcript) | Q | δ consts | IN | broadcast | blob part | pad | witness W_j | unlocking | budget | op cons / std | margin cons / std |');
console.log('|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|');
let tot = {w: 0, u: 0};
for (const x of L.ins) {
  const [c0, c1] = x.chunks; const e0 = c0 ? bounds[c0 - 1] : 0, e1 = bounds[c1 - 1];
  const dl = VKC.lines.filter((l) => l.e >= e0 && l.e < e1).length;
  const p1 = (x.j === 0 ? 448 + 128 + 288 : 0) + (c1 - c0) * 288; const K = dl * 4 * W; const IN = x.j ? 7 * W : 0; const bc = x.j === hub ? BCW * W : 0;
  const role = [x.j === hub && BCW ? 'hub' : null, x.j === N - 1 ? 'terminal' : null, 'events'].filter(Boolean).join(' + ');
  const w = p1 + x.q + K + IN + bc + x.cb + x.pad; tot.w += w; tot.u += x.unlocking;
  console.log(`| ${x.j} | ${role} | ${e0}–${e1 - 1} (${x.events}) | ${c1 - c0} | ${p1} | ${x.q} (${x.q / W} w) | ${K} (${dl} lines) | ${IN} | ${bc} | ${x.cb} | ${x.pad} | ${w} | ${x.unlocking} | ${(x.budget / 1e6).toFixed(3)}M | ${(x.op.cons / 1e6).toFixed(3)}M / ${(x.op.std / 1e6).toFixed(3)}M | ${(100 * x.marginCons).toFixed(1)}% / ${(100 * x.marginStd).toFixed(1)}% |`);
}
console.log(`| total | | 64 | ${bounds.length} | | | | | | | ${L.pad} | ${tot.w} | ${tot.u} | | ${(L.ins.reduce((a, x) => a + x.op.cons, 0) / 1e6).toFixed(2)}M / ${(L.ins.reduce((a, x) => a + x.op.std, 0) / 1e6).toFixed(2)}M | |`);
console.log(`\nscore ${L.score} = unlocking ${L.bytes} + ${N} x 35 B P2SH32 lockings + tx framing ${L.score - L.bytes - 35 * N}`);

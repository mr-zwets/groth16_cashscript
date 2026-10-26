// Liveness sweep. Phase 1 (`measure`): for each proof (forced, edge and random statements) every event chunk runs
// end-to-end in the VM (proto_worker.segment) with that proof's own random challenges; per-proof chunk costs are cached.
// Phase 2 (`margins`): per-input op = measured setup (skeleton.json) + the proof's chunks + loop allowance + terminal,
// against each layout's fixed per-input budget, in consensus and standard accounting; reports the minimum margins.
//   node sweep.mjs measure <first> <count> <out.json>        (proof list index range; run several in parallel)
//   node sweep.mjs margins <chunks.json ...> -- <layout.json ...>
//   node sweep.mjs merge <chunk-costs-9.json> <chunks.json ...>   (per-chunk max/min/mean over all measured proofs -> chunk-costs.json)
import {readFileSync, writeFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {r, mod, X_ABS} from './blsmath.mjs';
import {prove, randProof, mintProof, uniformBounds} from './protocol.mjs';
import {segment} from './proto_worker.mjs';
const bounds = uniformBounds(2);
const H = (s) => mod(BigInt('0x' + createHash('sha256').update(s).digest('hex')), r);
// forced: every GLS nibble nonzero (d0 = |x| - 1, d1 = its bitwise complement below 2^64 < |x|), so no lookup returns 1
const d0 = X_ABS - 1n, d1 = ((1n << 64n) - 1n) ^ d0; const nAll = d0 + d1 * X_ABS;
export const PROOFS = [
  ['forced: all GLS nibbles nonzero', () => mintProof([nAll, nAll], H('fb'), H('fc'))],
  ['forced: all nibbles nonzero, B = G2', () => mintProof([nAll, nAll - 1n], 1n, H('fc2'))],
  ['edge: n = 0, 0 (all nibbles 0)', () => mintProof([0n, 0n], H('eb'), H('ec'))],
  ['edge: n = r-1', () => mintProof([r - 1n, r - 1n], H('eb2'), H('ec2'))],
  ['edge: n = 1, 2^64', () => mintProof([1n, 1n << 64n], H('eb3'), H('ec3'))],
  ['edge: B = G2, C = G1', () => mintProof([H('n0'), H('n1')], 1n, 1n)],
  ...Array.from({length: 200}, (_, i) => ['random ' + i, () => randProof(5000 + i)]),
];
const mode = process.argv[2];
if (mode === 'measure') {
  const first = Number(process.argv[3]), count = Number(process.argv[4]), out = process.argv[5]; const rows = [];
  for (const [name, mk] of PROOFS.slice(first, first + count)) {
    const pr = prove(mk(), {bounds}); const z = H(name + '/z'), rho = H(name + '/rho');
    const ch = bounds.map((b, k) => segment(pr, k ? bounds[k - 1] : 0, b, {bounds, z, rho}).op);
    rows.push({name, chunks: ch, loop: ch.reduce((a, b) => a + b, 0)}); writeFileSync(out, JSON.stringify(rows));
    console.log(name, (rows.at(-1).loop / 1e6).toFixed(3) + 'M');
  }
} else if (mode === 'merge') {
  const base = JSON.parse(readFileSync(process.argv[3])); const rows = process.argv.slice(4).flatMap((f) => JSON.parse(readFileSync(f)));
  const per = base.perChunk.map((s, k) => { const xs = rows.map((rw) => rw.chunks[k]); return {min: Math.min(s.min, ...xs), max: Math.max(s.max, ...xs), mean: Math.round((s.mean * base.proofs.length + xs.reduce((a, b) => a + b, 0)) / (base.proofs.length + xs.length))}; });
  const out = {bounds: base.bounds, proofs: [...base.proofs, ...rows.map((rw) => rw.name)], perChunk: per, totalOfMax: per.reduce((a, s) => a + s.max, 0)};
  writeFileSync('chunk-costs.json', JSON.stringify(out, null, 1)); console.log('proofs', out.proofs.length, 'sum of per-chunk max', out.totalOfMax);
} else if (mode === 'margins') {
  const sep = process.argv.indexOf('--'); const rows = process.argv.slice(3, sep).flatMap((f) => JSON.parse(readFileSync(f)));
  const SK = JSON.parse(readFileSync(new URL('./skeleton.json', import.meta.url)));
  const summary = [];
  for (const f of process.argv.slice(sep + 1)) {
    const L = JSON.parse(readFileSync(f)); const N = L.ins.length; const hub = L.hub ?? 0; const parts = L.parts ?? 1;
    const per = rows.map((rw) => L.ins.map((x) => { const [c0, c1] = x.chunks; const ev = 2 * (c1 - c0);
      const loop = rw.chunks.slice(c0, c1).reduce((a, b) => a + b, 0) + SK.loopPerEvent * ev; const term = x.j === N - 1 ? SK.terminal : 0;
      const su = (m) => SK[L.variant][x.j === hub ? 'first' : 'other'][m] + (x.j === N - 1 ? SK.terminalExtraSetup : 0) + 30000 * (parts - 1);
      return {std: 1 - (su('std') + loop + term) / x.budget, cons: 1 - (su('cons') + loop + term) / x.budget}; }));
    const minStd = per.map((p) => Math.min(...p.map((q) => q.std))), minCons = per.map((p) => Math.min(...p.map((q) => q.cons)));
    const w = minStd.indexOf(Math.min(...minStd));
    const s = {layout: f, score: L.score, proofs: rows.length, worstMarginStd: +(100 * minStd[w]).toFixed(2), worstMarginCons: +(100 * Math.min(...minCons)).toFixed(2), worstProof: rows[w].name,
      meanMarginStd: +(100 * minStd.reduce((a, b) => a + b, 0) / minStd.length).toFixed(2), loopMin: Math.min(...rows.map((x) => x.loop)), loopMax: Math.max(...rows.map((x) => x.loop))};
    summary.push(s); console.log(JSON.stringify(s));
  }
  writeFileSync('sweep-summary.json', JSON.stringify(summary, null, 1));
}

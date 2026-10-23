// Sweep of the two byte/op trade-off knobs of the prototype, end-to-end on the VM (fixture 0):
//   K      = number of leading events whose B step is affine with a witnessed slope (rest projective)
//   f1From = first event whose gamma/delta lines are baked as (lambda, beta) (F1) instead of lambda only (F2)
// and the resulting full-verifier score with the measured MSM and terminal verdict added.
// Usage: KS=0,16,65 FS=64,65 node sweep.mjs   (OUT=file.json to save the rows)
// EXT holds the separately measured parts (msm.mjs, verdict.mjs) and estimates (integration, tx).
import {pathToFileURL} from 'node:url';
import {build} from './hotloop.mjs'; import {makeWitness, EVENTS} from './witness.mjs'; import {run, asm, L, num} from './sscomp.mjs';
import {writeFileSync} from 'node:fs';
const EXT = {msmCode: 3816, msmWitness: 98, msmWorst: 11.190941e6, msmFix0: 10.331925e6, verdictCode: 1590, verdictOp: 0.440030e6,
  integrationCode: 300, integrationOp: 0.05e6, vkxPush: 66, redeemHdr: 3, txOverhead: 100};
export const score = (r) => {
  const bytes = r.lock + EXT.msmCode + EXT.verdictCode + EXT.integrationCode + EXT.redeemHdr + r.witness - EXT.vkxPush + EXT.msmWitness;
  const opW = r.op + EXT.msmWorst + EXT.verdictOp + EXT.integrationOp, opT = r.op + EXT.msmFix0 + EXT.verdictOp + EXT.integrationOp;
  return {bytes, opWorstM: +(opW / 1e6).toFixed(3), opFix0M: +(opT / 1e6).toFixed(3), budgetM: +((10000 + bytes) * 800 / 1e6).toFixed(3),
    score: Math.round(Math.max(bytes, opW / 800 - 10000) + EXT.txOverhead), scoreFix0: Math.round(Math.max(bytes, opT / 800 - 10000) + EXT.txOverhead)};
};
if (import.meta.url === pathToFileURL(process.argv[1]).href) {
const Ks = (process.env.KS ?? '0,10,20,30,40,50,60,65').split(',').map(Number);
const Fs = (process.env.FS ?? '0,10,20,30,40,50,60,65').split(',').map(Number);
const rows = [];
for (const K of Ks) {
  const w = makeWitness(0, K);
  const base = run(build(w).pushes, asm('1')).cost;
  for (const f1From of Fs) {
    const B = build(w, {f1From});
    const r = run(B.pushes, B.lock);
    if (r.err) { console.log('FAIL', K, f1From, r.err); continue; }
    const witness = B.pushes.reduce((s, x) => s + (x instanceof Uint8Array ? L.encodeDataPush(x).length : L.encodeDataPush(num(x)).length), 0);
    const row = {K, f1From, op: r.cost - base, lock: B.lock.length, witness, nQ: B.nQ};
    Object.assign(row, score(row)); rows.push(row);
    console.log(JSON.stringify(row));
  }
}
rows.sort((a, b) => a.score - b.score);
console.log('best', JSON.stringify(rows.slice(0, 5)));
if (process.env.OUT) writeFileSync(process.env.OUT, JSON.stringify({EXT, rows}, null, 1));
}

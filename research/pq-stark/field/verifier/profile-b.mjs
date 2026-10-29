// Per-phase op-cost of layout (b) from NOP markers (markers build: same code plus OP_NOPs; the markers' own cost is
// subtracted: 100 per NOP). usage: node profile-b.mjs vectors... -> results/profile-b.json
import {writeFileSync, mkdirSync} from 'node:fs';
import {loadVector, spendB} from './layout-b.mjs';
import {evaluate} from './vm.mjs';

const out = [];
for (const path of process.argv.slice(2)) {
  const {prm, proof} = loadVector(path);
  const sp = spendB(prm, proof.subarray(0, 16), proof, {markers: true});
  const r = evaluate('looseStd', sp.locking, sp.unlocking);
  if (!r.accepted) throw new Error('not accepted: ' + r.error);
  const labels = sp.built.codeSizes.map(([l]) => l);
  const main = labels.filter((l) => !l.startsWith('q-') && l !== 'end'), q = labels.filter((l) => l.startsWith('q-'));
  const S = r.snaps, s = prm.s;
  const d = (a, b) => b.op - a.op - 100;
  const phases = {'witness pushes, redeem hash, OP_DEFINEs': S[0].op};
  for (let i = 1; i < main.length; i++) phases[main[i]] = d(S[i - 1], S[i]);
  const qtot = Object.fromEntries(q.map((l) => [l, 0]));
  const base = main.length;
  for (let k = 0; k < s; k++) for (let j = 0; j < q.length; j++) {
    const a = S[base + k * q.length + j - 1], b = S[base + k * q.length + j];
    qtot[q[j]] += d(a, b);
  }
  const queriesTotal = Object.values(qtot).reduce((x, y) => x + y, 0);
  const tail = r.opCost - S[S.length - 1].op;
  const row = {set: prm.name, vector: path.split('/').pop(), opStdWithMarkers: r.opCost, markers: r.markers, phases, perQuery: Object.fromEntries(Object.entries(qtot).map(([k, v]) => [k, Math.round(v / s)])), queriesTotal, cleanup: tail};
  out.push(row);
  console.log(JSON.stringify(row));
}
mkdirSync(new URL('./results/', import.meta.url), {recursive: true});
writeFileSync(new URL('./results/profile-b.json', import.meta.url), JSON.stringify(out, null, 1) + '\n');

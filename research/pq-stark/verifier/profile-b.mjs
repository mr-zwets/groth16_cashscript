// Per-phase op-cost of layout (b) (OP_NOP markers, loose VM, standard op-cost), per-query averages, and the split
// between the AIR-specific part (periodic columns + constraint evaluation + Horner in alpha, generated from air.mjs)
// and the generic STARK verifier. Writes results/profile-b.json (merged by vector).
// usage: node profile-b.mjs vectors...
import {writeFileSync, readFileSync} from 'node:fs';
import {loadVector, spendB} from './layout-b.mjs';
import {evaluate} from './vm.mjs';

const out = [];
for (const path of process.argv.slice(2)) {
  const {v, vk, proof, pis} = loadVector(path);
  const sp = spendB(vk, pis, proof, pis, {markers: true});
  const plain = spendB(vk, pis, proof, pis);
  const r = evaluate('looseStd', sp.locking, sp.unlocking);
  if (!r.accepted) throw new Error(path + ' not accepted: ' + r.error);
  const marks = sp.built.marks.map(([l]) => l);
  const qi = marks.indexOf('q-x'), qn = marks.indexOf('queries') - qi;     // query-function markers
  const seq = [...marks.slice(0, qi), ...Array.from({length: vk.Q}, () => marks.slice(qi, qi + qn)).flat(), ...marks.slice(qi + qn)];
  if (seq.length !== r.snaps.length) throw new Error(`marker count ${r.snaps.length} vs ${seq.length}`);
  const phase = {}; let prev = 0;
  r.snaps.forEach((s, i) => { phase[seq[i]] = (phase[seq[i]] ?? 0) + (s.op - prev) - 100; prev = s.op; });   // minus the NOP itself
  phase.cleanup = r.opCost - prev;
  const perQuery = Object.fromEntries(marks.slice(qi, qi + qn).map((l) => [l, Math.round(phase[l] / vk.Q)]));
  // code bytes of the main program sections (AIR-specific: between the markers air-generic-a and air-specific)
  const pos = Object.fromEntries(sp.built.marks.filter(([l]) => !l.startsWith('q-')).map(([l, p]) => [l, p]));
  const nopsBefore = (l) => marks.slice(0, marks.indexOf(l) + 1).filter((x) => !x.startsWith('q-')).length;
  const airSpecificBytes = (pos['air-specific'] - nopsBefore('air-specific')) - (pos['air-generic-a'] - nopsBefore('air-generic-a'));
  const airAllBytes = (pos['air-generic-b'] - nopsBefore('air-generic-b')) - (pos['air-start'] - nopsBefore('air-start'));
  const total = r.opCost - 100 * r.snaps.length;
  const row = {
    vector: path.split('/').pop(), air: v.air, set: v.set.name, Q: vk.Q, opStd: total, phases: phase, perQuery,
    queryTotal: Object.values(perQuery).reduce((a, x) => a + x, 0),
    airSpecific: {opCost: phase['air-specific'], pctOfTotal: +(100 * phase['air-specific'] / total).toFixed(2), codeBytes: airSpecificBytes, airBlockCodeBytes: airAllBytes,
      redeemBytes: plain.redeem.length, pctOfRedeem: +(100 * airSpecificBytes / plain.redeem.length).toFixed(1), constraintSteps: sp.built.airSteps},
    merkle: phase.merkle, merklePct: +(100 * phase.merkle / total).toFixed(1),
  };
  out.push(row);
  console.log(`${row.vector.padEnd(24)} op ${total} | per query ${row.queryTotal} ${JSON.stringify(perQuery)} | merkle ${row.merkle} (${row.merklePct}%) | AIR-specific ${row.airSpecific.opCost} op (${row.airSpecific.pctOfTotal}%), ${airSpecificBytes} B of ${plain.redeem.length} B redeem`);
  console.log('   phases', JSON.stringify(phase));
}
const file = new URL('./results/profile-b.json', import.meta.url);
let prev = []; try { prev = JSON.parse(readFileSync(file, 'utf8')); } catch {}
writeFileSync(file, JSON.stringify([...prev.filter((x) => !out.some((y) => y.vector === x.vector)), ...out].sort((a, b) => a.vector.localeCompare(b.vector)), null, 1) + '\n');

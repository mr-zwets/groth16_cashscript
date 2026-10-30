#!/usr/bin/env node
// profile-b2.mjs: per-phase op-cost of each input of layout b2 (OP_NOP markers on the loose VM, libauth standard
// op-cost; the marker NOPs are subtracted). Phases: entry (library definitions, transaction pins, statement),
// transcript, AIR (per instance: periodic, DAG, quotient), DEEP/FRI constants, queries (per query), Merkle.
// Writes results/profile-b2.json.  usage: node profile-b2.mjs VECTOR.json...
import {writeFileSync} from 'node:fs';
import {readVector, vkxN, stmtFor, spendB2} from './layoutn.mjs';
import {evaluate} from './vm.mjs';

const outputsOf = (v) => v.s4_outputs.map((o) => ({lockingBytecode: Uint8Array.from(Buffer.from(o.lockingBytecode, 'hex')), valueSatoshis: BigInt(o.valueSatoshis)}));
const Qk = ['q-x', 'q-deep', 'q-folds', 'q-final'];
const rows = [];
for (const path of process.argv.slice(2)) {
  const v = readVector(path); const vk = vkxN(v, {stmt: 'pool'}); const pis = v.public_values.flat().map(BigInt);
  const QA = vk.inst.length > 1 ? 9 : 12;
  const sp = spendB2(vk, stmtFor(vk, pis, {mode: 'pool', ctx: 'tx'}), QA, Buffer.from(v.proof_hex, 'hex'), pis, outputsOf(v), {markers: true});
  const marks = sp.built.marks.map(([l]) => l);
  const air = marks.slice(marks.indexOf('air-start'), marks.indexOf('air-end') + 1);
  const consts = ['deep-points', 'deep-consts', 'tables', 'unpack'];
  const seqs = [
    ['entry', 'transcript', ...air, ...consts, ...Array.from({length: QA}, () => Qk).flat(), 'queries', 'merkle', 'end'],
    ['entry', 'transcript', ...consts, ...Array.from({length: vk.Q - QA}, () => Qk).flat(), 'queries', 'merkle', 'end'],
  ];
  const defBytes = [...sp.built.g.fns.values()].reduce((a, f) => a + f.body.length, 0);
  const inputs = [0, 1].map((i) => {
    const r = evaluate('looseStd', null, null, sp.progs[i]);
    if (!r.accepted) throw new Error(`${path} input ${i}: ${r.error}`);
    const seq = seqs[i];
    if (seq.length !== r.snaps.length) throw new Error(`input ${i}: ${r.snaps.length} markers, expected ${seq.length}`);
    const phase = {}; let prev = 0;
    r.snaps.forEach((s, k) => { phase[seq[k]] = (phase[seq[k]] ?? 0) + (s.op - prev) - 100; prev = s.op; });
    phase.cleanup = r.opCost - prev;
    const total = r.opCost - 100 * r.snaps.length;
    const queries = Qk.reduce((a, k) => a + phase[k], 0) + phase.queries;
    const airTotal = air.reduce((a, k) => a + (phase[k] ?? 0), 0);
    const constsTotal = consts.reduce((a, k) => a + phase[k], 0);
    return {opStd: total, opBchnAdjusted: total + defBytes, entry: phase.entry, transcript: phase.transcript, air: airTotal, consts: constsTotal, queries,
      perQuery: Math.round(queries / (i ? vk.Q - QA : QA)), merkle: phase.merkle, phases: phase};
  });
  const row = {vector: path.split('/').pop(), QA, libBytes: sp.lib.length, defineBodyBytes: defBytes, inputs, dag: sp.built.dagStats};
  rows.push(row);
  for (const [i, x] of inputs.entries()) console.log(`${row.vector} input ${i}: op ${x.opStd} (+${defBytes} define bytes) = entry ${x.entry} + transcript ${x.transcript} + AIR ${x.air} + consts ${x.consts} + queries ${x.queries} (${x.perQuery}/query) + Merkle ${x.merkle}`);
}
writeFileSync(new URL('./results/profile-b2.json', import.meta.url), JSON.stringify(rows, null, 1) + '\n');

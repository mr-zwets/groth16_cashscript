#!/usr/bin/env node
// profile-b.mjs: per-phase op-cost of layout (b) (OP_NOP markers on the loose VM, libauth standard op-cost; the
// marker NOPs are subtracted), against the S0 layout model (params8.py opcost_model: per query 699,732 x 24,
// Merkle 7,232,172, fixed 4,230,000 = 28,255,740). Writes results/profile-b.json.
// usage: node profile-b.mjs VECTOR.json...
import {writeFileSync} from 'node:fs';
import {loadVector, spendB} from './layout-b.mjs';
import {evaluate} from './vm.mjs';

const MODEL = {perQuery: 699_732, queries: 16_793_568, merkle: 7_232_172, fixed: 4_230_000, total: 28_255_740, airM1: 600_000};
const outputsOf = (v) => v.s4_outputs.map((o) => ({lockingBytecode: Uint8Array.from(Buffer.from(o.lockingBytecode, 'hex')), valueSatoshis: BigInt(o.valueSatoshis)}));
const rows = [];
for (const path of process.argv.slice(2)) {
  const {v, vk, proof, pis} = loadVector(path);
  const sp = spendB(vk, pis.slice(0, 4), proof, pis, outputsOf(v), {markers: true});
  const r = evaluate('looseStd', sp.locking, sp.unlocking, sp.prog);
  if (!r.accepted) throw new Error(`${path}: not accepted: ${r.error}`);
  const marks = sp.built.marks.map(([l]) => l);
  const qi = marks.indexOf('q-x'), qn = marks.indexOf('queries') - qi;
  const seq = [...marks.slice(0, qi), ...Array.from({length: vk.Q}, () => marks.slice(qi, qi + qn)).flat(), ...marks.slice(qi + qn)];
  if (seq.length !== r.snaps.length) throw new Error(`marker count ${r.snaps.length} vs ${seq.length}`);
  const phase = {}, instr = {}; let prev = 0, pi = 0;
  r.snaps.forEach((s, i) => { phase[seq[i]] = (phase[seq[i]] ?? 0) + (s.op - prev) - 100; instr[seq[i]] = (instr[seq[i]] ?? 0) + (s.instr - pi) - 1; prev = s.op; pi = s.instr; });
  phase.cleanup = r.opCost - prev;
  const total = r.opCost - 100 * r.snaps.length;
  const qKeys = marks.slice(qi, qi + qn);
  const queries = qKeys.reduce((a, k) => a + phase[k], 0);
  const fixed = total - queries - phase.merkle;
  const air = phase['air-start'] + phase['air-generic-a'] + phase['air-periodic'] + phase['air-specific'] + phase['air-generic-b'];
  const code = {}; { let p0 = 0; for (const [l, p] of sp.built.marks) if (!l.startsWith('q-')) { code[l] = p - p0 - 1; p0 = p; } }
  const fnBytes = Object.fromEntries([...sp.built.fns].map(([n, f]) => [n, f.body.length]));
  const row = {
    vector: path.split('/').pop(), opStd: total, queries, perQuery: Math.round(queries / vk.Q), merkle: phase.merkle, fixed,
    air: {total: air, dagInterpreter: phase['air-specific'], periodic: phase['air-periodic'], quotient: phase['air-generic-b'], selectorsAndPowers: phase['air-generic-a'], oodParse: phase['air-start']},
    perQueryPhases: Object.fromEntries(qKeys.map((k) => [k, Math.round(phase[k] / vk.Q)])), phases: phase, instructions: instr,
    model: MODEL, vsModel: {queries: +(100 * (queries / MODEL.queries - 1)).toFixed(1), merkle: +(100 * (phase.merkle / MODEL.merkle - 1)).toFixed(1), fixed: +(100 * (fixed / MODEL.fixed - 1)).toFixed(1), total: +(100 * (total / MODEL.total - 1)).toFixed(1)},
    redeemBytes: sp.redeem.length, mainCodeBytes: sp.built.main.length, codeBytesBySection: code, functionBytes: fnBytes, dag: sp.built.dagStats,
  };
  rows.push(row);
  console.log(`${row.vector}: op ${total} = queries ${queries} (${row.perQuery}/query; model ${MODEL.perQuery}) + merkle ${phase.merkle} (model ${MODEL.merkle}) + fixed ${fixed} (model ${MODEL.fixed}; AIR ${air}, of which DAG interpreter ${phase['air-specific']})`);
  console.log('  phases', JSON.stringify(phase));
  console.log('  code', JSON.stringify(code));
}
writeFileSync(new URL('./results/profile-b.json', import.meta.url), JSON.stringify(rows, null, 1) + '\n');

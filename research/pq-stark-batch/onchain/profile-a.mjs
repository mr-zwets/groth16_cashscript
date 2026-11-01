#!/usr/bin/env node
// profile-a.mjs: per-phase op-cost of every input of layout a' (1-transaction plan), from OP_NOP markers on the loose VM
// (libauth standard op-cost; the marker NOPs are subtracted). Phases per role:
//   HEAD  entry (code loading by R, graph pins, item checks, CTX, FIN parse), transcript, AIR combination (quotient,
//         ACC parts)
//   CODE  entry (R, parses), transcript, AIR pre (zeta powers, selectors, periodic columns, opened values), DAG range
//   FIN   entry, transcript, DEEP point constants, A sums (alpha' ladder over the 94 opened values), TBL serialization
//   QRY   entry (R, parses, TBL), alpha' ladder and row keys, constants (fold columns, tables, final polynomial), the
//         queries (x, DEEP, folds, final polynomial, full paths)
// Writes results/profile-a.json.  usage: node profile-a.mjs VECTOR.json
import {writeFileSync} from 'node:fs';
import {readVector} from './layoutn.mjs';
import {vkxA} from './modela.mjs';
import {makePlanA, spendA} from './layouta.mjs';
import {evaluate} from './vm.mjs';

const path = process.argv[2];
const v = readVector(path); const vk = vkxA(v); const pis = v.public_values.flat().map(BigInt);
const outputs = v.s4_outputs.map((o) => ({lockingBytecode: Uint8Array.from(Buffer.from(o.lockingBytecode, 'hex')), valueSatoshis: BigInt(o.valueSatoshis)}));
const per = Array.from({length: Math.ceil(vk.Q / 3)}, (_, i) => Math.min(3, vk.Q - 3 * i));
const plan = makePlanA(vk, [per]);
const sp = spendA(vk, plan, Buffer.from(v.proof_hex, 'hex'), pis, outputs, {gen: {markers: true}});
const tx = sp.txs[0];
const nc = plan.nc;
const seqOf = (i) => {
  if (i === 0) return ['entry', '(transcript)', 'transcript', 'air'];
  if (i <= nc) return ['entry', '(transcript)', 'transcript', 'air-pre', 'air-dag'];
  if (i === nc + 1) return ['entry', '(transcript)', 'transcript', 'deep-points', 'a-sums', 'tbl'];
  const n = plan.txs[0].qry[i - nc - 2][1] - plan.txs[0].qry[i - nc - 2][0];
  return ['entry', 'row-keys', '(unpack)', 'consts', ...Array.from({length: n}, () => ['q-x', 'q-deep', 'q-folds', 'q-final+paths']).flat(), 'queries'];
};
const rows = [];
for (let i = 0; i < tx.transaction.inputs.length; i++) {
  const r = evaluate('looseStd', null, null, {inputIndex: i, sourceOutputs: tx.sourceOutputs, transaction: tx.transaction});
  if (!r.accepted) throw new Error(`input ${i}: ${r.error}`);
  const seq = seqOf(i);
  if (seq.length !== r.snaps.length) throw new Error(`input ${i}: ${r.snaps.length} markers, expected ${seq.length}`);
  const phase = {}; let prev = 0;
  r.snaps.forEach((s, k) => { const lab = seq[k].replace(/[()]/g, ''); phase[lab] = (phase[lab] ?? 0) + (s.op - prev) - 100; prev = s.op; });
  phase.cleanup = r.opCost - prev;
  // the parenthesized markers sit inside shared functions: "(transcript)" ends the transcript body, so the role's
  // "transcript" marker only adds the region shuffle; fold them together
  if (phase.transcript !== undefined) phase.transcript += 0;
  const total = r.opCost - 100 * r.snaps.length;
  const role = i === 0 ? 'HEAD' : i <= nc ? `CODE${i}` : i === nc + 1 ? 'FIN' : 'QRY';
  rows.push({input: i, role, unlocking: tx.transaction.inputs[i].unlockingBytecode.length, opStd: total, opBchnAdjusted: total + sp.pg.defineBytes, phases: phase});
  console.log(`in${i} ${role}: op ${total} (+${sp.pg.defineBytes} define bytes) ${Object.entries(phase).map(([k, x]) => `${k} ${x}`).join(', ')}`);
}
writeFileSync(new URL('./results/profile-a.json', import.meta.url), JSON.stringify({vector: path.split('/').pop(), plan: plan.txs, parts: plan.parts, code: sp.pg.code.map((c) => c.length), redeem: sp.pg.redeem.length, fnSizes: sp.pg.fnSizes, dag: sp.pg.g.dagStats, rows}, null, 1) + '\n');

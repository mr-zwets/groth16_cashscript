#!/usr/bin/env node
// profile-a2.mjs (Track 10 G2, from Track 8's profile-a.mjs): per-phase op-cost of every input of tx 0 of layout a' (plan of
// grade-a2.mjs planFor), from OP_NOP markers on the loose VM
// (libauth standard op-cost; the marker NOPs are subtracted). Phases per role:
//   HEAD  entry (code loading by R, graph pins, item checks, CTX, FIN parse), transcript, AIR combination (quotient,
//         ACC parts)
//   CODE  entry (R, parses), transcript, AIR pre (zeta powers, selectors, periodic columns, opened values), DAG range
//   FIN   entry, transcript, DEEP point constants, A sums (alpha' ladder over the 94 opened values), TBL serialization
//   QRY   entry (R, parses, TBL), alpha' ladder and row keys, constants (fold columns, tables, final polynomial), the
//         queries (x, DEEP, folds, final polynomial, full paths)
// usage: node profile-a2.mjs [--nc N] [--per N] [--out FILE] VECTOR.json
import {writeFileSync} from 'node:fs';
import {readVector} from './layoutn.mjs';
import {vkxA} from './modela.mjs';
import {makePlanA, spendA} from './layouta.mjs';
import {planFor} from './grade-a2.mjs';
import {evaluate} from './vm.mjs';

const args = process.argv.slice(2);
const opt = (k, d) => { const i = args.indexOf(k); return i >= 0 ? args[i + 1] : d; };
const path = args[args.length - 1];
const v = readVector(path); const vk = vkxA(v); const pis = v.public_values.flat().map(BigInt);
const outputs = v.s4_outputs.map((o) => ({lockingBytecode: Uint8Array.from(Buffer.from(o.lockingBytecode, 'hex')), valueSatoshis: BigInt(o.valueSatoshis)}));
const pf = planFor(vk, Buffer.from(v.proof_hex, 'hex'), pis, outputs, {nc: +opt('--nc', 3), per: opt('--per') ? +opt('--per') : undefined, pad: opt('--pad') !== '0'});
if (!pf.plan) throw new Error('no plan ' + JSON.stringify(pf.tried));
const plan = pf.plan;
const sp = spendA(vk, plan, Buffer.from(v.proof_hex, 'hex'), pis, outputs, {gen: {markers: true, ...(pf.gen ?? {})}});
const tx = sp.txs[0];
const nc = plan.nc;
const seqOf = (i) => {
  if (i === 0) return ['entry', '(transcript)', 'transcript', 'air', ...vk.inst.slice(1).map((J) => 'air' + J.i), ...(plan.txs.length > 1 ? ['thread'] : [])];
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
writeFileSync(opt('--out', new URL('./results/profile-a2.json', import.meta.url).pathname), JSON.stringify({vector: path.split('/').pop(), plan: plan.txs, parts: plan.parts, code: sp.pg.code.map((c) => c.length), redeem: sp.pg.redeem.length, fnSizes: sp.pg.fnSizes, dag: sp.pg.g.dagStats, rows}, null, 1) + '\n');

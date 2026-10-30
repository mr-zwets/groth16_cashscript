#!/usr/bin/env node
// grade-a.mjs: layout a' (today's standard rules) for transaction-bound M1 statements under Z128 cap 5, in the
// 1-transaction plan (12 inputs) and the 2-transaction baseline (NFT thread). For every input: libauth BCH 2026
// standard and consensus (today's rules: 10,000 B unlocking, 201 B P2S locking, base 41) and bch-spec standard; for
// every transaction: libauth's whole-transaction verification (standard) and its size (<= 100,000 B). Op-cost is
// reported as libauth's and BCHN-adjusted (+ the OP_DEFINE body bytes the input executes, Track 8a).
// Writes results/grade-a.json and prints a summary.  usage: node grade-a.mjs VECTOR.json...
import {writeFileSync} from 'node:fs';
import {readVector} from './layoutn.mjs';
import {vkxA} from './modela.mjs';
import {makePlanA, spendA, evaluateTxA, verifyTxA} from './layouta.mjs';

const plans = {
  '1tx': (vk) => [Array.from({length: Math.ceil(vk.Q / 3)}, (_, i) => Math.min(3, vk.Q - 3 * i))],
  '2tx': (vk) => { const p = Array.from({length: Math.ceil(vk.Q / 3)}, (_, i) => Math.min(3, vk.Q - 3 * i)); return [p.slice(0, -1), p.slice(-1)]; },
};
const roleOf = (plan, i) => (i === 0 ? 'HEAD' : i <= plan.nc ? `CODE${i}` : i === plan.nc + 1 ? 'FIN' : 'QRY');
const rows = [];
for (const path of process.argv.slice(2)) {
  const v = readVector(path); const vk = vkxA(v); const pis = v.public_values.flat().map(BigInt);
  const outputs = v.s4_outputs.map((o) => ({lockingBytecode: Uint8Array.from(Buffer.from(o.lockingBytecode, 'hex')), valueSatoshis: BigInt(o.valueSatoshis)}));
  for (const [pname, counts] of Object.entries(plans)) {
    const plan = makePlanA(vk, counts(vk));
    const sp = spendA(vk, plan, Buffer.from(v.proof_hex, 'hex'), pis, outputs);
    const txs = sp.txs.map((tx, t) => {
      const std = evaluateTxA(tx, 'bchStd'), cons = evaluateTxA(tx, 'bchCons'), spec = evaluateTxA(tx, 'specStd');
      const whole = verifyTxA(tx, 'bchStd');
      const inputs = std.map((r, i) => ({role: roleOf(plan, i), std: r.accepted, cons: cons[i].accepted, spec: spec[i].accepted, err: r.error ?? cons[i].error ?? null,
        unlocking: r.unlocking, opCost: r.opCost, opBchnAdjusted: r.opCost + sp.pg.defineBytes, budget: r.budget, pct: +(100 * (r.opCost + sp.pg.defineBytes) / r.budget).toFixed(2),
        hashIters: r.iters, iterLimit: Math.floor((41 + r.unlocking) / 2)}));
      return {tx: t, bytes: tx.txBytes, inputs: inputs.length, whole: whole === true ? true : String(whole), allStd: inputs.every((x) => x.std && x.cons), allSpec: inputs.every((x) => x.spec), detail: inputs};
    });
    const row = {vector: path.split('/').pop(), plan: pname, txs: txs.length, inputs: txs.reduce((a, t) => a + t.inputs, 0), totalBytes: txs.reduce((a, t) => a + t.bytes, 0),
      accepted: txs.every((t) => t.allStd && t.whole === true && t.bytes <= 100_000), proofBytes: v.proof_hex.length / 2,
      code: sp.pg.code.map((c) => c.length), redeem: sp.pg.redeem.length, defineBytes: sp.pg.defineBytes,
      opTotalBchnAdjusted: txs.reduce((a, t) => a + t.detail.reduce((b, x) => b + x.opBchnAdjusted, 0), 0),
      maxPct: Math.max(...txs.flatMap((t) => t.detail.map((x) => x.pct))), txsDetail: txs};
    rows.push(row);
    console.log(`${row.vector} ${pname}: ${row.accepted ? 'ACCEPTED' : 'NOT ACCEPTED'} ${row.txs} tx, ${row.inputs} inputs, ${txs.map((t) => t.bytes).join(' + ')} B, whole-tx ${txs.map((t) => t.whole).join('/')}, max ${row.maxPct}% of an input's budget, op-cost (BCHN-adj.) ${row.opTotalBchnAdjusted}, spec ${txs.every((t) => t.allSpec)}`);
    for (const t of txs) for (const [i, x] of t.detail.entries()) if (!(x.std && x.cons)) console.log(`   tx${t.tx} in${i} ${x.role}: ${x.err}`);
  }
}
const sum = {};
for (const p of Object.keys(plans)) {
  const r = rows.filter((x) => x.plan === p); if (!r.length) continue;
  const mm = (f) => [Math.min(...r.map(f)), Math.max(...r.map(f))];
  const per = {};
  for (const x of r) for (const t of x.txsDetail) for (const d of t.detail) { const k = d.role; (per[k] ??= []).push(d); }
  sum[p] = {statements: r.length, accepted: r.filter((x) => x.accepted).length, txs: r[0].txs, inputs: r[0].inputs, txBytes: r[0].txsDetail.map((_, t) => mm((x) => x.txsDetail[t].bytes)),
    totalBytes: mm((x) => x.totalBytes), opTotalBchnAdjusted: mm((x) => x.opTotalBchnAdjusted), maxPct: mm((x) => x.maxPct),
    perRole: Object.fromEntries(Object.entries(per).map(([k, ds]) => [k, {unlocking: [Math.min(...ds.map((d) => d.unlocking)), Math.max(...ds.map((d) => d.unlocking))], opBchnAdjusted: [Math.min(...ds.map((d) => d.opBchnAdjusted)), Math.max(...ds.map((d) => d.opBchnAdjusted))], pct: [Math.min(...ds.map((d) => d.pct)), Math.max(...ds.map((d) => d.pct))], hashIters: Math.max(...ds.map((d) => d.hashIters))}]))};
  console.log(`grade-a ${p}: ${sum[p].accepted}/${sum[p].statements} accepted; ${sum[p].txs} tx, ${sum[p].inputs} inputs; tx bytes ${JSON.stringify(sum[p].txBytes)}; total ${JSON.stringify(sum[p].totalBytes)}; op-cost BCHN-adj. total ${JSON.stringify(sum[p].opTotalBchnAdjusted)}; max input ${JSON.stringify(sum[p].maxPct)}%`);
  for (const [k, x] of Object.entries(sum[p].perRole)) console.log(`   ${k}: unlocking ${x.unlocking.join('-')} B, op (BCHN-adj.) ${x.opBchnAdjusted.join('-')}, ${x.pct.join('-')}% of budget, hash iterations <= ${x.hashIters}`);
}
writeFileSync(new URL('./results/grade-a.json', import.meta.url), JSON.stringify({summary: sum, rows}, null, 1) + '\n');

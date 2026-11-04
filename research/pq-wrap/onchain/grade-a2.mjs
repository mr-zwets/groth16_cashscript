#!/usr/bin/env node
// grade-a2.mjs (Track 10 G2): layout a' (today's standard rules) for the shape twin, as Track 8's grade-a.mjs, with a
// plan search instead of Track 8's two fixed plans:
//   per   queries per QRY input (--per; default: the largest of 3, 2, 1 whose QRY unlocking fits 10,000 B)
//   txs   the fewest transactions T such that every transaction fits 100,000 B; each holds HEAD, nc CODE, FIN and an
//         even share of the QRY inputs (the first transaction gets the remainder last); T > 1 uses the NFT thread
// For every input: libauth BCH 2026 standard and consensus (today's rules) and bch-spec standard; for every transaction:
// whole-transaction verification (standard) and size. Op-cost "BCHN-adjusted" = max(std, cons) + OP_DEFINE body bytes
// (Track 8a; exact on BCHN 29.1.0), against the budget (41 + unlocking) * 800.
//   pad   FIN and QRY inputs get a checked zero pad (gena.mjs) sized so that op-cost <= target (0.93) of the budget
//   opt   layout-review optimizations (gena.mjs plan.opt), e.g. --opt sib; absent = the baseline generator. With
//         opt.state the transactions after tx0 run under R1 (STATE, one library input, QRY inputs): tx0 takes as many
//         QRY inputs as fit and the later transactions share the rest; --opt ...,cap=3 adds the per-transaction
//         Merkle cap layer at level 3
// usage: node grade-a2.mjs [--per N] [--nc N] [--maxT N] [--pad 0|1] [--target 0.93] [--opt a,b] [--out FILE] VECTOR.json...
import {writeFileSync} from 'node:fs';
import {readVector} from './layoutn.mjs';
import {vkxA} from './modela.mjs';
import {makePlanA, spendA, evaluateTxA, verifyTxA, parseOpt} from './layouta.mjs';
import {evaluate} from './vm.mjs';

const args = process.argv.slice(2);
const opt = (k, d) => { const i = args.indexOf(k); return i >= 0 ? args[i + 1] : d; };
const files = args.filter((a, i) => !a.startsWith('--') && !['--per', '--nc', '--out', '--maxT', '--pad', '--target', '--opt'].includes(args[i - 1]));
const outFile = opt('--out', new URL('./results/grade-a2.json', import.meta.url).pathname);
const NC = +opt('--nc', 2), MAXT = +opt('--maxT', 8);
const r1Of = (plan, t) => t > 0 && !!plan.opt?.state && plan.txs.length > 1;
export const roleOf = (plan, i, t = 0) => (r1Of(plan, t) ? (i === 0 ? 'STATE' : i === 1 ? 'LIB' : i === 2 && plan.opt?.cap ? 'TOP' : 'QRY')
  : i === 0 ? 'HEAD' : i <= plan.nc ? `CODE${i}` : i === plan.nc + 1 ? 'FIN' : 'QRY');
// OP_DEFINE body bytes of an input of transaction t (R0 or, opt.state, R1)
export const defineBytesOf = (sp, t) => (t > 0 && sp.pg.R1 ? sp.pg.R1.defineBytes : sp.pg.defineBytes);
const split = (Q, per) => Array.from({length: Math.ceil(Q / per)}, (_, i) => Math.min(per, Q - per * i));
const share = (xs, T) => { const out = Array.from({length: T}, () => []); const n = xs.length; let k = 0;
  for (let t = T - 1; t >= 0; t--) { const m = Math.floor(n / T) + (T - 1 - t < n % T ? 1 : 0); for (let j = 0; j < m; j++) out[t].push(xs[k++]); }
  return out.map((o) => o.length ? o : []); };

// op-cost (BCHN-adjusted, loose VM: no density limit) of every input of a built spend
function costs(sp) {
  return sp.txs.map((tx, t) => tx.transaction.inputs.map((_, i) => {
    const r = evaluate('looseStd', null, null, {inputIndex: i, sourceOutputs: tx.sourceOutputs, transaction: tx.transaction});
    const c = evaluate('looseCons', null, null, {inputIndex: i, sourceOutputs: tx.sourceOutputs, transaction: tx.transaction});
    return {ok: r.accepted && c.accepted, err: r.error ?? c.error, op: Math.max(r.opCost, c.opCost) + defineBytesOf(sp, t), unl: tx.unl[i].length};
  }));
}
// pad bytes N (one push of N zero bytes, header included) so that op <= target * (41 + unlocking) * 800
const pushHdr = (n) => (n === 0 ? 1 : n <= 75 ? 1 + n : n <= 255 ? 2 + n : 3 + n);
function padFor(op, unlNoPad, target) {
  let n = 0; while ((41 + unlNoPad - 1 + pushHdr(n)) * 800 * target < op) n += Math.max(1, Math.ceil((op / (800 * target) - 41 - unlNoPad - 2) / 2));
  return n;
}

export function planFor(vk, proof, pis, outputs, {per, nc = NC, pad = true, target = 0.93, opt} = {}) {
  const pers = per ? [per] : [3, 2, 1];
  const tried = [];
  for (const pq of pers) {
    const qs = split(vk.Q, pq);
    let padv = null;
    if (pad) {
      // probe: one transaction, zero pads; measure FIN and QRY, size their pads, re-measure (pads move the reads of FIN)
      padv = {fin: 0, qry: [qs.map(() => 0)]};
      for (let it = 0; it < 4; it++) {
        let sp;
        try { sp = spendA(vk, makePlanA(vk, [qs], {nc, pad: padv, opt}), proof, pis, outputs); } catch (e) { tried.push({per: pq, probe: it, error: String(e.message).slice(0, 160)}); padv = null; break; }
        const cs = costs(sp)[0], fin = nc + 1;
        const next = {fin: padFor(cs[fin].op, cs[fin].unl - pushHdr(padv.fin), target), qry: [qs.map((_, j) => padFor(cs[fin + 1 + j].op, cs[fin + 1 + j].unl - pushHdr(padv.qry[0][j]), target))]};
        const byCount = new Map(); qs.forEach((n, j) => byCount.set(n, Math.max(byCount.get(n) ?? 0, next.qry[0][j])));
        next.qry = [qs.map((n) => byCount.get(n))];
        const same = next.fin <= padv.fin && next.qry[0].every((x, j) => x <= padv.qry[0][j]);
        padv = {fin: Math.max(next.fin, padv.fin), qry: [next.qry[0].map((x, j) => Math.max(x, padv.qry[0][j]))]};
        tried.push({per: pq, probe: it, finOp: cs[fin].op, qryOp: Math.max(...cs.slice(fin + 1).map((x) => x.op)), pad: {fin: padv.fin, qry: Math.max(...padv.qry[0])}});
        if (same) break;
      }
      if (!padv) continue;
    }
    const padOfCount = new Map(); if (padv) qs.forEach((n, j) => padOfCount.set(n, padv.qry[0][j]));
    for (let T = 1; T <= MAXT; T++) {
      if (opt?.state && T > 1) {
        // tx0 (R0) takes as many QRY inputs as fit; the later (R1) transactions share the rest
        let done = null, stop = false;
        for (let n0 = Math.min(qs.length - (T - 1), 12); n0 >= 1; n0--) {
          const counts = [qs.slice(0, n0), ...share(qs.slice(n0), T - 1)];
          if (counts.some((c) => !c.length)) continue;
          const plan = makePlanA(vk, counts, {nc, opt, ...(padv ? {pad: {fin: padv.fin, qry: counts.map((c) => c.map((n) => padOfCount.get(n)))}} : {})});
          let sp;
          try { sp = spendA(vk, plan, proof, pis, outputs); } catch (e) { tried.push({per: pq, T, n0, error: String(e.message).slice(0, 160)}); stop = true; break; }
          const unl = sp.txs.flatMap((tx) => tx.unl.map((u) => u.length));
          const bytes = sp.txs.map((tx) => tx.txBytes);
          tried.push({per: pq, T, n0, maxUnlocking: Math.max(...unl), txBytes: bytes});
          if (Math.max(...unl) > 10_000) { stop = true; break; }
          if (bytes[0] > 100_000) continue;
          if (Math.max(...bytes) <= 100_000) done = {plan, sp, per: pq, T, tried};
          break;
        }
        if (done) return done;
        if (stop) break;
        continue;
      }
      const counts = share(qs, T);
      if (counts.some((c) => !c.length)) break;
      const plan = makePlanA(vk, counts, {nc, opt, ...(padv ? {pad: {fin: padv.fin, qry: counts.map((c) => c.map((n) => padOfCount.get(n)))}} : {})});
      let sp;
      try { sp = spendA(vk, plan, proof, pis, outputs); } catch (e) { tried.push({per: pq, T, error: String(e.message).slice(0, 160)}); break; }
      const unl = sp.txs.flatMap((tx) => tx.unl.map((u) => u.length));
      const bytes = sp.txs.map((tx) => tx.txBytes);
      tried.push({per: pq, T, maxUnlocking: Math.max(...unl), txBytes: bytes});
      if (Math.max(...unl) > 10_000) break;               // more transactions do not shrink an input
      if (Math.max(...bytes) <= 100_000) return {plan, sp, per: pq, T, tried};
    }
  }
  return {plan: null, tried};
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const rows = [];
  for (const path of files) {
    const v = readVector(path); const vk = vkxA(v); const pis = v.public_values.flat().map(BigInt);
    const outputs = v.s4_outputs.map((o) => ({lockingBytecode: Uint8Array.from(Buffer.from(o.lockingBytecode, 'hex')), valueSatoshis: BigInt(o.valueSatoshis)}));
    const proof = Buffer.from(v.proof_hex, 'hex');
    const {plan, sp, per, T, tried} = planFor(vk, proof, pis, outputs, {per: opt('--per') ? +opt('--per') : undefined, pad: opt('--pad') !== '0', target: +opt('--target', 0.93), opt: parseOpt(opt('--opt'))});
    if (!plan) { console.log(`${path.split('/').pop()}: NO PLAN ${JSON.stringify(tried)}`); rows.push({vector: path.split('/').pop(), plan: null, tried}); continue; }
    const txs = sp.txs.map((tx, t) => {
      const std = evaluateTxA(tx, 'bchStd'), cons = evaluateTxA(tx, 'bchCons'), spec = evaluateTxA(tx, 'specStd');
      const whole = verifyTxA(tx, 'bchStd');
      const inputs = std.map((r, i) => {
        const bchn = Math.max(r.opCost, cons[i].opCost) + defineBytesOf(sp, t);
        return {role: roleOf(plan, i, t), std: r.accepted, cons: cons[i].accepted, spec: spec[i].accepted, err: r.error ?? cons[i].error ?? null,
          unlocking: r.unlocking, opCost: r.opCost, opCons: cons[i].opCost, opBchnAdjusted: bchn, budget: r.budget, pct: +(100 * bchn / r.budget).toFixed(2),
          bchnWithinBudget: bchn <= r.budget, hashIters: r.iters, iterLimit: Math.floor((41 + r.unlocking) / 2)};
      });
      return {tx: t, bytes: tx.txBytes, inputs: inputs.length, whole: whole === true ? true : String(whole), allStd: inputs.every((x) => x.std && x.cons && x.bchnWithinBudget), allSpec: inputs.every((x) => x.spec), detail: inputs};
    });
    const row = {vector: path.split('/').pop(), opt: plan.opt ?? {}, per, T, pad: plan.pad ?? null, counts: plan.txs.map((x) => x.qry.map(([a, b]) => b - a)), txs: txs.length, inputs: txs.reduce((a, t) => a + t.inputs, 0),
      totalBytes: txs.reduce((a, t) => a + t.bytes, 0), proofBytes: proof.length,
      accepted: txs.every((t) => t.allStd && t.whole === true && t.bytes <= 100_000),
      code: sp.pg.code.map((c) => c.length), redeem: sp.pg.redeem.length, defineBytes: sp.pg.defineBytes,
      ...(sp.pg.R1 ? {r1: {code: sp.pg.R1.code.map((c) => c.length), redeem: sp.pg.R1.redeem.length, defineBytes: sp.pg.R1.defineBytes, functions: sp.pg.R1.names.length}} : {}),
      opTotalBchnAdjusted: txs.reduce((a, t) => a + t.detail.reduce((b, x) => b + x.opBchnAdjusted, 0), 0),
      maxPct: Math.max(...txs.flatMap((t) => t.detail.map((x) => x.pct))), le95: txs.every((t) => t.detail.every((x) => x.pct <= 95)), tried, txsDetail: txs};
    rows.push(row);
    console.log(`${row.vector}: ${row.accepted ? 'ACCEPTED' : 'NOT ACCEPTED'} ${row.txs} tx, ${row.inputs} inputs (${per} queries per QRY input), ${txs.map((t) => t.bytes).join(' + ')} = ${row.totalBytes} B, whole-tx ${txs.map((t) => t.whole).join('/')}, max ${row.maxPct}% of an input's budget, op-cost (BCHN-adj.) ${row.opTotalBchnAdjusted}, spec ${txs.every((t) => t.allSpec)}, code ${row.code.join('+')} B, define ${row.defineBytes} B${row.r1 ? `, R1 code ${row.r1.code.join('+')} B (redeem ${row.r1.redeem} B, define ${row.r1.defineBytes} B, ${row.r1.functions} functions)` : ''}`);
    for (const t of txs) for (const [i, x] of t.detail.entries()) if (!(x.std && x.cons && x.bchnWithinBudget)) console.log(`   tx${t.tx} in${i} ${x.role}: ${x.err} (${x.pct}%)`);
    const per2 = {};
    for (const t of txs) for (const d of t.detail) (per2[`${t.tx}:${d.role}`] ??= []).push(d);
    for (const [k, ds] of Object.entries(per2)) console.log(`   tx${k}: x${ds.length} unlocking ${Math.min(...ds.map((d) => d.unlocking))}-${Math.max(...ds.map((d) => d.unlocking))} B, op (BCHN-adj.) ${Math.min(...ds.map((d) => d.opBchnAdjusted))}-${Math.max(...ds.map((d) => d.opBchnAdjusted))}, ${Math.min(...ds.map((d) => d.pct))}-${Math.max(...ds.map((d) => d.pct))}%`);
  }
  writeFileSync(outFile, JSON.stringify({rows}, null, 1) + '\n');
}

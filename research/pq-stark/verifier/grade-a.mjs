// Grade layout (a) (today's standard rules) for every vector given. Per input: the zero pad (pad slot of HEAD and QRY
// inputs) grows by least fixpoint until the BCHN-adjusted standard op-cost is <= 94% of the input's budget
// (41 + unlocking) * 800 and the hash iterations fit 0.5 * (41 + unlocking); then every input is evaluated on the real
// BCH 2026 VM (standard and consensus) and every transaction is verified as a whole (libauth vm.verify).
// BCHN-adjusted = libauth op-cost + the body bytes of every OP_DEFINE executed by that input (code blobs defined by R,
// every function defined by the blobs): every input runs R, so every input pays all of them.
// usage: node grade-a.mjs vectors...   -> results/layout-a.json
import {writeFileSync, readFileSync, mkdirSync} from 'node:fs';
import {loadVector, makePlan, programA, witnessesA, txsA, evaluateTx, verifyTx, encodeA} from './layout-a.mjs';

const MARGIN = 0.94;
const pushLen = (n) => n + (n < 76 ? 1 : n < 256 ? 2 : 3);
export function planAndProgram(vk, pis, opts = {}) {
  let nc = 1, plan, pg;
  for (;;) {
    try {
      const pathBytes = vk.trees.reduce((t, tr) => t + tr.depth * vk.h, 0);
      plan = makePlan(vk, {pathBytes, codeBytes: Array(nc).fill(10_000), redeemBytes: 120 * nc, ptBytes: 0});
      for (let it = 0; it < 4; it++) {
        pg = programA(vk, pis, plan, {...opts, codeBlobs: nc});
        const ptBytes = pg.ptOrder.reduce((a, x) => a + pushLen({FIN: vk.L * vk.e8, ROOTS: 1 + vk.nRoots * vk.h, OOD: vk.oodVals * vk.e8, BPOW: 8, FROOTS: vk.logArities.length * vk.h, CPOW: 8 * vk.logArities.length, QPOW: 8}[x]), 0);
        const next = makePlan(vk, {pathBytes, codeBytes: pg.code.map((c) => c.length), redeemBytes: pg.redeem.length, ptBytes});
        if (JSON.stringify(next.txs) === JSON.stringify(plan.txs)) break;
        plan = next;
      }
      pg = programA(vk, pis, plan, {...opts, codeBlobs: nc});
      return {plan, pg};
    } catch (e) { if (!/does not fit/.test(e.message) || nc >= 4) throw e; nc++; }
  }
}
export function gradeA(vk, proof, pis, opts = {}) {
  const {plan, pg} = planAndProgram(vk, pis, opts);
  const enc = encodeA(vk, proof, pis);
  const defineBytes = pg.code.reduce((a, c) => a + c.length, 0) + [...pg.fns.values()].reduce((a, f) => a + f.body.length, 0);
  const pads = {};
  let txs, res;
  for (let it = 0; it < 12; it++) {
    txs = txsA(vk, plan, pg, witnessesA(vk, plan, pg, enc, pads), enc.G);
    res = txs.map((tx) => evaluateTx(tx, 'looseStd'));
    let changed = false;
    res.forEach((rs, t) => rs.forEach((r, i) => {
      if (i >= 1 && i <= pg.nc) return;   // CODE inputs have no pad slot
      const need = Math.max(Math.ceil((r.opCost + defineBytes) / (800 * MARGIN)) - 41, Math.ceil(r.iters / 0.5) - 41);
      if (need > r.unlocking) { pads[`${t}:${i}`] = (pads[`${t}:${i}`] ?? 0) + need - r.unlocking; changed = true; }
    }));
    if (!changed) break;
  }
  const real = txs.map((tx) => ({std: evaluateTx(tx, 'bchStd'), cons: evaluateTx(tx, 'bchCons'), verifyStd: verifyTx(tx, 'bchStd'), verifyCons: verifyTx(tx, 'bchCons')}));
  const role = (t, i) => (i === 0 ? 'HEAD' : i <= pg.nc ? 'CODE' : 'QRY ' + plan.txs[t].qry[i - 1 - pg.nc].join('-'));
  const out = {
    air: vk.air, set: null, proofBytes: proof.length, queries: vk.Q, perInput: plan.per, codeBlobs: pg.nc, codeBytes: pg.code.map((c) => c.length), redeemBytes: pg.redeem.length, defineBytes,
    transactions: txs.length, inputs: txs.reduce((a, t) => a + t.unl.length, 0), totalBytes: txs.reduce((a, t) => a + t.txBytes, 0),
    txBytes: txs.map((t) => t.txBytes), padBytes: Object.values(pads).reduce((a, b) => a + b, 0),
    accepted: real.every((r) => r.std.every((x) => x.accepted) && r.cons.every((x) => x.accepted) && r.verifyStd === true && r.verifyCons === true),
    txVerify: real.map((r) => ({std: r.verifyStd, cons: r.verifyCons})),
    fitsStandard: txs.every((t) => t.txBytes <= 100_000) && txs.every((t) => t.unl.every((u) => u.length <= 10_000)),
    opStdTotal: res.flat().reduce((a, r) => a + r.opCost, 0), opConsTotal: real.flatMap((r) => r.cons).reduce((a, r) => a + r.opCost, 0),
    opBchnTotal: real.flatMap((r) => r.cons).reduce((a, r) => a + r.opCost + defineBytes, 0),
    itersTotal: res.flat().reduce((a, r) => a + r.iters, 0),
    perInputDetail: res.map((rs, t) => rs.map((r, i) => ({tx: t, input: i, role: role(t, i),
      unlocking: r.unlocking, pad: pads[`${t}:${i}`] ?? 0, opStd: r.opCost, opCons: real[t].cons[i].opCost, opBchn: real[t].cons[i].opCost + defineBytes,
      budget: r.budget, pct: +(100 * (r.opCost + defineBytes) / r.budget).toFixed(1), iters: r.iters, iterLimitStd: Math.floor(0.5 * (41 + r.unlocking)),
      std: real[t].std[i].accepted, cons: real[t].cons[i].accepted, err: real[t].std[i].error ?? real[t].cons[i].error}))),
  };
  return {out, plan, pg, enc, txs, pads};
}
if (import.meta.url === `file://${process.argv[1]}`) {
  const all = [];
  for (const path of process.argv.slice(2).filter((x) => x.endsWith('.json'))) {
    const {v, vk, proof, pis} = loadVector(path);
    const {out} = gradeA(vk, proof, pis);
    out.vector = path.split('/').pop(); out.set = v.set.name; out.zk = !!v.set.zk;
    all.push(out);
    console.log(`${out.vector.padEnd(24)} tx ${out.transactions} inputs ${out.inputs} bytes ${out.totalBytes} (${out.txBytes.join(' + ')}) pad ${out.padBytes} code ${out.codeBytes.join('+')} R ${out.redeemBytes} | op ${out.opStdTotal} bchn ${out.opBchnTotal} | real std+cons+verify ${out.accepted} | standard ${out.fitsStandard}`);
    for (const r of out.perInputDetail.flat()) console.log(`   tx${r.tx} in${String(r.input).padStart(2)} ${r.role.padEnd(10)} unl ${String(r.unlocking).padStart(5)} pad ${String(r.pad).padStart(4)} op ${String(r.opBchn).padStart(8)} / ${r.budget} ${r.pct}% it ${r.iters}/${r.iterLimitStd} ${r.std && r.cons ? 'ok' : 'REJ ' + r.err}`);
    if (!out.accepted) console.log('   txVerify', JSON.stringify(out.txVerify));
  }
  mkdirSync(new URL('./results/', import.meta.url), {recursive: true});
  const file = new URL('./results/layout-a.json', import.meta.url);
  let prev = []; try { prev = JSON.parse(readFileSync(file, 'utf8')); } catch {}
  writeFileSync(file, JSON.stringify([...prev.filter((x) => !all.some((y) => y.vector === x.vector)), ...all].sort((a, b) => a.vector.localeCompare(b.vector)), null, 1) + '\n');
}

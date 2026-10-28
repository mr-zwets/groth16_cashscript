// Grade layout (a) (today's standard rules) for every vector given. Per input: the zero pad (pad slot of HEAD and QRY
// inputs) is grown by least fixpoint until the BCHN-adjusted standard op-cost is <= 94% of the input's budget
// (41 + unlocking) * 800 and the hash iterations fit 0.5 * (41 + unlocking); then every input is evaluated on the real
// BCH 2026 VM (standard and consensus) and the transactions are checked against 100,000 B.
// BCHN-adjusted = libauth standard op-cost + the body bytes of every OP_DEFINE (MAIN defined by R, every function by MAIN),
// charged in full to every input including CODE: a conservative upper bound, not an exact per-input figure.
// usage: node grade-a.mjs [--per 3] vectors...   -> results/layout-a.json
import {writeFileSync, readFileSync, mkdirSync} from 'node:fs';
import {loadVector, makePlan, programA, witnessesA, txsA, evaluateTx, verifyTx} from './layout-a.mjs';
import {encodeA} from './model.mjs';
import {sha} from './field.mjs';

const args = process.argv.slice(2);
const per = args.includes('--per') ? Number(args[args.indexOf('--per') + 1]) : 3;
const files = args.filter((x) => x.endsWith('.json'));
const MARGIN = 0.94;
export function gradeA(prm, proof, {per: perQ = per, fast = !args.includes('--compact')} = {}) {
  const perTx = prm.s > 30 ? Math.ceil(prm.s / 2) : prm.s;  // P128 / U100: two transactions
  const plan = makePlan(prm, {per: perQ, perTx});
  const st = Uint8Array.from(proof.subarray(0, 16));
  const pg = programA(prm, st, plan, {fast});
  const enc = encodeA(prm, proof);
  if (plan.thread) plan.thread.commitment = sha(Buffer.from('pq-hash/thread'), enc.tr.G, Uint8Array.of(1));
  const defineBytes = pg.code.length + [...pg.fns.values()].reduce((a, f) => a + f.body.length, 0);
  const pads = {};
  let txs, res;
  for (let it = 0; it < 12; it++) {
    txs = txsA(prm, plan, pg, witnessesA(prm, plan, pg, enc, pads));
    res = txs.map((tx) => evaluateTx(tx, 'looseStd'));
    let changed = false;
    res.forEach((rs, t) => rs.forEach((r, i) => {
      if (i === 1) return;   // CODE input has no pad slot (its op-cost is small)
      const need = Math.max(Math.ceil((r.opCost + defineBytes) / (800 * MARGIN)) - 41, Math.ceil(r.iters / 0.5) - 41);
      if (need > r.unlocking) { pads[`${t}:${i}`] = (pads[`${t}:${i}`] ?? 0) + need - r.unlocking; changed = true; }
    }));
    if (!changed) break;
  }
  const real = txs.map((tx) => ({std: evaluateTx(tx, 'bchStd'), cons: evaluateTx(tx, 'bchCons'), verifyStd: verifyTx(tx, 'bchStd'), verifyCons: verifyTx(tx, 'bchCons')}));
  const out = {
    set: prm.name, variant: fast ? 'fast' : 'compact', proofBytes: proof.length, queries: prm.s, perInput: perQ, codeBytes: pg.code.length, redeemBytes: pg.redeem.length, defineBytes,
    transactions: txs.length, inputs: txs.reduce((a, t) => a + t.unl.length, 0), totalBytes: txs.reduce((a, t) => a + t.txBytes, 0),
    txBytes: txs.map((t) => t.txBytes), padBytes: Object.values(pads).reduce((a, b) => a + b, 0),
    accepted: real.every((r) => r.std.every((x) => x.accepted) && r.cons.every((x) => x.accepted) && r.verifyStd === true && r.verifyCons === true),
    txVerify: real.map((r) => ({std: r.verifyStd, cons: r.verifyCons})),
    // BCHN adjustment here is an upper bound: every input (CODE included) is charged the full code plus every function body
    opBchnBasis: 'standard libauth op-cost + all OP_DEFINE body bytes per input (upper bound)',
    fitsStandard: txs.every((t) => t.txBytes <= 100_000) && txs.every((t) => t.unl.every((u) => u.length <= 10_000)),
    opStdTotal: res.flat().reduce((a, r) => a + r.opCost, 0), opBchnTotal: res.flat().reduce((a, r) => a + r.opCost + defineBytes, 0),
    itersTotal: res.flat().reduce((a, r) => a + r.iters, 0),
    perInputDetail: res.map((rs, t) => rs.map((r, i) => ({tx: t, input: i, role: i === 0 ? 'HEAD' : i === 1 ? 'CODE' : 'QRY ' + plan.txs[t].qry[i - 2].join('-'),
      unlocking: r.unlocking, pad: pads[`${t}:${i}`] ?? 0, opStd: r.opCost, opCons: real[t].cons[i].opCost, opBchn: r.opCost + defineBytes,
      budget: r.budget, pct: +(100 * (r.opCost + defineBytes) / r.budget).toFixed(1), iters: r.iters, iterLimitStd: Math.floor(0.5 * (41 + r.unlocking)),
      std: real[t].std[i].accepted, cons: real[t].cons[i].accepted, err: real[t].std[i].error ?? real[t].cons[i].error}))),
  };
  return {out, plan, pg, enc, txs, pads};
}
if (import.meta.url === `file://${process.argv[1]}`) {
  const all = [];
  for (const path of files) {
    const {prm, proof} = loadVector(path);
    const {out} = gradeA(prm, proof);
    out.vector = path.split('/').pop();
    all.push(out);
    console.log(`${out.vector.padEnd(12)} tx ${out.transactions} inputs ${out.inputs} bytes ${out.totalBytes} (${out.txBytes.join(' + ')}) pad ${out.padBytes} code ${out.codeBytes} | op ${out.opStdTotal} bchn ${out.opBchnTotal} | real std+cons (per input and full-tx verify) ${out.accepted} | standard ${out.fitsStandard}`);
    for (const r of out.perInputDetail.flat()) console.log(`   tx${r.tx} in${r.input} ${r.role.padEnd(9)} unl ${String(r.unlocking).padStart(5)} pad ${String(r.pad).padStart(4)} op ${String(r.opBchn).padStart(8)} / ${r.budget} ${r.pct}% it ${r.iters}/${r.iterLimitStd} ${r.std && r.cons ? 'ok' : 'REJ ' + r.err}`);
  }
  mkdirSync(new URL('./results/', import.meta.url), {recursive: true});
  const file = new URL('./results/layout-a.json', import.meta.url);
  let prev = []; try { prev = JSON.parse(readFileSync(file, 'utf8')); } catch {}
  writeFileSync(file, JSON.stringify([...prev.filter((x) => !all.some((y) => y.vector === x.vector && y.perInput === x.perInput && y.variant === x.variant)), ...all].sort((a, b) => a.vector.localeCompare(b.vector)), null, 1) + '\n');
}

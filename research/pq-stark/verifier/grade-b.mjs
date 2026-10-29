// Grade layout (b) (one input) for every vector given: bytes, op-cost (libauth standard/consensus, BCHN-adjusted),
// hash iterations, acceptance on TXv5 as written (BCH 2026 + 100,000 B items/scripts, density base 41: the
// "100 KB inputs" regime) and on libauth bch-spec (density base 10,000); when TXv5 rejects for budget, the least zero
// pad (fixpoint, as zk-verifier-bench src/harness/txv5.ts). Writes results/layout-b.json (merged by vector).
// usage: node grade-b.mjs vectors...
import {writeFileSync, readFileSync, mkdirSync} from 'node:fs';
import {loadVector, spendB} from './layout-b.mjs';
import {evaluate} from './vm.mjs';

const TXOVER = (L) => 4 + 1 + 36 + (L < 253 ? 1 : L < 65536 ? 3 : 5) + 4 + 1 + 34 + 4; // 1 input, 1 P2PKH output
const out = [];
for (const path of process.argv.slice(2)) {
  const {v, vk, proof, pis} = loadVector(path);
  const sp = spendB(vk, pis, proof, pis);
  const L = sp.unlocking.length;
  const bchnExtra = [...sp.built.fns.values()].reduce((a, f) => a + f.body.length, 0);
  const run = (vm, s = sp) => evaluate(vm, s.locking, s.unlocking);
  const ls = run('looseStd'), lc = run('looseCons');
  const ts = run('txv5Std'), tc = run('txv5Cons');
  const ss = run('specStd'), sc = run('specCons');
  let pad = 0, pv = sp, tries = 0;
  if (!ts.accepted && ls.accepted && L < 100_000) {
    for (;;) {
      pv = spendB(vk, pis, proof, pis, {padSlot: true, pad});
      const u = run('txv5uStd', pv);
      if (!u.accepted) { pv.unbudgetedError = u.error; break; }
      const need = Math.max(Math.ceil(u.opCost / 800) - 41, Math.ceil(u.iters / 0.5) - 41);
      if (pv.unlocking.length >= need || ++tries > 20) break;
      pad += need - pv.unlocking.length;
    }
  }
  const ps = pv === sp ? ts : run('txv5Std', pv), pc = pv === sp ? tc : run('txv5Cons', pv);
  const r = {
    vector: path.split('/').pop(), air: v.air, set: v.set.name, zk: !!v.set.zk, ext: v.set.ext, queries: vk.Q, proofBytes: proof.length,
    redeemBytes: sp.redeem.length, witnessBytes: sp.items.reduce((a, x) => a + x.length, 0), unlockingBytes: L, txBytes: L + TXOVER(L),
    opStd: ls.opCost, opCons: lc.opCost, opBchnAdjusted: lc.opCost + bchnExtra, opBchnAdjustedStd: ls.opCost + bchnExtra, defineBodyBytes: bchnExtra,
    hashIterations: ls.iters, instructions: ls.instr,
    accepted: {loose: ls.accepted && lc.accepted, txv5Std: ts.accepted, txv5Cons: tc.accepted, specStd: ss.accepted, specCons: sc.accepted},
    errors: {loose: ls.error, txv5Std: ts.error, specStd: ss.error},
    txv5Budget: (41 + L) * 800, specBudget: (10000 + L) * 800,
    txv5Pad: pv === sp ? null : {unbudgetedError: pv.unbudgetedError, padBytes: pv.unlocking.length - L, unlockingBytes: pv.unlocking.length, txBytes: pv.unlocking.length + TXOVER(pv.unlocking.length), std: ps.accepted, cons: pc.accepted},
    fitsOneInput100k: L <= 100_000, fitsTx100k: L + TXOVER(L) <= 100_000,
  };
  r.txv5Pct = +(100 * r.opStd / r.txv5Budget).toFixed(1); r.specPct = +(100 * r.opStd / r.specBudget).toFixed(1);
  out.push(r);
  console.log(`${r.vector.padEnd(24)} proof ${r.proofBytes} unl ${L} redeem ${r.redeemBytes} | op ${r.opStd} cons ${r.opCons} bchn ${r.opBchnAdjusted} | loose ${r.accepted.loose} txv5 ${ts.accepted}/${tc.accepted} ${r.txv5Pct}%${r.txv5Pad ? ` pad ${r.txv5Pad.padBytes} -> ${r.txv5Pad.std}/${r.txv5Pad.cons}` : ''} | spec ${ss.accepted}/${sc.accepted} ${r.specPct}%${ts.accepted ? '' : ' txv5err ' + ts.error}`);
}
mkdirSync(new URL('./results/', import.meta.url), {recursive: true});
const file = new URL('./results/layout-b.json', import.meta.url);
let prev = []; try { prev = JSON.parse(readFileSync(file, 'utf8')); } catch {}
const merged = [...prev.filter((x) => !out.some((y) => y.vector === x.vector)), ...out].sort((a, b) => a.vector.localeCompare(b.vector));
writeFileSync(file, JSON.stringify(merged, null, 1) + '\n');

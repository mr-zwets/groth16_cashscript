// Grade layout (b) (one input) for every vector given: bytes, op-cost (libauth standard/consensus, BCHN-adjusted),
// hash iterations, acceptance on libauth BCH_SPEC (density base 10,000) and on TXv5 as written (BCH 2026 + 100 kB
// items, density base 41); when TXv5 rejects for budget, the least zero pad (least fixpoint, as zk-verifier-bench
// src/harness/txv5.ts) and the padded figures. Writes results/layout-b.json.
// usage: node grade-b.mjs vectors...
import {writeFileSync, mkdirSync} from 'node:fs';
import {loadVector, spendB} from './layout-b.mjs';
import {evaluate} from './vm.mjs';

const TXOVER = (L) => 4 + 1 + 36 + (L < 253 ? 1 : L < 65536 ? 3 : 5) + 4 + 1 + 34 + 4; // 1 input, 1 P2PKH output
const out = [];
for (const path of process.argv.slice(2)) {
  const {v, prm, proof} = loadVector(path);
  const st = Uint8Array.from(proof.subarray(0, 16));
  const sp = spendB(prm, st, proof);
  const L = sp.unlocking.length;
  const bchnExtra = [...sp.built.fns.values()].reduce((a, f) => a + f.body.length, 0);
  const run = (vm, s = sp) => evaluate(vm, s.locking, s.unlocking);
  const ls = run('looseStd'), lc = run('looseCons');
  const ss = run('specStd'), sc = run('specCons');
  const ts = run('txv5Std'), tc = run('txv5Cons');
  const bs = run('bchStd');
  // TXv5 padding (variant with a pad slot): least fixpoint over op-cost and hash iterations (standard: 0.5/B)
  let pad = 0, pv, tries = 0;
  for (;;) {
    pv = spendB(prm, st, proof, {padSlot: true, pad});
    const u = run('txv5uStd', pv);
    if (!u.accepted) { pv.unbudgetedError = u.error; break; }
    const need = Math.max(Math.ceil(u.opCost / 800) - 41, Math.ceil(u.iters / 0.5) - 41);
    if (pv.unlocking.length >= need || ++tries > 20) break;
    pad += need - pv.unlocking.length;
  }
  const ps = run('txv5Std', pv), pc = run('txv5Cons', pv);
  const r = {
    set: prm.name, vector: path.split('/').pop(), proofBytes: proof.length, queries: prm.s, redeemBytes: sp.redeem.length,
    witnessBytes: L - sp.redeem.length - 3, unlockingBytes: L, txBytes: L + TXOVER(L),
    opStd: ls.opCost, opCons: lc.opCost, opBchnAdjusted: lc.opCost + bchnExtra, opBchnAdjustedStd: ls.opCost + bchnExtra, defineBodyBytes: bchnExtra,
    hashIterations: ls.iters, instructions: ls.instr,
    accepted: {loose: ls.accepted && lc.accepted, specStd: ss.accepted, specCons: sc.accepted, txv5Std: ts.accepted, txv5Cons: tc.accepted, bch2026Std: bs.accepted},
    errors: {specStd: ss.error, txv5Std: ts.error, txv5Cons: tc.error, bch2026Std: bs.error},
    specBudget: (10000 + L) * 800, txv5Budget: (41 + L) * 800,
    txv5Pad: {unbudgetedError: pv.unbudgetedError, padBytes: pv.unlocking.length - L, unlockingBytes: pv.unlocking.length, txBytes: pv.unlocking.length + TXOVER(pv.unlocking.length), std: ps.accepted, cons: pc.accepted, opStd: ps.opCost},
    fitsStandardTx: L + TXOVER(L) <= 100_000,
  };
  r.specPct = +(100 * r.opStd / r.specBudget).toFixed(1); r.txv5Pct = +(100 * r.opStd / r.txv5Budget).toFixed(1);
  out.push(r);
  console.log(`${r.vector.padEnd(12)} proof ${r.proofBytes} unl ${L} tx ${r.txBytes} redeem ${r.redeemBytes} | op std ${r.opStd} cons ${r.opCons} bchn ${r.opBchnAdjusted} it ${r.hashIterations} | spec ${ss.accepted}/${sc.accepted} ${r.specPct}% | txv5 ${ts.accepted}/${tc.accepted} ${r.txv5Pct}% pad ${r.txv5Pad.padBytes} -> ${r.txv5Pad.std}/${r.txv5Pad.cons} tx ${r.txv5Pad.txBytes} | std-tx ${r.fitsStandardTx}`);
}
mkdirSync(new URL('./results/', import.meta.url), {recursive: true});
const file = new URL('./results/layout-b.json', import.meta.url);
let prev = []; try { prev = JSON.parse((await import('node:fs')).readFileSync(file, 'utf8')); } catch {}
const merged = [...prev.filter((x) => !out.some((y) => y.vector === x.vector)), ...out].sort((a, b) => a.vector.localeCompare(b.vector));
writeFileSync(file, JSON.stringify(merged, null, 1) + '\n');

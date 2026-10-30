#!/usr/bin/env node
// grade-b.mjs: layout (b) (one input) for every transaction-bound M1 vector (gen-statements.mjs): bytes, op-cost
// (libauth standard / consensus, BCHN-adjusted = libauth standard + OP_DEFINE body bytes, Track 8a), hash iterations,
// and the verdict in four regimes:
//   today   real BCH 2026 relay rules (10,000 B unlocking, 201 B P2S locking, 100,000 B tx)
//   r100    one 100 KB input: per-input unlocking, bytecode and stack-item limits raised to 100,000 B (density base 41,
//           tx limit 100,000 B unchanged): relay/standardness limits raised
//   spec    libauth bch-spec (density base 10,000, 100,000 B scripts)
//   loose   every ceiling lifted (a reject there is a failed check)
// Input verdicts use the spending transaction (its outputs fix CTX); libauth's whole-transaction verify is run too.
// usage: node grade-b.mjs [--out FILE] VECTOR.json...
import {writeFileSync, mkdirSync} from 'node:fs';
import {encodeTransactionBch} from '@bitauth/libauth';
import {loadVector, spendB} from './layout-b.mjs';
import {evaluate, verifyTx} from './vm.mjs';

const args = process.argv.slice(2);
const oi = args.indexOf('--out'); const outFile = oi >= 0 ? args[oi + 1] : new URL('./results/grade-b.json', import.meta.url).pathname;
const files = args.filter((a, i) => !a.startsWith('--') && args[i - 1] !== '--out');
export const outputsOf = (v) => v.s4_outputs.map((o) => ({lockingBytecode: Uint8Array.from(Buffer.from(o.lockingBytecode, 'hex')), valueSatoshis: BigInt(o.valueSatoshis)}));
const MODEL = {params8: 28_255_740, designLow: 30_000_000, designHigh: 32_000_000};
const rows = [];
for (const path of files) {
  const {v, vk, proof, pis} = loadVector(path);
  const outs = outputsOf(v);
  const sp = spendB(vk, pis.slice(0, 4), proof, pis, outs);
  const L = sp.unlocking.length, tx = encodeTransactionBch(sp.prog.transaction).length;
  const defBytes = [...sp.built.fns.values()].reduce((a, f) => a + f.body.length, 0);
  const run = (vm) => evaluate(vm, sp.locking, sp.unlocking, sp.prog);
  const R = Object.fromEntries(['looseStd', 'looseCons', 'r100Std', 'r100Cons', 'bchStd', 'bchCons', 'specStd', 'specCons'].map((k) => [k, run(k)]));
  const T = Object.fromEntries(['r100Std', 'r100Cons', 'bchStd', 'specStd', 'specCons'].map((k) => [k, verifyTx(k, sp.prog)]));
  const op = R.looseStd.opCost, bchn = op + defBytes;
  const r = {
    vector: path.split('/').pop(), leaf: v.s4_leaf, proofBytes: proof.length, redeemBytes: sp.redeem.length,
    witnessBytes: sp.items.reduce((a, x) => a + x.length, 0), unlockingBytes: L, lockingBytes: sp.locking.length, txBytes: tx,
    opStd: op, opCons: R.looseCons.opCost, defineBodyBytes: defBytes, opBchnAdjusted: bchn, opBchnAdjustedCons: R.looseCons.opCost + defBytes,
    hashIterations: R.looseStd.iters, instructions: R.looseStd.instr,
    budgetR100: (41 + L) * 800, budgetSpec: (10_000 + L) * 800,
    // BCHN counts OP_DEFINE body bytes on top of libauth's op-cost (Track 8a): gate on the adjusted value too
    bchnWithinBudget: {r100: bchn <= (41 + L) * 800 && R.looseCons.opCost + defBytes <= (41 + L) * 800, spec: bchn <= (10_000 + L) * 800},
    pctR100: +(100 * bchn / ((41 + L) * 800)).toFixed(1), pctSpec: +(100 * bchn / ((10_000 + L) * 800)).toFixed(1),
    vsModel: {params8Pct: +(100 * (bchn / MODEL.params8 - 1)).toFixed(1), designMidPct: +(100 * (bchn / 31_000_000 - 1)).toFixed(1)},
    accepted: Object.fromEntries(Object.entries(R).map(([k, x]) => [k, x.accepted])),
    errors: Object.fromEntries(Object.entries(R).filter(([, x]) => !x.accepted).map(([k, x]) => [k, String(x.error).slice(0, 160)])),
    txVerify: Object.fromEntries(Object.entries(T).map(([k, x]) => [k, x === true ? true : String(x).slice(0, 200)])),
    dag: sp.built.dagStats,
  };
  rows.push(r);
  const a = r.accepted;
  console.log(`${r.vector.padEnd(22)} proof ${r.proofBytes} unl ${L} tx ${tx} redeem ${r.redeemBytes} | op ${op} bchn ${bchn} (${r.pctR100}% r100, ${r.pctSpec}% spec; model ${r.vsModel.params8Pct >= 0 ? '+' : ''}${r.vsModel.params8Pct}%) | loose ${a.looseStd}/${a.looseCons} r100 ${a.r100Std}/${a.r100Cons} tx ${T.r100Std === true} | spec ${a.specStd}/${a.specCons} tx ${T.specStd === true} | today ${a.bchStd}/${a.bchCons}`);
}
const ok = rows.every((r) => r.accepted.looseStd && r.accepted.looseCons && r.accepted.r100Std && r.accepted.r100Cons && r.txVerify.r100Std === true && r.accepted.specStd && r.accepted.specCons && r.bchnWithinBudget.r100 && r.bchnWithinBudget.spec && r.unlockingBytes <= 100_000 && r.txBytes <= 100_000);
const stat = (k) => { const xs = rows.map((r) => r[k]); return {min: Math.min(...xs), max: Math.max(...xs), mean: Math.round(xs.reduce((a, x) => a + x, 0) / xs.length)}; };
const summary = {vectors: rows.length, allAcceptedR100AndSpec: ok, proofBytes: stat('proofBytes'), unlockingBytes: stat('unlockingBytes'), txBytes: stat('txBytes'),
  redeemBytes: stat('redeemBytes'), opBchnAdjusted: stat('opBchnAdjusted'), opCons: stat('opCons'), pctR100: stat('pctR100'), pctSpec: stat('pctSpec'), model: MODEL,
  todayAccepted: rows.filter((r) => r.accepted.bchStd || r.accepted.bchCons).length, todayErrors: [...new Set(rows.map((r) => r.errors.bchStd))]};
mkdirSync(new URL('./results/', import.meta.url), {recursive: true});
writeFileSync(outFile, JSON.stringify({summary, rows}, null, 1) + '\n');
console.log(JSON.stringify(summary));
process.exit(ok ? 0 : 1);

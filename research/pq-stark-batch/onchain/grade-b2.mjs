#!/usr/bin/env node
// grade-b2.mjs: layout b2 (two inputs) for transaction-bound M1/M2 statements (pool statement: ROOT constant, NF
// witness, CTX from the spending transaction): bytes, op-cost per input (libauth, and BCHN-adjusted = libauth +
// OP_DEFINE body bytes, Track 8a; each input defines the whole library) and the verdicts per regime:
//   today   BCH 2026 relay rules (10,000 B unlocking, 201 B P2S locking, 100,000 B transaction)
//   r100    per-input unlocking, bytecode and stack-item limits raised to 100,000 B; transaction limit 100,000 B
//   r100t   r100 with the standard transaction size raised to 200,000 B (needed when the two inputs exceed 100 KB)
//   spec    libauth bch-spec (density base 10,000)
// Relay/standardness limits raised, not a new transaction version.
// usage: node grade-b2.mjs [--out FILE] [--qa N] VECTOR.json...
import {writeFileSync, mkdirSync} from 'node:fs';
import {encodeTransactionBch} from '@bitauth/libauth';
import {readVector, vkxN, stmtFor, spendB2} from './layoutn.mjs';
import {evaluate} from './vm.mjs';
import {verifyTxN} from './vmn.mjs';

const args = process.argv.slice(2);
const oi = args.indexOf('--out'); const outFile = oi >= 0 ? args[oi + 1] : new URL('./results/grade-b2.json', import.meta.url).pathname;
const qi = args.indexOf('--qa'); const QAarg = qi >= 0 ? +args[qi + 1] : null;
const files = args.filter((a, i) => !a.startsWith('--') && args[i - 1] !== '--out' && args[i - 1] !== '--qa');
const outputsOf = (v) => v.s4_outputs.map((o) => ({lockingBytecode: Uint8Array.from(Buffer.from(o.lockingBytecode, 'hex')), valueSatoshis: BigInt(o.valueSatoshis)}));
const rows = [];
for (const path of files) {
  const v = readVector(path); const vk = vkxN(v);
  if (vk.stmt !== 'pool') throw new Error(`${path}: not a pool statement`);
  const pis = v.public_values.flat().map(BigInt);
  const QA = QAarg ?? (vk.inst.length > 1 ? 9 : 12);
  const sp = spendB2(vk, stmtFor(vk, pis, {mode: 'pool', ctx: 'tx'}), QA, Buffer.from(v.proof_hex, 'hex'), pis, outputsOf(v));
  const defBytes = [...sp.built.g.fns.values()].reduce((a, f) => a + f.body.length, 0);
  const txBytes = encodeTransactionBch(sp.tx).length;
  const inputs = [0, 1].map((i) => {
    const R = Object.fromEntries(['looseStd', 'looseCons', 'r100Std', 'r100Cons', 'bchStd', 'bchCons', 'specStd', 'specCons'].map((k) => [k, evaluate(k, null, null, sp.progs[i])]));
    const L = i ? sp.unlocking1.length : sp.unlocking0.length;
    const op = R.looseStd.opCost, bchn = op + defBytes;
    return {
      unlockingBytes: L, lockingBytes: (i ? sp.locking1 : sp.locking0).length, opStd: op, opCons: R.looseCons.opCost, opBchnAdjusted: bchn,
      budgetR100: (41 + L) * 800, pctR100: +(100 * bchn / ((41 + L) * 800)).toFixed(1), pctSpec: +(100 * bchn / ((10_000 + L) * 800)).toFixed(1),
      hashIterations: R.looseStd.iters, accepted: Object.fromEntries(Object.entries(R).map(([k, x]) => [k, x.accepted])),
      errors: Object.fromEntries(Object.entries(R).filter(([, x]) => !x.accepted).map(([k, x]) => [k, String(x.error).slice(0, 140)])),
    };
  });
  const T = Object.fromEntries(['r100Std', 'r100Cons', 'r100tStd', 'r100tCons', 'specStd', 'bchStd'].map((k) => { const x = verifyTxN(k, sp.sourceOutputs, sp.tx); return [k, x === true ? true : String(x).slice(0, 160)]; }));
  const r = {
    vector: path.split('/').pop(), statement: v.case.split('@')[0], leaf: v.s4_leaf, QA, proofBytes: v.proof_hex.length / 2, libBytes: sp.lib.length, defineBodyBytes: defBytes,
    txBytes, totalUnlocking: inputs[0].unlockingBytes + inputs[1].unlockingBytes, inputs, txVerify: T, dag: sp.built.dagStats,
  };
  rows.push(r);
  const a = (i) => inputs[i].accepted;
  console.log(`${r.vector.padEnd(30)} proof ${r.proofBytes} lib ${r.libBytes} unl ${inputs[0].unlockingBytes}+${inputs[1].unlockingBytes} tx ${txBytes} | in0 ${inputs[0].opBchnAdjusted} (${inputs[0].pctR100}%) in1 ${inputs[1].opBchnAdjusted} (${inputs[1].pctR100}%) | r100 ${a(0).r100Std && a(0).r100Cons}/${a(1).r100Std && a(1).r100Cons} tx ${T.r100Std === true} r100t-tx ${T.r100tStd === true} | spec ${a(0).specStd && a(0).specCons}/${a(1).specStd && a(1).specCons} tx ${T.specStd === true} | today ${a(0).bchStd}/${a(1).bchStd}`);
}
const stat = (f) => { const xs = rows.map(f); return {min: Math.min(...xs), max: Math.max(...xs), mean: Math.round(xs.reduce((a, x) => a + x, 0) / xs.length)}; };
const by = (s) => rows.filter((r) => r.statement === s);
const summary = {};
for (const s of [...new Set(rows.map((r) => r.statement))]) {
  const R = by(s); const st = (f) => { const xs = R.map(f); return {min: Math.min(...xs), max: Math.max(...xs), mean: Math.round(xs.reduce((a, x) => a + x, 0) / xs.length)}; };
  summary[s] = {
    statements: R.length, QA: R[0].QA, proofBytes: st((r) => r.proofBytes), libBytes: st((r) => r.libBytes), unlocking0: st((r) => r.inputs[0].unlockingBytes), unlocking1: st((r) => r.inputs[1].unlockingBytes),
    txBytes: st((r) => r.txBytes), op0: st((r) => r.inputs[0].opBchnAdjusted), op1: st((r) => r.inputs[1].opBchnAdjusted), pct0: st((r) => r.inputs[0].pctR100), pct1: st((r) => r.inputs[1].pctR100),
    pctSpec0: st((r) => r.inputs[0].pctSpec), pctSpec1: st((r) => r.inputs[1].pctSpec),
    bothInputsR100: R.every((r) => r.inputs.every((x) => x.accepted.r100Std && x.accepted.r100Cons)),
    bothInputsSpec: R.every((r) => r.inputs.every((x) => x.accepted.specStd && x.accepted.specCons)),
    txVerifyR100: R.filter((r) => r.txVerify.r100Std === true).length, txVerifyR100t: R.filter((r) => r.txVerify.r100tStd === true && r.txVerify.r100tCons === true).length,
    txVerifySpec: R.filter((r) => r.txVerify.specStd === true).length, todayAccepted: R.filter((r) => r.inputs.some((x) => x.accepted.bchStd || x.accepted.bchCons)).length,
    todayErrors: [...new Set(R.flatMap((r) => r.inputs.map((x) => x.errors.bchStd)))], txErrors: [...new Set(R.map((r) => r.txVerify.r100Std).filter((x) => x !== true))],
  };
}
void stat;
mkdirSync(new URL('./results/', import.meta.url), {recursive: true});
writeFileSync(outFile, JSON.stringify({summary, rows}, null, 1) + '\n');
console.log(JSON.stringify(summary, null, 1));
const ok = Object.values(summary).every((s) => s.bothInputsR100 && s.txVerifyR100t === s.statements);
process.exit(ok ? 0 : 1);

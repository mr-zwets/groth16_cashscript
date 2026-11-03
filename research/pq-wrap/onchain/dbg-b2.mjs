// dbg-b2.mjs: layout b2 on vectors: both inputs under loose, r100 (std/cons); sizes and op-cost per input
import {readVector, vkxN, stmtFor, spendB2} from './layoutn.mjs';
import {evaluate} from './vm.mjs';
import {encodeTransactionBch} from '@bitauth/libauth';
const QA = +(process.env.QA ?? 12);
for (const f of process.argv.slice(2)) {
  const v = readVector(f); const vk = vkxN(v, {stmt: 'witness'});
  const pis = v.public_values.flat().map(BigInt);
  const sp = spendB2(vk, stmtFor(vk, pis, {mode: 'witness'}), Math.min(QA, vk.Q - 1), Buffer.from(v.proof_hex, 'hex'), pis, [{lockingBytecode: Uint8Array.of(0x6a), valueSatoshis: 0n}], {markers: true});
  const tx = encodeTransactionBch(sp.tx).length;
  const defB = sp.lib.length;
  const out = [0, 1].map((i) => { const r = evaluate('looseStd', null, null, sp.progs[i]); const s = evaluate('r100Std', null, null, sp.progs[i]); const u = i ? sp.unlocking1.length : sp.unlocking0.length; return {acc: r.accepted, r100: s.accepted, err: (r.error ?? s.error ?? '').slice(0, 90), opAdj: r.opCost + defB, pct: +(100 * (r.opCost + defB) / ((41 + u) * 800)).toFixed(1)}; });
  console.log(f.split('/').pop(), 'lib', sp.lib.length, 'locking', sp.locking0.length, sp.locking1.length, 'unl', sp.unlocking0.length, sp.unlocking1.length, 'tx', tx, JSON.stringify(out));
}

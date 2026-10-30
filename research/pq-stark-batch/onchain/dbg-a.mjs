#!/usr/bin/env node
// dbg-a.mjs: build layout a' for one vector and run every input on the loose VM (op-cost, unlocking, first error)
// usage: node dbg-a.mjs VECTOR.json [plan: 1tx | 2tx] [vm]
import {readVector} from './layoutn.mjs';
import {vkxA} from './modela.mjs';
import {makePlanA, spendA, evaluateTxA, verifyTxA} from './layouta.mjs';
const [path, which = '2tx', vm = 'looseStd'] = process.argv.slice(2);
const v = readVector(path); const vk = vkxA(v); const pis = v.public_values.flat().map(BigInt);
const outputs = v.s4_outputs.map((o) => ({lockingBytecode: Uint8Array.from(Buffer.from(o.lockingBytecode, 'hex')), valueSatoshis: BigInt(o.valueSatoshis)}));
const per = Array.from({length: Math.ceil(vk.Q / 3)}, (_, i) => Math.min(3, vk.Q - 3 * i));
const counts = which === '1tx' ? [per] : [per.slice(0, -1), per.slice(-1)];
const plan = makePlanA(vk, counts);
const t0 = Date.now();
const sp = spendA(vk, plan, Buffer.from(v.proof_hex, 'hex'), pis, outputs, {gen: {markers: process.env.MARK === '1'}});
console.log(`build ${Date.now() - t0} ms; code ${sp.pg.code.map((c) => c.length)} (total ${sp.pg.codeTotal}), R ${sp.pg.redeem.length} B, parts ${JSON.stringify(plan.parts)}, define bytes ${sp.pg.defineBytes}`);
console.log('largest fns', sp.pg.fnSizes.slice(0, 14).map((x) => x.join(':')).join(' '));
for (const [t, tx] of sp.txs.entries()) {
  const t1 = Date.now();
  const r = evaluateTxA(tx, vm);
  console.log(`tx${t}: ${tx.txBytes} B, ${tx.unl.length} inputs, ${Date.now() - t1} ms`);
  r.forEach((x, i) => console.log(`  in${i}: ${x.accepted ? 'ok ' : 'REJ'} unl ${x.unlocking} op ${x.opCost} (${(100 * (x.opCost + sp.pg.defineBytes) / x.budget).toFixed(1)}% of ${x.budget}) iters ${x.iters} ${x.error ?? ''} markers ${x.markers}`));
  if (vm.startsWith('bch')) console.log('  verify', verifyTxA(tx, vm));
}

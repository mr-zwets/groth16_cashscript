// dbg-n.mjs: quick check of the generalized generator in layout b (loose VM) on vectors
import {readVector, vkxN, stmtFor, spendBN} from './layoutn.mjs';
import {verifyModelN} from './modeln.mjs';
import {evaluate} from './vm.mjs';
for (const f of process.argv.slice(2)) {
  const v = readVector(f); const vk = vkxN(v, {stmt: 'witness'});
  const pis = v.public_values.flat().map(BigInt);
  const m = verifyModelN(vk, Buffer.from(v.proof_hex, 'hex'), pis);
  const t0 = Date.now();
  const sp = spendBN(vk, stmtFor(vk, pis, {mode: 'witness'}), Buffer.from(v.proof_hex, 'hex'), pis, [{lockingBytecode: Uint8Array.of(0x6a), valueSatoshis: 0n}], {markers: true});
  const tb = Date.now() - t0;
  const r = evaluate('looseStd', sp.locking, sp.unlocking, sp.prog);
  const marks = sp.built.marks.map((x) => x[0]);
  console.log(f.split('/').pop(), 'model', m.ok, m.reason ?? '', '| redeem', sp.redeem.length, 'unl', sp.unlocking.length, 'build', tb, 'ms | chain', r.accepted, r.error ?? '', 'op', r.opCost, 'markers', r.markers, 'last mark', marks[r.markers - 1] ?? '-', JSON.stringify(sp.built.dagStats.map((d) => [d.registers, d.maxDepth])));
  if (!r.accepted) console.log(r.stackTop);
}

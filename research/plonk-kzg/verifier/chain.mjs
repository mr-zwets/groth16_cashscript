// Today's standard rules: build the multi-input chain for a circuit, size each input's FILL from its measured
// op-cost, and spend the whole transaction on the libauth BCH 2026 VM (consensus and standard).
//   node chain.mjs <circuit> [proof index]
import {loadVectors, parseVK} from './plonk.mjs';
import {makePlan, buildMulti, multiWitness, planOpts} from './multi.mjs';
import {p2sh32, encodeUnlocking, spendTx} from './vm.mjs';
import {encodeTransaction} from '@bitauth/libauth';
export const txBytes = (tx) => encodeTransaction({version: 2, locktime: 0, inputs: tx.map((x, k) => ({outpointIndex: k, outpointTransactionHash: new Uint8Array(32), sequenceNumber: 0, unlockingBytecode: x.unlocking})), outputs: [{lockingBytecode: Uint8Array.of(0x6a), valueSatoshis: 0n}]}).length;

export function chainTx(vk, plan, built, pushes, fills) {
  const locking = p2sh32(built.redeem);
  return pushes.map((ps, i) => ({locking, unlocking: encodeUnlocking([...ps, Buffer.alloc(fills?.[i] ?? 0), built.redeem])}));
}
// FILL per input: measured on the unbudgeted VM and iterated on the filled transaction (a remote read pushes the whole
// unlocking of the input it reads, so every FILL raises its readers' op-cost); 64 B slack per filled input
export function sizeFills(vk, plan, built, pushes, {strict = true} = {}) {
  let fills = pushes.map(() => 0);
  for (let it = 0; it < 4; it++) {
    const tx = chainTx(vk, plan, built, pushes, fills); const free = spendTx('free', 'standard', tx); let changed = false;
    fills = free.map((x, i) => { if (strict && x.error && !/budget|density/.test(x.error)) throw new Error(`input ${i} (${plan.roles[i].kind}): ${x.error}`);
      const need = Math.ceil((x.opCost + built.defBytes) / 800) - 41 - tx[i].unlocking.length + fills[i]; // BCHN-adjusted, beyond the unfilled size
      const f = need > 0 ? need + 64 : 0;
      if (f > fills[i]) { changed = true; return f; } return fills[i]; });
    if (!changed) break;
  }
  return fills;
}
if (import.meta.url === `file://${process.argv[1]}`) {
  const [c = 'mul2', pi = '0'] = process.argv.slice(2);
  const d = loadVectors(c); const vk = parseVK(d.vk.hex);
  const plan = makePlan(vk, planOpts(vk, c)); const built = buildMulti(vk, plan);
  console.log('code blob', built.code.length, 'redeem', built.redeem.length, 'roles', plan.roles.map((r) => r.kind).join(','), 'bodies', built.bodies.join(','));
  const w = multiWitness(vk, plan, built, d.valid[Number(pi)].proof, d.valid[Number(pi)].publicInputs);
  const fills = sizeFills(vk, plan, built, w.pushes);
  const tx = chainTx(vk, plan, built, w.pushes, fills);
  for (const mode of ['consensus', 'standard']) {
    const res = spendTx('bch2026', mode, tx);
    console.log(mode, res.every((x) => x.accepted) ? 'ACCEPTED' : 'REJECTED');
    res.forEach((x, i) => console.log(`  in${i} ${plan.roles[i].kind.padEnd(2)} unlocking ${x.unlockingLen} fill ${fills[i]} op ${x.opCost} / ${x.budget} ${x.accepted ? '' : x.error}`));
  }
  console.log('total unlocking', tx.reduce((s, x) => s + x.unlocking.length, 0), 'tx bytes', txBytes(tx));
}

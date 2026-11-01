// Track 9 S0: export the flush worker input (flush-fit.mjs) as node-check workloads (bench research/node-check nc.ts,
// json: format) to confirm the op-cost accounting on BCHN v29.1.0 regtest:
//   fit13   n = 13 compressions, 10,000 B unlocking (93.6% of the budget, BCHN-adjusted): expect accept;
//   over14  n = 14: over the budget in libauth already: expect reject;
//   probe   n = 13 with the unlocking shortened so that libauth op-cost <= budget < libauth op-cost + DEFINE body
//           bytes: libauth (unpatched) accepts, BCHN must reject (it charges the OP_DEFINE body).
// Usage: node s0-bchn-export.mjs OUT.json
import fs from 'fs';
import {build, measure, CODE} from './flush-fit.mjs';
const hex = (b) => Buffer.from(b).toString('hex');
const out = process.argv[2];
const wl = (id, kind, expect, expectLibauth, n, unlock, description) => {
  const b = build(n, unlock), m = measure(n, {unlock});
  return {id, group: 't9-s0', kind, expect, expectLibauth, defBytes: CODE.length, description: `${description}; libauth op ${m.opCost}, +DEFINE ${m.bchnAdjusted}, budget ${m.budget}`,
    libauth: m,
    txs: [{label: id, version: 2, locktime: 0,
      inputs: [{source: {lockingHex: hex(b.locking), valueSatoshis: '100000'}, unlockingHex: hex(b.unlocking), sequenceNumber: 0}],
      outputs: [{lockingHex: '6a', valueSatoshis: '0'}]}]};
};
// probe: the largest unlocking length whose budget is still below libauth + DEFINE, with libauth itself under it
let probe;
for (let u = 9_200; u <= 10_000; u++) {
  const m = measure(13, {unlock: u});
  if (m.txVerify === true && m.opCost <= m.budget && m.bchnAdjusted > m.budget) { probe = u; break; }
}
if (!probe) throw new Error('no probe length');
const W = [
  wl('fit13', 'valid', 'accept', 'accept', 13, 10_000, '13 compressions in one 10,000 B input'),
  wl('over14', 'tampered', 'reject', 'reject', 14, 10_000, '14 compressions: over the density budget'),
  wl('probe13', 'define-probe', 'reject', 'accept', 13, probe, `13 compressions, unlocking ${probe} B: libauth op <= budget < libauth op + DEFINE bytes`),
];
fs.writeFileSync(out, JSON.stringify({workloads: W}, null, 1));
console.log(W.map((w) => `${w.id}: ${w.description}`).join('\n'));

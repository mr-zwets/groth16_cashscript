// Run the transaction for several witnesses on the real bch-2026 VM (standard + consensus), report per-input margins.
//   WIT=committed,dense,forced:44 node check.mjs
import {buildAll} from './script.mjs';
import {txPushes} from './protocol.mjs';
import {witnessFor} from './measure.mjs';
import {p2sh32, txOf, unlockingsFor, evalTx, verifyTx, txSize} from './vm.mjs';
const b = buildAll(); console.log('blob', b.blob.length, 'R', b.R.length);
let worst = 1;
for (const spec of (process.env.WIT ?? 'committed,dense,forced:44').split(',')) {
  const w = await witnessFor(spec); const un = unlockingsFor(txPushes(w, b.blob), b.R); const ctx = txOf(un, un.map(() => p2sh32(b.R)));
  for (const mode of ['standard', 'consensus']) {
    const rs = evalTx(ctx, mode); const v = verifyTx(ctx, mode);
    const m = rs.map((x) => 1 - x.op / x.budget); worst = Math.min(worst, ...m);
    console.log(spec.padEnd(10), mode.padEnd(9), 'n_q', w.nq, v === true ? 'VALID' : 'INVALID ' + v, 'U', rs.map((x) => x.bytes).join(','), 'sum', un.reduce((s, u) => s + u.length, 0), 'tx', txSize(ctx), 'margins', m.map((x) => (100 * x).toFixed(2) + '%').join(' '));
  }
}
console.log('min margin', (100 * worst).toFixed(2) + '%');

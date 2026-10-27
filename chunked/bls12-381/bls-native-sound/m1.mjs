// M1 smoke: build the program, prove fixture `committed`, run the 4-input transaction in both modes.
import {buildAll} from './script.mjs';
import {FIXTURES} from './math.mjs';
import {prove, txPushes} from './protocol.mjs';
import {p2sh32, txOf, unlockingsFor, evalTx, verifyTx, txSize} from './vm.mjs';
const t0 = Date.now();
const b = buildAll();
console.log('blob', b.blob.length, 'R', b.R.length, 'roles', b.info.roles.join(','), 'funcs', JSON.stringify(b.info.funcs), ((Date.now() - t0) / 1000).toFixed(0) + 's');
console.log('sections', JSON.stringify(b.info.sections));
const w = prove(FIXTURES[process.env.FIX ?? 'committed']);
const un = unlockingsFor(txPushes(w, b.blob), b.R); const lk = un.map(() => p2sh32(b.R));
const ctx = txOf(un, lk);
for (const mode of ['standard', 'consensus']) {
  const rs = evalTx(ctx, mode);
  rs.forEach((x, i) => console.log(mode, 'in' + i, x.ok ? 'OK ' : 'ERR', x.error ?? '', 'U', x.bytes, 'op', x.op, 'budget', x.budget, 'margin', ((1 - x.op / x.budget) * 100).toFixed(2) + '%'));
  console.log(mode, 'verify:', verifyTx(ctx, mode));
}
console.log('tx', txSize(ctx), 'sum U', un.reduce((s, u) => s + u.length, 0));
if (process.env.UNL) { const {evalTxUnlimited} = await import('./vm.mjs'); for (const mode of ['standard', 'consensus']) evalTxUnlimited(ctx, mode).forEach((x, i) => console.log('UNLIMITED', mode, 'in' + i, x.ok ? 'OK' : x.error, 'op', x.op, 'needs U >=', Math.ceil(x.op / 800 / 0.94 - 41))); }

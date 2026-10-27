const o = require('./opcat.json');
const cat = (spec, i) => {
  const x = o[spec].inputs[i], b = x.by, c = x.calls; const g = (k) => b[k] ?? 0;
  const ev = g('EV') / c.EV, rd6 = g('RD6') / (c.RD6 || 1), rd2 = g('RD2') / (c.RD2 || 1);
  const states = [5, 10, 10, 7][i], slopes = [10, 21, 21, 16][i];
  const out = {};
  out.events = g('AFFDBL') + g('AFFADD') + g('DSTEP') + g('BND') + g('LOOP') + states * rd6 + slopes * rd2;
  out.setup = g('SETUP') + g('TBL') + g('TM') + 9 * ev;
  if (i === 0) {
    const r0 = (k) => g('ROLE0:' + k);
    out.headCore = r0('after-statement') + r0('after-binding') + r0('after-quotient+final') + g('G1C') + g('TA') + r0('after-setup') + ev /*Rconst*/ + (g('RD6') - states * rd6) + (g('RD2') - slopes * rd2) /* statement, WQ? decode */;
    out.transcript = r0('after-transcript');
    out.pinsK = r0('start') + r0('after-pin+K');
    out.handoff = g('FINW') + g('C48');
  } else {
    const rk = (k) => g(`ROLE${i}:` + k);
    if (i === 3) out.terminal = rk('after-work');
    out.pinsK = rk('start') + rk('after-pin+K');
    out.handoff = g('READ0') + g('WSTART') + ev + g('FINW') + g('C48') + g('WORK') + (g('RD6') - states * rd6) + (g('RD2') - slopes * rd2) + (b.RD ?? 0) + rk('after-params');
  }
  out.loader = g('R') + g('BLOB');
  const known = Object.values(out).reduce((s, v) => s + v, 0); out.other = x.op - known;
  return {op: x.op, budget: x.budget, U: x.U, ...Object.fromEntries(Object.entries(out).map(([k, v]) => [k, Math.round(v / 1000)]))};
};
for (const [spec, ins] of [['forced:44d3', [0]], ['all15', [1, 2, 3]], ['committed', [0, 1, 2, 3]]]) for (const i of ins) console.log(spec, i, JSON.stringify(cat(spec, i)));

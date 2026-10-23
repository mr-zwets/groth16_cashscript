// Best measured configuration (K = 16 affine-prefix events, F1 from event 64): all 5 fixtures,
// standard + consensus, and the full-verifier totals with MSM + verdict.
import {build} from './hotloop.mjs'; import {makeWitness} from './witness.mjs'; import {run, asm, vmCons, L, num} from './sscomp.mjs';
import {score} from './sweep.mjs';
const K = Number(process.env.K ?? 16), f1From = Number(process.env.F1 ?? 64);
const out = [];
for (let fi = 0; fi < 5; fi++) {
  const w = makeWitness(fi, K); const B = build(w, {f1From});
  const a = run(B.pushes, B.lock), c = run(B.pushes, B.lock, {vm: vmCons});
  const base = run(B.pushes, asm('1')).cost, baseC = run(B.pushes, asm('1'), {vm: vmCons}).cost;
  const witness = B.pushes.reduce((s, x) => s + (x instanceof Uint8Array ? L.encodeDataPush(x).length : L.encodeDataPush(num(x)).length), 0);
  const row = {fi, accepted: !a.err && !c.err, op: a.cost - base, opCons: c.cost - baseC, lock: B.lock.length, witness, nQ: B.nQ, pushes: B.pushes.length, calls: B.counts};
  Object.assign(row, score(row)); out.push(row); console.log(JSON.stringify(row));
}

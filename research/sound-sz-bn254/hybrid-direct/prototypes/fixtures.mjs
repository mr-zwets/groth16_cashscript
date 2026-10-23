// Runs the hot-section prototype on all 5 fixtures (both B modes), standard + consensus, and a few
// rejection sanity checks (one-limb perturbations of the witness must make the script fail).
import {build} from './hotloop.mjs';
import {makeWitness} from './witness.mjs';
import {run, asm, vmCons, L, num, P} from './sscomp.mjs';
const res = [];
for (const mode of ['proj', 'aff']) for (let fi = 0; fi < 5; fi++) {
  const w = makeWitness(fi, mode); const B = build(w);
  const base = run(B.pushes, asm('1')).cost, baseC = run(B.pushes, asm('1'), {vm: vmCons}).cost;
  const a = run(B.pushes, B.lock), c = run(B.pushes, B.lock, {vm: vmCons});
  const wb = B.pushes.reduce((s, x) => s + (x instanceof Uint8Array ? L.encodeDataPush(x).length : L.encodeDataPush(num(x)).length), 0);
  const row = {mode, fi, ok: !a.err && !c.err, opStd: a.cost - base, opCons: c.cost - baseC, lock: B.lock.length, witness: wb};
  if (fi === 0) {
    // rejection sanity: perturb one limb of: a state, a Q coefficient, u0, By0
    const tamper = (k, f) => { const p = B.pushes.slice(); p[k] = f(p[k]); return !!run(p, B.lock).err; };
    const idx = (len) => B.pushes.findIndex((x) => x instanceof Uint8Array && x.length === len);
    const flipByte = (x) => { const y = Buffer.from(x); y[5] ^= 1; return y; };
    const ui = B.pushes.length - 18; // u0 position (see setupIn order)
    row.rejects = {state: tamper(idx(6912), flipByte), q: tamper(idx(32 * B.nQ), flipByte), u0: tamper(ui, (x) => (x + 1n) % P), By0: tamper(B.pushes.length - 3, (x) => (x + 1n) % P)};
  }
  res.push(row); console.log(JSON.stringify(row));
}

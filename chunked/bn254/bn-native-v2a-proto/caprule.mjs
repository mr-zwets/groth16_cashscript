// v2a prototype: cap-rule check (op per input at the 10,000-byte cap <= 0.94 x 8,032,800) on the forced cases + fixtures.
import assert from 'node:assert/strict';
import {FIXTURES} from '../sound-si-gls/math.mjs';
import {mint, rng, denseStatement, thinDenseStatement, zeroStatement} from '../sound-si-gls/mint.mjs';
import {buildProgram} from './script.mjs';
import {proveCore, CUTS} from './protocol.mjs';
import {unlockingsFor, lockingOf, sizeFills, UNLOCK_CAP} from './transaction.mjs';
import {spendAll, budgetOf} from './vm.mjs';
const prog = buildProgram(); const lock = lockingOf(prog); const rnd = rng('v2a-cap');
const CAP = Math.floor(0.94 * budgetOf(new Uint8Array(10000)));
const cases = FIXTURES.fixtures.map((f, i) => [`fixture ${i}`, f, {}]);
for (const [l, d] of [['every nibble 15', denseStatement()], ['every nibble 0', zeroStatement()], ['every nibble 1', thinDenseStatement()]]) cases.push([l, mint(...d.n, rnd), {es: d.es}]);
for (let i = 0; i < Number(process.env.NR ?? 4); i++) cases.push([`random ${i}`, mint(rnd(), rnd(), rnd), {}]);
const worst = [0, 0, 0];
for (const [label, fx, opts] of cases) {
  const core = proveCore(fx, opts);
  const fills = unlockingsFor(core, prog, [0, 0, 0]).unlockings.map((u) => UNLOCK_CAP - u.length + 1 - 3);
  const {unlockings} = unlockingsFor(core, prog, fills);
  const out = {}; for (const m of ['consensus', 'standard']) { const r = spendAll(unlockings.map(() => lock), unlockings, m); r.forEach((x, i) => assert.ok(x.accepted, `${label} ${m} ${i} ${x.error}`)); out[m] = r; }
  const fit = sizeFills(core, prog); const sz = unlockingsFor(core, prog, fit.fills).unlockings;
  const ops = out.standard.map((x) => x.opCost); ops.forEach((o, i) => (worst[i] = Math.max(worst[i], o)));
  console.log(`${label.padEnd(18)} nq ${core.nq} cap-run op ${ops.join(' / ')} ${ops.every((o) => o <= CAP) ? 'ok' : 'CAP RULE FAIL'}; sized unlocking ${sz.map((u) => u.length).join(' / ')} = ${sz.reduce((a, u) => a + u.length, 0)}`);
}
console.log(`CUTS ${CUTS.join(',')}: worst cap-run op ${worst.join(' / ')} vs rule ${CAP}: headroom ${worst.map((o) => (100 * (1 - o / budgetOf(new Uint8Array(10000)))).toFixed(2) + '%').join(' / ')}`);

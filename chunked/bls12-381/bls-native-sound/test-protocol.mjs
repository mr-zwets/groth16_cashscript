// Protocol self-test: honest witnesses for every fixture verify at value level (split claims included), and
// simple tampering is rejected by the reference verifier.
import assert from 'node:assert/strict';
import {FIXTURES, FIXTURE_NAMES} from './math.mjs';
import {prove, verifyValues, ROLES, NQ_MAX, N_MIN, K_BLOCKS} from './protocol.mjs';
console.log('NQ_MAX', NQ_MAX, 'N_MIN', N_MIN, 'roles', ROLES.map((r) => `[${r.e0}..${r.e1}] states ${r.states.length} slopes ${r.nslopes} G ${r.regionSize} K ${r.kSize}`).join(' | '));
for (const n of FIXTURE_NAMES) {
  const w = prove(FIXTURES[n]); assert.equal(w.claims.final, 0n, 'split final identity ' + n);
  const v = verifyValues(w); assert.ok(v.ok, n + ': ' + v.why);
  v.claims.R.forEach((R, i) => assert.equal(R, w.claims.R[i]));
  console.log(n.padEnd(14), 'n_q', w.nq, '(true', w.nqTrue + ')', 'R', w.claims.R.map((x) => x.toString(16).slice(0, 6)).join(','));
}
{ const w = prove(FIXTURES.committed); const g = Buffer.from(w.regions[2]); g[100] ^= 1; assert.ok(!verifyValues({...w, regions: [w.regions[0], w.regions[1], g, w.regions[3]]}).ok); }
console.log('ok; K blocks', K_BLOCKS.map((b) => b.length).join(','));

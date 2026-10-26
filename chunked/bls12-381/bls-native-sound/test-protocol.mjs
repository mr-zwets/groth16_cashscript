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
// The accepted relation, for ARBITRARY (not necessarily valid) A, B, C and n: the product f' that the identities
// chain (both Miller loops, Rconst', the GLS factors selected by the canonical digits) satisfies
//   FE(f') = e(A, B) * (e(alpha, beta) * e(vk_x, gamma) * e(C, delta))^-1,   vk_x = IC0 + n0 IC1 + n1 IC2,
// so FE(f') = 1 is exactly the Groth16 equation (not only "valid proofs give FE = 1").
{
  const {bls12_381} = await import('@noble/curves/bls12-381.js');
  const {createHash} = await import('node:crypto');
  const {r, F12, G1, G2, VK, fromPoly, glsDigits} = await import('./math.mjs');
  const {factorSchedule} = await import('./protocol.mjs');
  const h = (s) => 1n + BigInt('0x' + createHash('sha256').update('test-protocol relation:' + s).digest('hex')) % (r - 1n);
  const pr = (a, b) => bls12_381.pairing(a, b);
  for (let t = 0; t < 3; t++) {
    const A = G1.BASE.multiply(h(`A${t}`)), B = G2.BASE.multiply(h(`B${t}`)), C = G1.BASE.multiply(h(`C${t}`)); const ns = [h(`n0${t}`), h(`n1${t}`)];
    const N = ns.map(glsDigits).map((a) => Array.from({length: 64}, (_, j) => a.reduce((s, ai, i) => s | (Number((ai >> BigInt(63 - j)) & 1n) << i), 0)));
    const [Aa, Ba, Ca] = [A, B, C].map((P) => P.toAffine());
    const sch = factorSchedule({xA: Aa.x, yA: Aa.y, xB: Ba.x, yB: Ba.y, xC: Ca.x, yC: Ca.y, N}); assert.ok(sch.ok && sch.endpoint);
    let f = F12.ONE; for (const x of sch.start) f = F12.mul(f, fromPoly(x));
    for (const ev of sch.events) { f = F12.sqr(f); for (const x of ev.fs) f = F12.mul(f, fromPoly(x)); }
    const vkx = VK.ic[0].add(VK.ic[1].multiply(ns[0])).add(VK.ic[2].multiply(ns[1]));
    const want = F12.mul(pr(A, B), F12.inv(F12.mul(F12.mul(pr(VK.alpha, VK.beta), pr(vkx, VK.gamma)), pr(C, VK.delta))));
    assert.ok(!F12.eql(want, F12.ONE), 'a random (A, B, C, n) is not a valid proof');
    assert.ok(F12.eql(F12.finalExponentiate(f), want), "FE(f') = e(A,B) / (e(alpha,beta) e(vk_x,gamma) e(C,delta))");
  }
  console.log("accepted relation: FE(f') = e(A,B)/(e(alpha,beta) e(vk_x,gamma) e(C,delta)) on 3 random non-valid (A, B, C, n)");
}
